package s3

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// The fixture deliberately invalidates a cursor when its referenced version is deleted.
// Erasure must restart listing, not delete a page and then follow the lost marker.
type versionStore struct {
	mu             sync.Mutex
	rows           []Object
	page           int
	deletes        []VersionCursor
	fail           string
	transient      string
	transientCalls int
	ignoreDeletes  bool
}

func escapedXML(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
func (s *versionStore) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := r.URL.Query()
	if r.Method == "DELETE" {
		key := strings.TrimPrefix(r.URL.Path, "/bucket/")
		id := q.Get("versionId")
		s.deletes = append(s.deletes, VersionCursor{key, id})
		if id == "" {
			http.Error(w, "a normal delete would create a marker", 400)
			return
		}
		if id == s.fail {
			w.WriteHeader(403)
			return
		}
		if id == s.transient {
			s.transientCalls++
			if s.transientCalls == 1 {
				w.WriteHeader(503)
				return
			}
		}
		for i, obj := range s.rows {
			if obj.Key == key && obj.VersionID == id {
				if !s.ignoreDeletes {
					s.rows = append(s.rows[:i], s.rows[i+1:]...)
				}
				break
			}
		}
		w.Header().Set("X-Amz-Version-Id", id)
		w.WriteHeader(204)
		return
	}
	if r.Method != "GET" || !q.Has("versions") {
		w.WriteHeader(400)
		return
	}
	var rows []Object
	for _, obj := range s.rows {
		if strings.HasPrefix(obj.Key, q.Get("prefix")) {
			rows = append(rows, obj)
		}
	}
	start := 0
	if key := q.Get("key-marker"); key != "" {
		start = -1
		for i, obj := range rows {
			if obj.Key == key && obj.VersionID == q.Get("version-id-marker") {
				start = i + 1
				break
			}
		}
		if start < 0 {
			http.Error(w, "deleted pagination marker", 400)
			return
		}
	}
	end := min(start+s.page, len(rows))
	fmt.Fprintf(w, `<ListVersionsResult><EncodingType>url</EncodingType><IsTruncated>%t</IsTruncated>`, end < len(rows))
	for _, obj := range rows[start:end] {
		tag := "Version"
		if obj.DeleteMarker {
			tag = "DeleteMarker"
		}
		fmt.Fprintf(w, "<%s><Key>%s</Key><VersionId>%s</VersionId><Size>%d</Size></%s>", tag, escapedXML(escape(obj.Key, false)), escapedXML(obj.VersionID), obj.Size, tag)
	}
	if end < len(rows) {
		last := rows[end-1]
		fmt.Fprintf(w, "<NextKeyMarker>%s</NextKeyMarker><NextVersionIdMarker>%s</NextVersionIdMarker>", escapedXML(escape(last.Key, false)), escapedXML(last.VersionID))
	}
	_, _ = fmt.Fprint(w, "</ListVersionsResult>")
}

func TestExactAndPrefixErasureCoversVersionsMarkersAndRetries(t *testing.T) {
	store := &versionStore{page: 2, transient: "old+/%=v", rows: []Object{
		// Neighbours before the exact key force eraseBatch to follow both pagination markers.
		{Key: "orgs/a/key-neighbour", VersionID: "n1", Size: 3},
		{Key: "orgs/a/key-neighbour", VersionID: "n2", DeleteMarker: true},
		{Key: "orgs/a/key", VersionID: "marker+/%", DeleteMarker: true},
		{Key: "orgs/a/key", VersionID: "old+/%=v", Size: 5},
		{Key: "orgs/a/key", VersionID: "null", Size: 4},
		{Key: "orgs/a/key", VersionID: "other marker", DeleteMarker: true},
		{Key: "orgs/a/other", VersionID: "v", Size: 2},
		{Key: "orgs/ab/other", VersionID: "v", Size: 7},
	}}
	c, _ := tlsClient(t, store.serve)
	if err := c.DeleteAllVersions(context.Background(), "orgs/a/key"); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	for _, obj := range store.rows {
		if obj.Key == "orgs/a/key" {
			t.Error("exact version survived", obj)
		}
	}
	if len(store.rows) != 4 || store.transientCalls != 2 {
		t.Errorf("neighbours/retry: %v, %d", store.rows, store.transientCalls)
	}
	for _, d := range store.deletes {
		if d.Key != "orgs/a/key" || d.VersionID == "" {
			t.Errorf("overbroad exact erase: %+v", d)
		}
	}
	store.mu.Unlock()
	if err := c.DeleteAllVersions(context.Background(), "orgs/a/key"); err != nil {
		t.Fatal("repeat", err)
	}
	if err := c.DeletePrefix(context.Background(), "orgs/a/"); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.rows) != 1 || store.rows[0].Key != "orgs/ab/other" {
		t.Fatalf("prefix crossed boundary: %v", store.rows)
	}
}

func TestErasureResumesAfterFailureAndRejectsNoProgress(t *testing.T) {
	store := &versionStore{page: 2, fail: "v2", rows: []Object{{Key: "orgs/a/key", VersionID: "v1", Size: 1}, {Key: "orgs/a/key", VersionID: "v2", Size: 2}, {Key: "orgs/a/key", VersionID: "m", DeleteMarker: true}}}
	c, _ := tlsClient(t, store.serve)
	if err := c.DeletePrefix(context.Background(), "orgs/a/"); !errors.Is(err, ErrFailure) {
		t.Fatal("failure swallowed", err)
	}
	store.mu.Lock()
	store.fail = ""
	store.mu.Unlock()
	if err := c.DeletePrefix(context.Background(), "orgs/a/"); err != nil {
		t.Fatal("resume", err)
	}
	store.mu.Lock()
	if len(store.rows) != 0 {
		t.Error(store.rows)
	}
	store.rows = []Object{{Key: "orgs/a/key", VersionID: "v", Size: 1}}
	store.ignoreDeletes = true
	store.mu.Unlock()
	if err := c.DeletePrefix(context.Background(), "orgs/a/"); !errors.Is(err, ErrFailure) {
		t.Fatal("success without progress", err)
	}
	for _, prefix := range []string{"", "orgs/a"} {
		if err := c.DeletePrefix(context.Background(), prefix); !errors.Is(err, ErrInvalid) {
			t.Fatal("unsafe prefix", err)
		}
	}
	if err := c.DeleteAllVersions(context.Background(), ""); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.DeletePrefix(ctx, "orgs/a/"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestForeignListingNeverReachesDelete(t *testing.T) {
	deleted := false
	c, _ := tlsClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			deleted = true
			t.Error("foreign object reached delete")
			return
		}
		_, _ = fmt.Fprint(w, `<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>orgs/a/good</Key><VersionId>v</VersionId><Size>1</Size></Version><Version><Key>orgs/b/bad</Key><VersionId>v</VersionId><Size>1</Size></Version></ListVersionsResult>`)
	})
	if err := c.DeletePrefix(context.Background(), "orgs/a/"); !errors.Is(err, ErrFailure) || deleted {
		t.Fatal(err)
	}
}
