package suitedir

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
)

const erasedTestOrg = "a20ec51f-9bb0-4b48-b557-4324372a68dc"

func erasedRow(subject string, revision int64) string {
	return fmt.Sprintf(`{"sub":%q,"org_id":"%s","revision":%d}`, subject, erasedTestOrg, revision)
}

func TestErasedPagesAndSinceRoundTrip(t *testing.T) {
	// Use a gap and revisions above 2^53: both JSON integers and string cursors
	// must preserve their exact value.
	const high int64 = 9007199254740993
	c, queries := suitePages(t, "erased", map[string]string{
		"limit=500&since=0":                `{"subjects":[` + erasedRow("a", high) + `],"next":"9007199254740993"}`,
		"limit=500&since=9007199254740993": `{"subjects":[` + erasedRow("b", high+9) + `]}`,
		"limit=500&since=9007199254741002": `{"subjects":[]}`,
	})
	got, next, err := c.Erased(t.Context(), 0)
	want := []ErasedSubject{{"a", erasedTestOrg, high}, {"b", erasedTestOrg, high + 9}}
	if err != nil || !slices.Equal(got, want) || next != high+9 {
		t.Fatalf("Erased = %v, %d, %v", got, next, err)
	}
	empty, same, err := c.Erased(t.Context(), next)
	if err != nil || empty == nil || len(empty) != 0 || same != next || len(*queries) != 3 {
		t.Fatalf("resume = %v, %d, %v; queries %v", empty, same, err, *queries)
	}
}

func TestErasedFailsWholeReadOnInvalidPage(t *testing.T) {
	const since = 4
	row := erasedRow("b", 7)
	tooMany := make([]string, erasedPageSize+1)
	for i := range tooMany {
		tooMany[i] = erasedRow(fmt.Sprintf("sub-%d", i), int64(i+6))
	}
	page := func(row string) string { return `{"subjects":[` + row + `]}` }
	for name, bad := range map[string]string{
		"missing list":   `{}`,
		"null list":      `{"subjects":null}`,
		"wrong list":     `{"subjects":{}}`,
		"extra field":    `{"subjects":[],"more":true}`,
		"wrong case":     `{"SUBJECTS":[]}`,
		"duplicate list": `{"subjects":[],"subjects":[]}`, "trailing JSON": page(row) + `{}`,
		"null entry":              page("null"),
		"missing org":             page(`{"sub":"b","revision":7}`),
		"malformed org":           page(strings.ReplaceAll(row, erasedTestOrg, strings.ToUpper(erasedTestOrg))),
		"empty subject":           page(erasedRow("", 7)),
		"blank subject":           page(erasedRow(" ", 7)),
		"long subject":            page(erasedRow(strings.Repeat("a", 256), 7)),
		"extra entry field":       page(strings.ReplaceAll(row, `"sub"`, `"new":1,"sub"`)),
		"duplicate subject field": page(strings.ReplaceAll(row, `"sub"`, `"sub":"a","sub"`)),
		"missing revision":        page(`{"sub":"b","org_id":"` + erasedTestOrg + `"}`),
		"wrong revision type":     page(strings.ReplaceAll(row, `:7`, `:"7"`)),
		"repeated revision":       page(erasedRow("b", 5)),
		"decreasing revision":     page(row + "," + erasedRow("c", 6)),
		"empty continuation":      `{"subjects":[],"next":"5"}`,
		"cursor skips":            `{"subjects":[` + row + `],"next":"8"}`,
		"numeric cursor":          `{"subjects":[` + row + `],"next":7}`,
		"null cursor":             `{"subjects":[],"next":null}`,
		"empty cursor":            `{"subjects":[` + row + `],"next":""}`,
		"row limit":               page(strings.Join(tooMany, ",")),
		"body limit":              `{"subjects":[]}` + strings.Repeat(" ", maxBody),
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := suitePages(t, "erased", map[string]string{
				"limit=500&since=4": `{"subjects":[` + erasedRow("a", 5) + `],"next":"5"}`,
				"limit=500&since=5": bad,
			})
			if got, next, err := c.Erased(t.Context(), since); err == nil || got != nil || next != since {
				t.Fatalf("Erased = %v, %d, %v", got, next, err)
			}
		})
	}
}

func TestErasedRequestErrors(t *testing.T) {
	c, req := serve(t, http.StatusUnauthorized, `{"error":"invalid_client"}`)
	if got, next, err := c.Erased(t.Context(), -1); err == nil || got != nil || next != -1 || req() != nil {
		t.Fatalf("negative since = %v, %d, %v", got, next, err)
	}
	if got, next, err := c.Erased(t.Context(), 9); !errors.Is(err, ErrUnauthorized) || got != nil || next != 9 {
		t.Fatalf("refused credentials = %v, %d, %v", got, next, err)
	}
	r := req()
	if id, secret, ok := r.BasicAuth(); !ok || id != c.ClientID || secret != c.ClientSecret || r.Method != http.MethodGet {
		t.Fatal("expected a GET with the calling app's credentials")
	}
	c, _ = serve(t, http.StatusNotFound, `{"error":"not_found"}`)
	if got, next, err := c.Erased(t.Context(), 9); err == nil || got != nil || next != 9 {
		t.Fatalf("single tenant = %v, %d, %v", got, next, err)
	}
}

func TestErasedResumesAtPageBound(t *testing.T) {
	pages := map[string]string{}
	for i := 0; i <= maxErasedPages; i++ {
		row := erasedRow(fmt.Sprintf("sub-%d", i), int64(i+1))
		pages[fmt.Sprintf("limit=500&since=%d", i)] = fmt.Sprintf(`{"subjects":[%s],"next":"%d"}`, row, i+1)
	}
	pages[fmt.Sprintf("limit=500&since=%d", maxErasedPages+1)] = `{"subjects":[]}`
	c, queries := suitePages(t, "erased", pages)
	got, next, err := c.Erased(t.Context(), 0)
	if err != nil || len(got) != maxErasedPages || next != maxErasedPages || len(*queries) != maxErasedPages {
		t.Fatalf("read %d pages, %d subjects, next %d, err %v", len(*queries), len(got), next, err)
	}
	got, next, err = c.Erased(t.Context(), next)
	if err != nil || len(got) != 1 || next != maxErasedPages+1 {
		t.Fatalf("resume = %v, %d, %v", got, next, err)
	}
}
