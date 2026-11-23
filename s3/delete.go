package s3

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"
	"strings"
)

// DeleteAllVersions removes precisely key, including every delete marker. A nonexistent key
// is success; prefix neighbours are untouched. The caller first fences concurrent writers.
// Re-running after any failure safely resumes the erasure.
func (c *Client) DeleteAllVersions(ctx context.Context, key string) error {
	if key == "" {
		return ErrInvalid
	}
	return c.erase(ctx, key, true)
}

// DeletePrefix removes every version and delete marker under a nonempty, slash-terminated
// namespace prefix, never a guessed/cleaned path. Fence writers first. Provider replica copies
// outside this bucket require the product's separate replication/retention policy.
func (c *Client) DeletePrefix(ctx context.Context, prefix string) error {
	if prefix == "" || !strings.HasSuffix(prefix, "/") {
		return ErrInvalid
	}
	return c.erase(ctx, prefix, false)
}

func (c *Client) erase(ctx context.Context, prefix string, exact bool) error {
	seen := map[[32]byte]int{}
	for {
		batch, err := c.eraseBatch(ctx, prefix, exact)
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}
		// A provider reporting successful deletes without removing anything must not spin.
		sort.Slice(batch, func(i, j int) bool {
			if batch[i].Key != batch[j].Key {
				return batch[i].Key < batch[j].Key
			}
			return batch[i].VersionID < batch[j].VersionID
		})
		h := sha256.New()
		for _, obj := range batch {
			for _, s := range []string{obj.Key, obj.VersionID} {
				_ = binary.Write(h, binary.BigEndian, uint64(len(s)))
				_, _ = h.Write([]byte(s))
			}
		}
		var digest [32]byte
		copy(digest[:], h.Sum(nil))
		seen[digest]++
		if seen[digest] == 3 {
			return failure("ERASE", 503)
		}
		for _, obj := range batch {
			if _, err := c.Delete(ctx, obj.Key, obj.VersionID); err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
		}
		// ponytail: restart after each bounded batch. Removing a version also used as a page
		// marker can invalidate that cursor; restarting keeps erasure resumable without a ledger.
	}
}

func (c *Client) eraseBatch(ctx context.Context, prefix string, exact bool) ([]Object, error) {
	var cursor VersionCursor
	seen := map[VersionCursor]bool{}
	for {
		page, err := c.ListObjectVersions(ctx, prefix, cursor)
		if err != nil {
			return nil, err
		}
		batch := make([]Object, 0, len(page.Objects))
		for _, obj := range page.Objects {
			if !exact || obj.Key == prefix {
				batch = append(batch, obj)
			}
		}
		if len(batch) > 0 || page.Next == (VersionCursor{}) {
			return batch, nil
		}
		if seen[page.Next] {
			return nil, failure("LIST", 200)
		}
		seen[page.Next] = true
		cursor = page.Next
	}
}
