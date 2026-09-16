// Command kyauditverify checks any audit chain in the suite.
//
// The products store their trails differently — two write JSON lines, one writes
// a database — and they authenticate different fields. What they share is the
// chain, so this tool reads the one thing they can all emit: the records as
// auditchain sees them, plus the anchor kept outside the log.
//
//	kyauditverify -key @/etc/kypassword/audit.key -anchor 42:9f3c... trail.jsonl
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/Busnes-app/ky-primitives/auditchain"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "kyauditverify:", err)
		os.Exit(1)
	}
}

func run() error {
	key := flag.String("key", "", "@path to a file holding the chain key as hex")
	anchor := flag.String("anchor", "", "recorded anchor as count:hash")
	flag.Parse()

	k, err := loadKey(*key)
	if err != nil {
		return err
	}
	a, err := parseAnchor(*anchor)
	if err != nil {
		return err
	}

	in := os.Stdin
	if flag.NArg() > 0 {
		f, err := os.Open(flag.Arg(0))
		if err != nil {
			return err
		}
		defer f.Close()
		in = f
	}

	if err := auditchain.VerifyStream(k, records(in), a); err != nil {
		return err
	}
	fmt.Printf("chain verifies: %d records, head %s\n", a.Count, a.Hash)
	return nil
}

// records yields one chain record per line, reporting a malformed line rather
// than ending the walk early — a short read must not look like a short chain.
func records(r io.Reader) func(func(auditchain.Record, error) bool) {
	return func(yield func(auditchain.Record, error) bool) {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var rec auditchain.Record
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				yield(auditchain.Record{}, err)
				return
			}
			if !yield(rec, nil) {
				return
			}
		}
		if err := sc.Err(); err != nil {
			yield(auditchain.Record{}, err)
		}
	}
}

func loadKey(spec string) ([]byte, error) {
	if !strings.HasPrefix(spec, "@") || len(spec) == 1 {
		return nil, errors.New("-key must be @path; inline secrets are exposed in process listings and shell history")
	}
	data, err := os.ReadFile(spec[1:])
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimSpace(string(data)))
}

func parseAnchor(spec string) (auditchain.Anchor, error) {
	count, hash, ok := strings.Cut(spec, ":")
	if !ok {
		return auditchain.Anchor{}, errors.New("-anchor must be count:hash")
	}
	n, err := strconv.ParseUint(count, 10, 64)
	if err != nil {
		return auditchain.Anchor{}, fmt.Errorf("-anchor count: %w", err)
	}
	return auditchain.Anchor{Count: n, Hash: hash}, nil
}
