package recoveryclient

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/ky-primitives/shamir"
)

// restore is the product-side half of the ceremony: k custodian shares typed from their cards,
// combined here, used once, and dropped. It refuses a capsule from another service before
// touching the key, and prints the authenticated manifest so the operator can compare
// CapsuleID and CreatedAt against kyrecovery's deposit record.
func Restore(capsulePath, targetDir, expectService string, shareStrings []string, stdout io.Writer) error {
	raw, err := os.ReadFile(capsulePath)
	if err != nil {
		return err
	}
	peek, err := capsule.ReadUnverifiedManifest(raw)
	if err != nil {
		return err
	}
	if peek.ServiceName != expectService {
		return fmt.Errorf("capsule is for service %q, this instance is %q; pass -service to override", peek.ServiceName, expectService)
	}
	shares := make([]shamir.Share, 0, len(shareStrings))
	for i, s := range shareStrings {
		sh, err := shamir.ParseShare(s)
		if err != nil {
			return fmt.Errorf("share %d: %w", i+1, err)
		}
		shares = append(shares, sh)
	}
	priv, err := recoverykey.Combine(shares)
	if err != nil {
		return err
	}
	m, files, err := capsule.Open(raw, priv, targetDir)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Restored %d files from capsule %s\n  service:      %s (v%s)\n  created:      %s\n  recovery key: %s\n  payload hash: %s\n",
		len(files), AuditSafe(m.CapsuleID), AuditSafe(m.ServiceName), AuditSafe(m.AppVersion), m.CreatedAt.Format(time.RFC3339), AuditSafe(m.RecoveryKeyID), AuditSafe(m.PayloadHash))
	return nil
}

// readShares takes custodian shares off a reader, one per non-empty line. They never travel
// in argv: /proc/<pid>/cmdline is world-readable, argv lands in shell history, and k of these
// lines rebuild the suite private key.
func ReadShares(r io.Reader) ([]string, error) {
	var shares []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			shares = append(shares, line)
		}
	}
	return shares, sc.Err()
}
