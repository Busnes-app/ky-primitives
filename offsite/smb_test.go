package offsite

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseSMBEndpoint(t *testing.T) {
	tests := []struct {
		endpoint, share, dir, addr string
	}{
		{"nas.lan", "Public", "capsules", "nas.lan:445"},
		{"nas.lan:1445", "Public", "capsules", "nas.lan:1445"},
		{"//nas.lan/Public/", "", "capsules", "nas.lan:445"},
		{`\\nas.lan\Public\capsules`, "", "", "nas.lan:445"},
		{"smb://nas.lan/Public/capsules/", "", "", "nas.lan:445"},
		{"smb://[::1]:1445/Public", "", "capsules", "[::1]:1445"},
		{"[::1]", "Public", "capsules", "[::1]:445"},
		{"::1", "Public", "capsules", "[::1]:445"},
	}
	for _, tt := range tests {
		addr, share, dir, err := ParseSMBEndpoint(tt.endpoint, tt.share, tt.dir)
		if err != nil || addr != tt.addr || share != "Public" || dir != "capsules" {
			t.Errorf("%q -> addr=%q share=%q dir=%q err=%v", tt.endpoint, addr, share, dir, err)
		}
	}
	for _, endpoint := range []string{"smb://ky:hunter2@nas/Public", "//ky@nas/Public", `smb://CORP\ky:pw@nas/Public`} {
		if addr, share, dir, err := ParseSMBEndpoint(endpoint, "", ""); err == nil || addr != "" || share != "" || dir != "" {
			t.Errorf("accepted credential-bearing endpoint %q", endpoint)
		}
	}
	// Found by fuzzing: a stray bracket came back as "0]0:445", which validation
	// accepted but the dialer could not use, and ":" came back with no host or port.
	for _, endpoint := range []string{"0]0", "0[0", "nas.lan]", "[nas.lan", "smb://nas]/Public", ":", ":445", "nas.lan:", "nas.lan:0", "nas.lan:65536", "nas.lan:smb"} {
		if addr, share, dir, err := ParseSMBEndpoint(endpoint, "Public", ""); err == nil || addr != "" || share != "" || dir != "" {
			t.Errorf("accepted %q as addr=%q", endpoint, addr)
		}
	}
}

func TestSMBStallHonorsBudget(t *testing.T) {
	target := &smbTarget{addr: stalledAddress(t), share: "vault", user: "ky", secret: "pw", dir: "dir", timeout: 200 * time.Millisecond}
	start := time.Now()
	if err := target.Put(context.Background(), "object", strings.NewReader("x"), 1); err == nil {
		t.Fatal("stalled server returned no error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("operation took %s", elapsed)
	}
}

func TestSMBNamesCannotAlias(t *testing.T) {
	for _, name := range []string{
		"tenant/secret::$DATA",
		"tenant/Secret",
		"tenant/secret.",
		"tenant/secret ",
		"tenant/con",
		"tenant/con.txt",
		"tenant/com1.log",
		"tenant/café",
		"tenant/progra~1",
	} {
		if _, err := cleanSMBName(name); err == nil {
			t.Errorf("accepted alias-prone SMB name %q", name)
		}
	}
	for _, name := range []string{"tenant/secret", "capsules/a1b2-c3.kycap", pingName} {
		if got, err := cleanSMBName(name); err != nil || got != name {
			t.Errorf("cleanSMBName(%q) = %q, %v", name, got, err)
		}
	}
}

func TestSMBLiveContract(t *testing.T) {
	spec := os.Getenv("KY_OFFSITE_SMB_TEST")
	if spec == "" {
		t.Skip("KY_OFFSITE_SMB_TEST not set")
	}
	parts := strings.SplitN(spec, "|", 3)
	if len(parts) != 3 {
		t.Fatal("KY_OFFSITE_SMB_TEST must be host:port/share|user|password")
	}
	hostShare := strings.SplitN(parts[0], "/", 2)
	if len(hostShare) != 2 {
		t.Fatal("KY_OFFSITE_SMB_TEST must be host:port/share|user|password")
	}
	target, err := Parse(Config{
		URL:       "smb://" + hostShare[0] + "/" + hostShare[1] + "/ky-offsite-test",
		AccessKey: parts[1], Secret: parts[2], Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	name := "contract-object-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if err := target.Put(context.Background(), name, strings.NewReader("payload"), 7); err != nil {
		t.Fatal(err)
	}
	if err := target.Put(context.Background(), name, strings.NewReader("replacement"), 11); !errors.Is(err, ErrObjectExists) {
		t.Fatalf("SMB overwrite error = %v", err)
	}
	r, err := target.Get(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil || string(raw) != "payload" {
		t.Fatalf("Get = %q, %v", raw, err)
	}
	if _, err := target.Get(context.Background(), "missing-object"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing error = %v", err)
	}
}
