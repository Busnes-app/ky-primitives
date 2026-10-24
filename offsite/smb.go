package offsite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/cloudsoda/go-smb2"
)

// ParseSMBEndpoint accepts a bare host, host:port, UNC path, slash path, or
// smb:// URL. Credentials in the endpoint are rejected because endpoints are
// commonly logged and stored in cleartext.
func ParseSMBEndpoint(endpoint, share, dir string) (addr, outShare, outDir string, err error) {
	addr = strings.ReplaceAll(endpoint, "\\", "/")
	if len(addr) >= 6 && strings.EqualFold(addr[:6], "smb://") {
		addr = addr[6:]
	}
	addr = strings.TrimLeft(addr, "/")
	if strings.Contains(addr, "@") {
		return "", "", "", errors.New("offsite: put SMB credentials in AccessKey and Secret, not the endpoint")
	}
	if host, rest, ok := strings.Cut(addr, "/"); ok {
		addr = host
		pathShare, pathDir, _ := strings.Cut(strings.Trim(rest, "/"), "/")
		if share == "" {
			share = pathShare
		}
		if dir == "" {
			dir = pathDir
		}
	}
	if addr == "" {
		return "", "", "", errors.New("offsite: SMB endpoint requires a host")
	}
	if _, _, splitErr := net.SplitHostPort(addr); splitErr != nil {
		if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
			addr = addr[1 : len(addr)-1]
		}
		addr = net.JoinHostPort(addr, "445")
	}
	// A stray bracket ("0]0", "host]") survives the default port and yields an
	// address the dialer and URL parser read differently, and ":" has neither
	// host nor port; refuse anything that is not exactly host:port.
	if host, port, splitErr := net.SplitHostPort(addr); splitErr != nil || host == "" || !validPort(port) {
		return "", "", "", fmt.Errorf("offsite: SMB endpoint has an invalid address %q", addr)
	}
	if share == "" || strings.ContainsAny(share, "/\\\x00") || share == "." || share == ".." {
		return "", "", "", errors.New("offsite: SMB endpoint requires a safe share name")
	}
	dir, err = cleanPrefix(dir)
	if err != nil {
		return "", "", "", err
	}
	return addr, share, dir, nil
}

// validPort reports whether port is a decimal TCP port from 1 to 65535.
func validPort(port string) bool {
	n, err := strconv.ParseUint(port, 10, 16)
	return err == nil && n > 0
}

type smbTarget struct {
	addr, share, user, secret, dir string
	timeout                        time.Duration
}

func (t *smbTarget) mount(ctx context.Context) (*smb2.Share, func(), error) {
	domain, user, _ := strings.Cut(t.user, "\\")
	if user == "" {
		domain, user = "", domain
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	cleanup := func() { stop(); _ = conn.Close() }
	dialer := &smb2.Dialer{
		Negotiator: smb2.Negotiator{RequireMessageSigning: true},
		Initiator:  &smb2.NTLMInitiator{User: user, Password: t.secret, Domain: domain},
	}
	session, err := dialer.DialConn(ctx, conn, t.addr)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	share, err := session.Mount(t.share)
	if err != nil {
		_ = session.Logoff()
		cleanup()
		return nil, nil, fmt.Errorf("offsite: mount SMB share %s: %w", t.share, err)
	}
	return share, func() { _ = share.Umount(); _ = session.Logoff(); cleanup() }, nil
}

func (t *smbTarget) Put(ctx context.Context, name string, r io.Reader, _ int64) error {
	name, err := cleanSMBName(name)
	if err != nil {
		return err
	}
	ctx, cancel := budget(ctx, t.timeout)
	defer cancel()
	share, cleanup, err := t.mount(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	final := path.Join(t.dir, name)
	if parent := path.Dir(final); parent != "." {
		if err := share.MkdirAll(parent, 0700); err != nil {
			return err
		}
	}
	if _, err := share.Stat(final); err == nil {
		return ErrObjectExists
	} else if !os.IsNotExist(err) {
		return err
	}
	tmp, err := stagingName(final)
	if err != nil {
		return err
	}
	f, err := share.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, &contextReader{ctx: ctx, r: r}); err != nil {
		_ = f.Close()
		_ = share.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = share.Remove(tmp)
		return err
	}
	if err := share.Rename(tmp, final); err != nil {
		_ = share.Remove(tmp)
		if os.IsExist(err) {
			return ErrObjectExists
		}
		return err
	}
	return nil
}

func (t *smbTarget) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	name, err := cleanSMBName(name)
	if err != nil {
		return nil, err
	}
	ctx, cancel := budget(ctx, t.timeout)
	share, cleanup, err := t.mount(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	f, err := share.Open(path.Join(t.dir, name))
	if err != nil {
		cleanup()
		cancel()
		if os.IsNotExist(err) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	return &sessionReadCloser{ReadCloser: f, cleanup: cleanup, cancel: cancel}, nil
}

// SMB servers commonly apply Windows case folding, alternate-data-stream,
// trailing-dot, device-name, and short-name rules. A small canonical grammar
// keeps distinct admitted names distinct on those servers.
func cleanSMBName(name string) (string, error) {
	name, err := cleanName(name)
	if err != nil {
		return "", err
	}
	for _, component := range strings.Split(name, "/") {
		if component[len(component)-1] == '.' {
			return "", errors.New("offsite: SMB object names must use lowercase ASCII letters, digits, dot, underscore, or hyphen")
		}
		for i := 0; i < len(component); i++ {
			c := component[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
				return "", errors.New("offsite: SMB object names must use lowercase ASCII letters, digits, dot, underscore, or hyphen")
			}
		}
		stem, _, _ := strings.Cut(component, ".")
		if stem == "con" || stem == "prn" || stem == "aux" || stem == "nul" ||
			(len(stem) == 4 && (strings.HasPrefix(stem, "com") || strings.HasPrefix(stem, "lpt")) && stem[3] >= '1' && stem[3] <= '9') {
			return "", errors.New("offsite: SMB object name uses a reserved Windows device name")
		}
	}
	return name, nil
}

func (t *smbTarget) Test(ctx context.Context) error {
	ctx, cancel := budget(ctx, t.timeout)
	defer cancel()
	share, cleanup, err := t.mount(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	if t.dir != "" {
		if err := share.MkdirAll(t.dir, 0700); err != nil {
			return err
		}
	}
	probe := path.Join(t.dir, pingName)
	if err := share.WriteFile(probe, []byte("ping"), 0600); err != nil {
		return err
	}
	return share.Remove(probe)
}
