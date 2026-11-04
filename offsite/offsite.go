package offsite

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path"
	"strings"
	"time"
)

const (
	defaultTransferBudget = 5 * time.Minute
	pingName              = ".ky-offsite-ping"
	stagingPrefix         = ".ky-offsite-tmp-"
)

// ErrObjectExists is returned when a backend cannot safely replace an object.
var ErrObjectExists = errors.New("offsite: object already exists")

// Target is an offsite object store. Get returns an error matching
// os.ErrNotExist when name is absent.
type Target interface {
	Put(ctx context.Context, name string, r io.Reader, size int64) error
	Get(ctx context.Context, name string) (io.ReadCloser, error)
	Test(ctx context.Context) error
}

// Config describes one target. Secrets belong in the dedicated fields, never
// in URL.
type Config struct {
	URL        string
	AccessKey  string
	Secret     string
	HostKey    string
	S3Endpoint string
	S3Region   string
	Timeout    time.Duration
}

// Parse validates c and constructs its target.
func Parse(c Config) (Target, error) {
	if c.Timeout < 0 {
		return nil, errors.New("offsite: timeout must not be negative")
	}
	u, err := url.Parse(c.URL)
	if err != nil {
		return nil, errors.New("offsite: invalid target URL")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("offsite: target URL must not contain a query or fragment")
	}
	if u.User != nil {
		if _, set := u.User.Password(); set {
			return nil, errors.New("offsite: put passwords in Secret, not URL userinfo")
		}
	}
	switch strings.ToLower(u.Scheme) {
	case "file":
		if u.Host != "" || !path.IsAbs(u.Path) {
			return nil, errors.New("offsite: file URL must contain an absolute path and no host")
		}
		if u.User != nil || c.AccessKey != "" || c.Secret != "" || c.HostKey != "" {
			return nil, errors.New("offsite: file target does not accept credentials")
		}
		return &localTarget{dir: u.Path}, nil
	case "s3":
		if u.User != nil || u.Host == "" {
			return nil, errors.New("offsite: s3 URL must be s3://bucket/prefix without userinfo")
		}
		if c.AccessKey == "" || c.Secret == "" {
			return nil, errors.New("offsite: s3 requires AccessKey and Secret")
		}
		prefix, err := cleanPrefix(u.Path)
		if err != nil {
			return nil, err
		}
		return newS3Target(u.Host, prefix, c)
	case "sftp":
		if u.Hostname() == "" {
			return nil, errors.New("offsite: sftp URL requires a host")
		}
		user := c.AccessKey
		if u.User != nil {
			if user != "" && user != u.User.Username() {
				return nil, errors.New("offsite: sftp URL user and AccessKey disagree")
			}
			user = u.User.Username()
		}
		if user == "" || c.Secret == "" {
			return nil, errors.New("offsite: sftp requires a user and Secret")
		}
		dir, err := cleanPrefix(u.Path)
		if err != nil {
			return nil, err
		}
		addr := u.Host
		if u.Port() == "" {
			addr = net.JoinHostPort(u.Hostname(), "22")
		}
		return &sftpTarget{addr: addr, user: user, secret: c.Secret, dir: dir, hostKey: c.HostKey, timeout: c.Timeout}, nil
	case "smb":
		if u.User != nil {
			return nil, errors.New("offsite: put SMB credentials in AccessKey and Secret, not URL userinfo")
		}
		addr, share, dir, err := ParseSMBEndpoint(u.Host+u.Path, "", "")
		if err != nil {
			return nil, err
		}
		if addr == "" || share == "" || c.AccessKey == "" || c.Secret == "" {
			return nil, errors.New("offsite: smb requires host, share, AccessKey, and Secret")
		}
		return &smbTarget{addr: addr, share: share, user: c.AccessKey, secret: c.Secret, dir: dir, timeout: c.Timeout}, nil
	default:
		return nil, fmt.Errorf("offsite: unsupported target scheme %q", u.Scheme)
	}
}

// Key returns a stable target identity with credentials removed. URLs that
// cannot be parsed return an empty key.
func Key(c Config) string {
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme == "" {
		return ""
	}
	u.User, u.RawQuery, u.Fragment = nil, "", ""
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	base := u.String()
	if u.Scheme != "s3" {
		return base
	}
	endpoint, err := url.Parse(c.S3Endpoint)
	if err != nil {
		return ""
	}
	endpoint.User, endpoint.RawQuery, endpoint.Fragment = nil, "", ""
	endpoint.Scheme = strings.ToLower(endpoint.Scheme)
	endpoint.Host = strings.ToLower(endpoint.Host)
	region := c.S3Region
	if region == "" {
		region = "us-east-1"
	}
	return base + "|" + endpoint.String() + "|" + region
}

func cleanName(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "\\\x00") || strings.HasPrefix(name, "/") {
		return "", errors.New("offsite: object name must be a relative slash-separated path")
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." || strings.HasPrefix(part, stagingPrefix) {
			return "", errors.New("offsite: object name contains an unsafe path component")
		}
	}
	return name, nil
}

func stagingName(final string) (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("offsite: create staging name: %w", err)
	}
	return path.Join(path.Dir(final), stagingPrefix+hex.EncodeToString(random[:])), nil
}

func cleanPrefix(p string) (string, error) {
	p = strings.Trim(p, "/")
	if p == "" {
		return "", nil
	}
	return cleanName(p)
}

func budget(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout == 0 {
		timeout = defaultTransferBudget
	}
	return context.WithTimeout(ctx, timeout)
}
