//go:build linux

package applysetup

import (
	"errors"
	"os"
	"strings"
	"syscall"
)

// Pin each ancestor with openat/no-follow. A root/user-owned sticky ancestor is
// permitted, but the product anchor and preparation directory belong to this user.
func requireStageDirectory(path string, private bool) error {
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("cannot inspect preparation directory")
	}
	defer func() { syscall.Close(fd) }()
	var st syscall.Stat_t
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, err := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return errors.New("unsafe preparation ancestor")
		}
		syscall.Close(fd)
		fd = next
		if syscall.Fstat(fd, &st) != nil || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || (st.Mode&0022 != 0 && st.Mode&syscall.S_ISVTX == 0) {
			return errors.New("preparation ancestors require protected root or runtime ownership")
		}
	}
	mask := uint32(0022)
	if private {
		mask = 0077
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&mask != 0 {
		return errors.New("preparation directory requires runtime ownership and protected permissions")
	}
	return nil
}
