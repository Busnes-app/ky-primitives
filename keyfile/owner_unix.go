//go:build unix

package keyfile

import (
	"os"
	"syscall"
)

func ownerUID(fi os.FileInfo) (uint32, bool) {
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}
