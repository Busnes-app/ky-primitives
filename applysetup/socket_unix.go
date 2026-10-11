//go:build unix

package applysetup

import (
	"errors"
	"syscall"
	"unsafe"
)

// maxSocketPath is the platform sun_path size less its terminator: 107 on Linux, 103 on macOS.
const maxSocketPath = int(unsafe.Sizeof(syscall.RawSockaddrUnix{}.Path)) - 1

func staleSocket(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }
