//go:build unix

package applysetup

import (
	"errors"
	"syscall"
)

func staleSocket(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }
