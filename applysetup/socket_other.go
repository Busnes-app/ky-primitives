//go:build !unix

package applysetup

func staleSocket(error) bool { return false }
