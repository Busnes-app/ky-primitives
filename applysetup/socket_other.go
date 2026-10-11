//go:build !unix

package applysetup

const maxSocketPath = 107

func staleSocket(error) bool { return false }
