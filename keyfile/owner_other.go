//go:build !unix

package keyfile

import "os"

// Ownership cannot be verified here, so private reads fail closed.
func ownerUID(os.FileInfo) (uint32, bool) { return 0, false }
