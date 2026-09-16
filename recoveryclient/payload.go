package recoveryclient

import (
	"fmt"
	"os"
	"strings"

	"github.com/Busnes-app/ky-primitives/capsule"
)

// MaxCapsuleFileBytes and MaxCapsuleTotalBytes are the caps capsule enforces on a payload,
// named here so an operator-facing message and the library can never disagree.
const (
	MaxCapsuleFileBytes  = capsule.MaxFileBytes
	MaxCapsuleTotalBytes = capsule.MaxExpandedBytes
)

// TooLargeMessage is what an operator is told when a backup outgrows a capsule.
var TooLargeMessage = fmt.Sprintf("Backup exceeds the capsule size limit (%d MiB per file, %d MiB total)",
	MaxCapsuleFileBytes>>20, MaxCapsuleTotalBytes>>20)

// File is one member of a capsule's payload, as the collectors produce it.
type File struct {
	Path string `json:"path"`
	Data []byte `json:"data"`
	Mode int64  `json:"mode"`
}

// Payload is what a backup carries: the members and the metadata the manifest records.
// ServiceName must equal the name KyRecovery pinned at pairing.
type Payload struct {
	ServiceName        string
	AppVersion         string
	Files              []File
	Dependencies       map[string]any
	VerificationRecipe map[string]any
}

// Seal writes a kycap/3 container sealed to the suite recovery public key with the pinned
// custodian topology. The product holds nothing afterwards that opens it; only the
// custodians' shares do.
func Seal(p Payload, key RecoveryKey) ([]byte, capsule.Manifest, error) {
	if key.Public.IsZero() {
		return nil, capsule.Manifest{}, ErrNotPaired
	}
	return capsule.Seal(p.ServiceName, p.AppVersion, toCapsuleFiles(p.Files), p.Dependencies, p.VerificationRecipe, key.Threshold, key.TotalShares, key.Public)
}

func toCapsuleFiles(files []File) []capsule.File {
	out := make([]capsule.File, 0, len(files))
	for _, f := range files {
		out = append(out, capsule.File{Path: f.Path, Content: f.Data, Mode: os.FileMode(f.Mode)})
	}
	return out
}

// FilenameSafe reduces a capsule ID to [A-Za-z0-9._-]. The ID embeds the app name, which an
// operator sets, so it can carry a quote, a slash or a newline that would break out of a
// Content-Disposition header or escape the directory a CLI export writes into.
func FilenameSafe(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			return r
		}
		return '-'
	}, s)
}
