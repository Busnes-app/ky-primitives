package applysetup

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/Busnes-app/ky-primitives/keyfile"
)

// ValidatePreparation checks secret-free metadata before any filesystem mutation.
// Products still validate their own service, callbacks and extended fields.
func (c Common) ValidatePreparation(service, callback, file string) error {
	if err := c.Validate(service, callback); err != nil {
		return err
	}
	paths := []string{}
	if c.SSO != nil {
		paths = append(paths, c.SSO.ClientSecretFile, c.SSO.DirectorySecretFile, c.SSO.SCIMTokenFile)
	}
	if c.Backup != nil && c.Backup.Recovery != nil {
		paths = append(paths, c.Backup.Recovery.PairingCodeFile)
	}
	seen := map[string]bool{file: true}
	for _, path := range paths {
		if path == "" {
			continue
		}
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || strings.ContainsFunc(path, unicode.IsControl) || seen[path] {
			return errors.New("preparation credentials require distinct clean absolute references")
		}
		seen[path] = true
	}
	return nil
}

func WritePreparation(out io.Writer, service, id, status string) error {
	if status != "created" && status != "present" {
		return errors.New("invalid native preparation status")
	}
	return json.NewEncoder(out).Encode(struct {
		Schema  string `json:"schema"`
		Service string `json:"service"`
		SetupID string `json:"setupId"`
		Status  string `json:"status"`
	}{"ky.setup-preparation/1", service, id, status})
}

// Stage publishes already validated, canonical, secret-free product metadata.
// Products decode/validate their own envelope before calling it; this function owns
// only immutable private-file preparation, never accounts or configuration.
func Stage(dataDir, file, id string, canonical []byte, check bool) (string, error) {
	if !setupID.MatchString(id) || len(canonical) < 16 || len(canonical) > MaxBundleBytes || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir || strings.ContainsFunc(dataDir, unicode.IsControl) || file != filepath.Join(dataDir, "installer", id, "setup.json") {
		return "", errors.New("invalid product preparation scope or size")
	}
	if err := requireStageDirectory(dataDir, false); err != nil {
		return "", errors.New("preparation requires a protected container-owned data directory")
	}
	for _, dir := range []string{filepath.Join(dataDir, "installer"), filepath.Dir(file)} {
		if !check {
			if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
				return "", errors.New("cannot create private preparation directory")
			}
		}
		if err := requireStageDirectory(dir, true); err != nil {
			return "", errors.New("preparation directory is absent, unsafe or foreign")
		}
	}
	compare := func() (string, error) {
		retained, err := keyfile.ReadPrivate(file, MaxBundleBytes)
		if err != nil || !bytes.Equal(retained, canonical) {
			return "", errors.New("prepared metadata is absent, unsafe or changed; retained files are preserved")
		}
		return "present", nil
	}
	if check {
		return compare()
	}
	if err := keyfile.Store(file, canonical, keyfile.Raw); err != nil {
		if errors.Is(err, os.ErrExist) {
			return compare()
		}
		return "", errors.New("cannot publish private preparation metadata")
	}
	return "created", nil
}
