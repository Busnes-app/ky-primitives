//go:build !linux

package applysetup

import "errors"

func requireStageDirectory(string, bool) error {
	return errors.New("native preparation requires Linux protected-directory support")
}
