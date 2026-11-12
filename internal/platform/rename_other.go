//go:build !linux

package platform

import "errors"

// RenameNoReplace は Linux 以外では未対応。
func RenameNoReplace(oldpath, newpath string) error { return errors.ErrUnsupported }
