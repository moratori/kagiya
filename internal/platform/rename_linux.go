//go:build linux

package platform

import (
	"errors"
	"syscall"
	"unsafe"
)

const (
	atFdCwd         = ^uintptr(99) // AT_FDCWD (-100)
	renameNoReplace = 1            // RENAME_NOREPLACE
)

// RenameNoReplace は、移動先が既にあれば失敗する改名（renameat2）。
// ハードリンクを作れないファイルシステム（vfat、exfat など）で、上書きせずにファイルを確定するために使う。
func RenameNoReplace(oldpath, newpath string) error {
	if sysRenameat2 == 0 {
		return errors.ErrUnsupported
	}
	o, err := syscall.BytePtrFromString(oldpath)
	if err != nil {
		return err
	}
	n, err := syscall.BytePtrFromString(newpath)
	if err != nil {
		return err
	}
	_, _, e := syscall.Syscall6(sysRenameat2, atFdCwd, uintptr(unsafe.Pointer(o)), atFdCwd, uintptr(unsafe.Pointer(n)), renameNoReplace, 0)
	if e != 0 {
		return e
	}
	return nil
}
