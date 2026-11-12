//go:build windows

package platform

import (
	"errors"
	"os"
)

// Elevated は Windows では未実装（実機検証とあわせて実装する）。
func Elevated() bool { return false }

// TerminationSignals は安全に停止すべきシグナル。
func TerminationSignals() []os.Signal { return []os.Signal{os.Interrupt} }

// CheckTrustedDir は Windows では未実装のため、外部ルールを受け付けない。
func CheckTrustedDir(dir string) error {
	return errors.New("external rule directories are not yet supported on Windows")
}
