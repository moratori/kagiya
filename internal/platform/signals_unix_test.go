//go:build unix

package platform

import (
	"syscall"
	"testing"
)

// 接続が切れたとき（SIGHUP）も、途中の結果を書いてから終わる（指摘 A-11）。
func TestTerminationSignalsIncludeHangup(t *testing.T) {
	want := map[syscall.Signal]bool{syscall.SIGINT: false, syscall.SIGTERM: false, syscall.SIGHUP: false}
	for _, s := range TerminationSignals() {
		if sig, ok := s.(syscall.Signal); ok {
			if _, known := want[sig]; known {
				want[sig] = true
			}
		}
	}
	for sig, found := range want {
		if !found {
			t.Errorf("signal %v is not handled", sig)
		}
	}
}
