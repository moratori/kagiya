package keymat

import (
	"bytes"
	"runtime"
	"testing"
)

// 独立したレビュー（2026-11-14）の指摘 P-4。1 行 1 鍵の形式（authorized_keys など）を、全体を行に分けてから読んでいたので、
// 改行だけの 1 MiB のファイルで、約 100 万個の要素（約 25 MB）を確保した。
func TestSSHLinesDoNotAmplify(t *testing.T) {
	data := bytes.Repeat([]byte("\n"), 1<<20)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	items, failed := parseSSHLines(data)
	runtime.ReadMemStats(&after)
	if len(items) != 0 || failed != 0 {
		t.Errorf("items = %d failed = %d", len(items), failed)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 1<<20 {
		t.Errorf("allocated %d bytes for an input of %d bytes", got, len(data))
	}
}
