package platform

import (
	"errors"
	"testing"
)

// マウント表は、読んでいる途中でマウントが変わると、行が抜けることがある（古いカーネル）。2 回続けて同じ内容が読めるまで読み直す
// （独立したレビューの指摘 A-10）。
func TestReadStable(t *testing.T) {
	seq := func(items ...string) func() ([]byte, error) {
		i := 0
		return func() ([]byte, error) {
			if i >= len(items) {
				return nil, errors.New("no more")
			}
			i++
			return []byte(items[i-1]), nil
		}
	}
	if b, ok := readStable(seq("A", "A")); !ok || string(b) != "A" {
		t.Errorf("two equal reads: %q %v", b, ok)
	}
	if b, ok := readStable(seq("A", "B", "B")); !ok || string(b) != "B" {
		t.Errorf("a change between reads: %q %v", b, ok)
	}
	if _, ok := readStable(seq("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L")); ok {
		t.Error("content that never settles must not be accepted")
	}
	if _, ok := readStable(seq("A")); ok {
		t.Error("a read error must not be accepted")
	}
}
