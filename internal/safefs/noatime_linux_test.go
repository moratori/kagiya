package safefs

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// 独立したレビュー（2026-11-14）の指摘 A-2。読んだファイルとディレクトリのアクセス時刻（atime）を書き換えない。
// 既定のマウント（relatime）では、atime が更新時刻より古いファイルを読むと atime が書き換わるので、その状態を作ってから読む
// （noatime でマウントされた場所では、直す前でも変わらないので、このテストでは違いが出ない）。
func TestReadingDoesNotChangeAccessTime(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	sub := filepath.Join(dir, "sub")
	file := filepath.Join(sub, "a.pem")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("-----BEGIN X-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	for _, p := range []string{file, sub, dir} {
		if err := os.Chtimes(p, old, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	atime := func(p string) int64 {
		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			t.Fatal(err)
		}
		return st.Atim.Sec
	}
	check := func(what string) {
		t.Helper()
		for _, p := range []string{file, sub, dir} {
			if got := atime(p); got != old.Unix() {
				t.Errorf("%s: the access time of %s changed (%d)", what, p, got)
			}
		}
	}

	// 探索
	w := &Walker{}
	read := 0
	if err := w.Walk(context.Background(), dir, func(e *Entry) error {
		if _, err := e.ReadAll(); err == nil {
			read++
		}
		return nil
	}); err != nil || read != 1 {
		t.Fatalf("walk: %v, read %d file(s)", err, read)
	}
	check("walk")
	if w.Stats.AtimeNotPreserved != 0 {
		t.Errorf("the owner must be able to preserve access times: %d", w.Stats.AtimeNotPreserved)
	}

	// 名前で開く経路
	o := &Opener{}
	if _, err := o.ReadFile(file, 1024); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ListNames(sub); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ReadDir(sub); err != nil {
		t.Fatal(err)
	}
	check("opener")
}
