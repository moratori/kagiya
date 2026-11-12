//go:build unix

package output

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func tmp(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestEnsureDirCreatesPrivateDirectory(t *testing.T) {
	d := filepath.Join(tmp(t), "out")
	if err := EnsureDir(d); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(d)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("mode = %o, want 700", fi.Mode().Perm())
	}
	// 既存のディレクトリはそのまま使える
	if err := EnsureDir(d); err != nil {
		t.Errorf("EnsureDir on existing dir: %v", err)
	}
}

func TestEnsureDirRejectsWorldWritableAndSymlink(t *testing.T) {
	base := tmp(t)
	ww := filepath.Join(base, "ww")
	if err := os.Mkdir(ww, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ww, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDir(ww); err == nil {
		t.Error("world-writable directory must be rejected")
	}
	real := filepath.Join(base, "real")
	os.Mkdir(real, 0o700)
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDir(link); err == nil {
		t.Error("symlink must be rejected as output directory")
	}
}

func TestCreateWritesOwnerOnlyFileAtomically(t *testing.T) {
	d := tmp(t)
	w, err := Create(d, "result.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	// 確定前は最終名のファイルが存在しない
	if _, err := os.Stat(filepath.Join(d, "result.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("final file must not exist before Commit (err=%v)", err)
	}
	if err := w.Commit(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(d, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", fi.Mode().Perm())
	}
	b, _ := os.ReadFile(filepath.Join(d, "result.json"))
	if string(b) != `{"a":1}` {
		t.Errorf("content = %q", b)
	}
	// 一時ファイルは残らない
	ents, _ := os.ReadDir(d)
	if len(ents) != 1 {
		t.Errorf("leftover files: %v", ents)
	}
}

func TestCreateNeverOverwrites(t *testing.T) {
	d := tmp(t)
	final := filepath.Join(d, "result.json")
	os.WriteFile(final, []byte("old"), 0o600)
	w, err := Create(d, "result.json")
	if err == nil {
		w.Write([]byte("new"))
		err = w.Commit()
	}
	if err == nil {
		t.Fatal("existing file must not be overwritten")
	}
	b, _ := os.ReadFile(final)
	if string(b) != "old" {
		t.Errorf("existing file was modified: %q", b)
	}
	ents, _ := os.ReadDir(d)
	if len(ents) != 1 {
		t.Errorf("leftover files: %v", ents)
	}
}

func TestCreateDoesNotFollowSymlink(t *testing.T) {
	d := tmp(t)
	victim := filepath.Join(tmp(t), "victim")
	os.WriteFile(victim, []byte("keep"), 0o600)
	// 攻撃者が一時ファイル名・最終名の位置にシンボリックリンクを仕込んだ場合
	os.Symlink(victim, filepath.Join(d, "result.json"))
	os.Symlink(victim, filepath.Join(d, "result.json.partial"))
	w, err := Create(d, "result.json")
	if err == nil {
		w.Write([]byte("pwned"))
		err = w.Commit()
	}
	if err == nil {
		t.Error("expected failure when a symlink occupies the target")
	}
	b, _ := os.ReadFile(victim)
	if string(b) != "keep" {
		t.Errorf("symlink target was written: %q", b)
	}
}

func TestCreateRejectsNameWithPathSeparator(t *testing.T) {
	d := tmp(t)
	for _, name := range []string{"../x.json", "a/b.json", "", ".", ".."} {
		if _, err := Create(d, name); err == nil {
			t.Errorf("Create(%q) must fail", name)
		}
	}
}

func TestAbortRemovesPartial(t *testing.T) {
	d := tmp(t)
	w, err := Create(d, "x.json")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("zzz"))
	w.Abort()
	ents, _ := os.ReadDir(d)
	if len(ents) != 0 {
		t.Errorf("leftover files after Abort: %v", ents)
	}
}
