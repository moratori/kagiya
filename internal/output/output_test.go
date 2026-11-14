//go:build unix

package output

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

func TestEnsureDirRejectsGroupWritable(t *testing.T) {
	d := filepath.Join(tmp(t), "gw")
	os.Mkdir(d, 0o770)
	os.Chmod(d, 0o770)
	if err := EnsureDir(d); err == nil {
		t.Error("group-writable directory must be rejected")
	}
}

// ハードリンクを作れないファイルシステム（vfat、exfat など。USB メモリでの回収で使われる）では、
// 上書きしない改名で確定する。
func TestCommitFallsBackToExclusiveRename(t *testing.T) {
	d := tmp(t)
	restore := stubFinalize(
		func(old, new string) error { return &os.LinkError{Op: "link", Old: old, New: new, Err: syscall.EPERM} },
		func(old, new string) error {
			if _, err := os.Lstat(new); err == nil {
				return fs.ErrExist
			}
			return os.Rename(old, new)
		})
	defer restore()
	w, err := Create(d, "result.json")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("data"))
	if err := w.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(d, "result.json")); string(b) != "data" {
		t.Errorf("content = %q", b)
	}
	if ents, _ := os.ReadDir(d); len(ents) != 1 {
		t.Errorf("leftover files: %v", ents)
	}
}

// どの方法でも確定できない場合、書いた内容を捨てない。一時ファイルを残し、その場所をエラーで知らせる。
func TestCommitKeepsPartialWhenItCannotFinalize(t *testing.T) {
	d := tmp(t)
	restore := stubFinalize(
		func(old, new string) error { return &os.LinkError{Op: "link", Old: old, New: new, Err: syscall.EPERM} },
		func(old, new string) error { return errors.ErrUnsupported })
	defer restore()
	w, _ := Create(d, "result.json")
	w.Write([]byte("precious"))
	err := w.Commit()
	if err == nil {
		t.Fatal("Commit must fail")
	}
	partial := filepath.Join(d, "result.json.partial")
	if !strings.Contains(err.Error(), partial) {
		t.Errorf("the error must name the kept file: %v", err)
	}
	if b, _ := os.ReadFile(partial); string(b) != "precious" {
		t.Errorf("partial content = %q; the result must not be lost", b)
	}
}

// 既に同じ名前のファイルがある場合は、上書きせず、一時ファイルも残さない。
func TestCommitFallbackNeverOverwrites(t *testing.T) {
	d := tmp(t)
	restore := stubFinalize(
		func(old, new string) error { return &os.LinkError{Op: "link", Old: old, New: new, Err: syscall.EPERM} },
		func(old, new string) error { return fs.ErrExist })
	defer restore()
	w, _ := Create(d, "result.json")
	w.Write([]byte("new"))
	if err := w.Commit(); !errors.Is(err, fs.ErrExist) {
		t.Errorf("err = %v, want fs.ErrExist", err)
	}
	if ents, _ := os.ReadDir(d); len(ents) != 0 {
		t.Errorf("leftover files: %v", ents)
	}
}

// 出力先でファイルを確定できるかを、スキャンの前に確かめる。
func TestProbe(t *testing.T) {
	d := tmp(t)
	if err := Probe(d); err != nil {
		t.Fatalf("Probe on a normal directory: %v", err)
	}
	if ents, _ := os.ReadDir(d); len(ents) != 0 {
		t.Errorf("Probe left files behind: %v", ents)
	}
	restore := stubFinalize(
		func(old, new string) error { return &os.LinkError{Op: "link", Old: old, New: new, Err: syscall.EPERM} },
		func(old, new string) error { return errors.ErrUnsupported })
	defer restore()
	if err := Probe(d); err == nil {
		t.Error("Probe must fail when files cannot be finalized")
	}
	if ents, _ := os.ReadDir(d); len(ents) != 0 {
		t.Errorf("failed Probe left files behind: %v", ents)
	}
}

func stubFinalize(link, rename func(old, new string) error) func() {
	l, r := linkFile, renameNoReplace
	linkFile, renameNoReplace = link, rename
	return func() { linkFile, renameNoReplace = l, r }
}

// ログは、最初から最終名で作る（異常終了しても、ログが書きかけの名前で残らないように。指摘 A-12）。
func TestCreateDirectUsesFinalNameFromTheStart(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	w, err := CreateDirect(dir, "kagiya.log")
	if err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(dir, "kagiya.log")
	fi, err := os.Lstat(final)
	if err != nil || fi.Mode().Perm() != 0o600 || w.Path() != final {
		t.Fatalf("the file must exist under its final name with mode 600: %v %v", fi, err)
	}
	if _, err := os.Lstat(final + ".partial"); err == nil {
		t.Error("no .partial file is expected")
	}
	w.Write([]byte("line\n"))
	if err := w.Commit(); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(final); string(data) != "line\n" {
		t.Errorf("content = %q", data)
	}
	// 上書きしない。リンクも辿らない
	if _, err := CreateDirect(dir, "kagiya.log"); err == nil {
		t.Error("an existing file must not be overwritten")
	}
	os.Symlink(filepath.Join(dir, "elsewhere"), filepath.Join(dir, "link.log"))
	if _, err := CreateDirect(dir, "link.log"); err == nil {
		t.Error("a symbolic link must not be followed")
	}
	if _, err := CreateDirect(dir, "a/b.log"); err == nil {
		t.Error("a name with a path separator must be rejected")
	}
}
