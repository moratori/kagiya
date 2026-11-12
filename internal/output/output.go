// Package output は出力ディレクトリ・ログディレクトリへの書き込みを担う唯一の経路。
// 出力は機密扱いとし、作成者だけが読める権限で、既存ファイルを上書きせずに作成する。
package output

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// EnsureDir は出力先ディレクトリを検証し、無ければ所有者専用の権限で作成する（親は作らない）。
func EnsureDir(dir string) error {
	if err := supported(); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return fmt.Errorf("create directory: %w", err)
		}
		return os.Chmod(dir, 0o700)
	}
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link; specify the real directory", dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("%s is writable by other users; use a private directory", dir)
	}
	return nil
}

// Writer は書き込み中のファイル。Commit するまで最終名では現れない。
type Writer struct {
	f              *os.File
	partial, final string
	done           bool
}

// Create は dir 直下に name を作る準備をする。name にパス区切りは使えない。
func Create(dir, name string) (*Writer, error) {
	if err := supported(); err != nil {
		return nil, err
	}
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) || name != filepath.Base(name) {
		return nil, fmt.Errorf("invalid output file name %q", name)
	}
	final := filepath.Join(dir, name)
	if _, err := os.Lstat(final); err == nil {
		return nil, fmt.Errorf("%s already exists; refusing to overwrite", final)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	partial := final + ".partial"
	// O_EXCL: 既存のファイルやシンボリックリンクがあれば失敗する（辿らない・上書きしない）。
	f, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", partial, err)
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		os.Remove(partial)
		return nil, err
	}
	return &Writer{f: f, partial: partial, final: final}, nil
}

func (w *Writer) Write(p []byte) (int, error) { return w.f.Write(p) }

// Path は確定後のファイルパス。
func (w *Writer) Path() string { return w.final }

// Commit は内容をディスクに書き出し、最終名で確定する。最終名が既にあれば失敗する。
func (w *Writer) Commit() error {
	if w.done {
		return errors.New("writer already closed")
	}
	w.done = true
	err := w.f.Sync()
	if cerr := w.f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		// ハードリンクは既存の名前を置き換えないので、上書きの競合が起きない。
		err = os.Link(w.partial, w.final)
	}
	if rerr := os.Remove(w.partial); err == nil && rerr != nil {
		err = rerr
	}
	return err
}

// Abort は書きかけのファイルを破棄する。
func (w *Writer) Abort() {
	if w.done {
		return
	}
	w.done = true
	w.f.Close()
	os.Remove(w.partial)
}
