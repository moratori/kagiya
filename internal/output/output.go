// Package output は出力ディレクトリ・ログディレクトリへの書き込みを担う唯一の経路。
// 出力は機密扱いとし、作成者だけが読める権限で、既存ファイルを上書きせずに作成する。
package output

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"kagiya/internal/platform"
)

// EnsureDir は出力先ディレクトリを検証し、無ければ所有者専用の権限で作成する（親は作らない）。
func EnsureDir(dir string) error {
	if err := supported(); err != nil {
		return err
	}
	// 上位に、他の利用者が書き込めるディレクトリがあれば、出力先そのものを差し替えられる
	if abs, err := filepath.Abs(dir); err == nil {
		if err := platform.CheckAncestors(abs); err != nil {
			return fmt.Errorf("%w; the output directory could be replaced by another user. Use a directory whose parents are not writable by others", err)
		}
	}
	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return fmt.Errorf("create directory: %w", err)
		}
		// 権限は、作ったディレクトリを開いて、その開いたものに対して付ける（パスで指定すると、その間にリンクへ差し替えられた場合に、
		// リンクの先の権限を変えてしまう）
		d, err := os.OpenFile(dir, os.O_RDONLY|platform.ReadOpenFlags|platform.DirectoryFlag, 0)
		if err != nil {
			return fmt.Errorf("open the new directory: %w", err)
		}
		defer d.Close()
		if st, err := d.Stat(); err != nil || !st.IsDir() {
			return fmt.Errorf("%s is not the directory that was just created", dir)
		}
		return d.Chmod(0o700)
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
	// 出力は機密扱い。他のユーザーやグループが書き込める場所では、ファイルの差し替えや削除ができてしまう。
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by other users; use a private directory (for example: chmod 700)", dir)
	}
	if !platform.OwnedBySelfOrRoot(fi) {
		return fmt.Errorf("%s is owned by another user; use a directory you own", dir)
	}
	return nil
}

// Writer は書き込み中のファイル。Commit するまで最終名では現れない。
type Writer struct {
	f              *os.File
	partial, final string
	done           bool
	direct         bool // 最初から最終名で作ったもの（CreateDirect）
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

// 確定に使う操作（テストで差し替える）。
var (
	linkFile        = os.Link
	renameNoReplace = platform.RenameNoReplace
)

// Commit は内容をディスクに書き出し、最終名で確定する。最終名が既にあれば失敗する（上書きしない）。
//
// まずハードリンクで確定する（既存の名前を置き換えないので、上書きの競合が起きない）。
// ハードリンクを作れないファイルシステム（vfat、exfat など）では、上書きしない改名で確定する。
// どちらもできない場合は、書いた内容を捨てずに一時ファイル（.partial）を残し、その場所をエラーで知らせる。
func (w *Writer) Commit() error {
	if w.done {
		return errors.New("writer already closed")
	}
	w.done = true
	err := w.f.Sync()
	if cerr := w.f.Close(); err == nil {
		err = cerr
	}
	if w.direct {
		return err // 最終名で作ってあるので、確定の手順は要らない（書き込みに失敗しても、書けた分は残す）
	}
	if err != nil {
		os.Remove(w.partial) // 書き込み自体が不完全
		return err
	}
	err = linkFile(w.partial, w.final)
	switch {
	case err == nil:
		return os.Remove(w.partial)
	case errors.Is(err, fs.ErrExist):
		os.Remove(w.partial)
		return err
	}
	switch rerr := renameNoReplace(w.partial, w.final); {
	case rerr == nil:
		return nil
	case errors.Is(rerr, fs.ErrExist):
		os.Remove(w.partial)
		return rerr
	}
	return fmt.Errorf("could not finalize %s on this filesystem (%v); the content was kept at %s", w.final, err, w.partial)
}

// Probe は、dir でファイルを確定できるか（ハードリンクまたは上書きしない改名が使えるか）を、小さな試験ファイルで確かめる。
// スキャンを終えてから結果を書けないと分かるのを避けるため、最初に呼ぶ。試験ファイルは残さない。
func Probe(dir string) error {
	var r [8]byte
	if _, err := rand.Read(r[:]); err != nil {
		return err
	}
	name := ".kagiya-probe-" + hex.EncodeToString(r[:])
	w, err := Create(dir, name)
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte("probe\n")); err != nil {
		w.Abort()
		return err
	}
	if err := w.Commit(); err != nil {
		os.Remove(w.partial)
		return fmt.Errorf("%s does not support creating files without overwriting (hard link or exclusive rename): %v", dir, errors.Unwrap(err))
	}
	return os.Remove(w.final)
}

// Abort は書きかけのファイルを破棄する。
func (w *Writer) Abort() {
	if w.done {
		return
	}
	w.done = true
	w.f.Close()
	if w.direct {
		os.Remove(w.final)
		return
	}
	os.Remove(w.partial)
}

// CreateDirect は dir 直下に name を、最初から最終名で作る（ログ用。書き足していくファイルなので、書きかけを隠す必要がなく、
// 異常終了したときに最終名で残っているほうがよい）。既存のファイルやシンボリックリンクがあれば失敗する（上書きしない・辿らない）。
func CreateDirect(dir, name string) (*Writer, error) {
	if err := supported(); err != nil {
		return nil, err
	}
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) || name != filepath.Base(name) {
		return nil, fmt.Errorf("invalid output file name %q", name)
	}
	final := filepath.Join(dir, name)
	f, err := os.OpenFile(final, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", final, err)
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		os.Remove(final)
		return nil, err
	}
	return &Writer{f: f, final: final, direct: true}, nil
}
