package safefs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"kagiya/internal/platform"
	"kagiya/internal/throttle"
)

// Skip は読まなかった場所と理由。結果 JSON の skipped[] とログに記録する。
type Skip struct {
	Path, Reason, Detail string
}

// ErrSkipped は対象を読まずに飛ばしたことを表す（理由は OnSkip に通知済み）。
var ErrSkipped = errors.New("skipped")

// MountChecker はパスに触れてよいかをマウント表から判定する。
type MountChecker interface {
	Check(path string) (Verdict, Mount)
	ByDevice(major, minor uint32) (Verdict, Mount, bool)
}

// Stats は走査の統計。
type Stats struct {
	Dirs, Files, Symlinks, Special int
	BytesRead                      int64
	// アクセス時刻（atime）を更新しない開き方ができなかった数（所有者でも root でもない場合）
	AtimeNotPreserved int
}

const (
	defaultMaxDepth    = 64
	defaultMaxFileSize = 64 << 20
	readChunk          = 64 << 10
	dirBatch           = 256
)

// サブボリュームを持ち、マウント境界でなくてもデバイス番号が変わるファイルシステム。
var subvolumeFS = map[string]bool{"btrfs": true, "bcachefs": true}

// Walker はディレクトリツリーを安全に辿る。
//   - 触れる前にマウント表で判定し、ネットワーク FS・自動マウント等には立ち入らない
//   - シンボリックリンクを辿らず、通常ファイル以外は開かない
//   - ディレクトリハンドル相対で開き、確認後の差し替えを検出する
type Walker struct {
	Mounts      MountChecker // nil なら判定しない（マウント表が得られない OS）
	Excludes    *Excludes
	SkipDirs    []string // 常に除外するディレクトリ（出力先・ログ先）
	MaxFileSize int64    // 0 なら既定値
	MaxDepth    int      // 0 なら既定値
	Limiter     *throttle.Limiter
	OnSkip      func(Skip)
	Stats       Stats

	devOf func(fs.FileInfo) (major, minor uint32, ok bool) // テスト用の差し替え口
}

// Entry は走査中に見つかった通常ファイル。visit の呼び出し中だけ有効。
type Entry struct {
	Path string
	Name string
	Size int64

	w    *Walker
	dir  *os.Root
	info fs.FileInfo
}

func (w *Walker) skip(path, reason, detail string) {
	if w.OnSkip != nil {
		w.OnSkip(Skip{Path: path, Reason: reason, Detail: detail})
	}
}

func (w *Walker) maxDepth() int {
	if w.MaxDepth > 0 {
		return w.MaxDepth
	}
	return defaultMaxDepth
}

func (w *Walker) maxFileSize() int64 {
	if w.MaxFileSize > 0 {
		return w.MaxFileSize
	}
	return defaultMaxFileSize
}

func (w *Walker) check(path string) (Verdict, Mount) {
	if w.Mounts == nil {
		return Allow, Mount{}
	}
	return w.Mounts.Check(path)
}

// Walk は root 配下の通常ファイルごとに visit を呼ぶ。root は正規化済みの絶対パスで、
// シンボリックリンクを含んではならない。root が読んではならない場所にある場合はスキップを記録して nil を返す。
func (w *Walker) Walk(ctx context.Context, root string, visit func(*Entry) error) error {
	if !isCleanAbs(root) {
		return fmt.Errorf("scan root %q must be a clean absolute path", root)
	}
	// ルートから1要素ずつ、触れる前にマウント表で判定し、その後でリンクでないことを確かめる。
	prefix := ""
	for _, seg := range strings.Split(strings.TrimPrefix(root, "/"), "/") {
		if seg == "" {
			break
		}
		prefix += "/" + seg
		if v, m := w.check(prefix); v != Allow {
			w.skip(root, v.Reason(), m.FSType)
			return nil
		}
		fi, err := os.Lstat(prefix)
		if err != nil {
			return fmt.Errorf("scan root: %w", err)
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("scan root %q contains a symbolic link at %q; specify the real path", root, prefix)
		}
		if !fi.IsDir() {
			return fmt.Errorf("scan root %q: %q is not a directory", root, prefix)
		}
	}
	if v, m := w.check(root); v != Allow {
		w.skip(root, v.Reason(), m.FSType)
		return nil
	}
	for _, sd := range w.SkipDirs {
		if root == sd {
			w.skip(root, "excluded", "output-directory")
			return nil
		}
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			w.skip(root, "permission-denied", "")
			return nil
		}
		return fmt.Errorf("scan root: %w", err)
	}
	defer r.Close()
	if fi, err := r.Stat("."); err == nil {
		if reason, detail := w.deviceVerdict(root, fi); reason != "" {
			w.skip(root, reason, detail)
			return nil
		}
	}
	return w.walkDir(ctx, r, root, 0, visit)
}

func join(dir, name string) string {
	if dir == "/" {
		return "/" + name
	}
	return dir + "/" + name
}

func (w *Walker) walkDir(ctx context.Context, r *os.Root, path string, depth int, visit func(*Entry) error) error {
	w.Stats.Dirs++
	d, err := openQuietly(func(flag int) (*os.File, error) { return r.OpenFile(".", flag, 0) }, os.O_RDONLY|platform.DirectoryFlag, &w.Stats.AtimeNotPreserved)
	if err != nil {
		w.skipErr(path, err)
		return nil
	}
	defer d.Close()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		ents, err := d.ReadDir(dirBatch)
		for _, de := range ents {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := w.walkEntry(ctx, r, path, de.Name(), depth, visit); err != nil {
				return err
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				w.skipErr(path, err)
			}
			return nil
		}
	}
}

func (w *Walker) walkEntry(ctx context.Context, r *os.Root, dir, name string, depth int, visit func(*Entry) error) error {
	full := join(dir, name)
	if w.Excludes.Match(full) {
		w.skip(full, "excluded", "")
		return nil
	}
	fi, err := r.Lstat(name)
	if err != nil {
		w.skipErr(full, err)
		return nil
	}
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		w.Stats.Symlinks++
	case fi.IsDir():
		for _, sd := range w.SkipDirs {
			if full == sd {
				w.skip(full, "excluded", "output-directory")
				return nil
			}
		}
		if depth+1 > w.maxDepth() {
			w.skip(full, "too-deep", "")
			return nil
		}
		// 開く前に判定する: 自動マウントやネットワーク FS は開くだけで通信が起きる。
		if v, m := w.check(full); v != Allow {
			w.skip(full, v.Reason(), m.FSType)
			return nil
		}
		sub, err := r.OpenRoot(name)
		if err != nil {
			w.skipErr(full, err)
			return nil
		}
		defer sub.Close()
		sfi, err := sub.Stat(".")
		if err != nil {
			w.skipErr(full, err)
			return nil
		}
		if !os.SameFile(fi, sfi) {
			w.skip(full, "changed", "replaced-during-scan")
			return nil
		}
		if reason, detail := w.deviceVerdict(full, fi); reason != "" {
			w.skip(full, reason, detail)
			return nil
		}
		return w.walkDir(ctx, sub, full, depth+1, visit)
	case fi.Mode().IsRegular():
		w.Stats.Files++
		e := &Entry{Path: full, Name: name, Size: fi.Size(), w: w, dir: r, info: fi}
		err := visit(e)
		e.dir = nil
		if w.Limiter != nil {
			w.Limiter.Yield()
		}
		if err != nil {
			return err
		}
		return ctx.Err()
	default:
		w.Stats.Special++ // FIFO、ソケット、デバイス等は開かない
	}
	return nil
}

// deviceVerdict は、開いたディレクトリのデバイス番号がマウント表の想定と合うかを確かめる。
// 合わない場合の理由コードと詳細を返す（問題なければ空）。
func (w *Walker) deviceVerdict(path string, fi fs.FileInfo) (reason, detail string) {
	if w.Mounts == nil {
		return "", ""
	}
	devOf := w.devOf
	if devOf == nil {
		devOf = platform.DeviceOf
	}
	major, minor, ok := devOf(fi)
	if !ok {
		return "", ""
	}
	_, covering := w.Mounts.Check(path)
	if covering.Major == major && covering.Minor == minor {
		return "", ""
	}
	if v, m, found := w.Mounts.ByDevice(major, minor); found {
		if v == Allow {
			return "", ""
		}
		return v.Reason(), m.FSType
	}
	if subvolumeFS[covering.FSType] {
		return "", ""
	}
	return SkipUnknownFS.Reason(), "device-mismatch"
}

func (w *Walker) skipErr(path string, err error) {
	switch {
	case errors.Is(err, fs.ErrPermission):
		w.skip(path, "permission-denied", "")
	case errors.Is(err, fs.ErrNotExist):
		w.skip(path, "changed", "removed-during-scan")
	default:
		w.skip(path, "read-error", errnoText(err))
	}
}

// errnoText はエラーからパス等を除いた原因だけを取り出す。
func errnoText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return "error"
}

// ReadAll はファイル全体を読む。上限超過・権限不足・差し替え検出時はスキップを記録して ErrSkipped を返す。
func (e *Entry) ReadAll() ([]byte, error) {
	return e.read(e.w.maxFileSize())
}

// ReadLimited は ReadAll と同じだが、上限をさらに小さくできる（コレクタが扱う形式に応じた上限）。
func (e *Entry) ReadLimited(limit int64) ([]byte, error) {
	if max := e.w.maxFileSize(); limit <= 0 || limit > max {
		limit = max
	}
	return e.read(limit)
}

func (e *Entry) read(limit int64) ([]byte, error) {
	w := e.w
	if e.dir == nil {
		return nil, errors.New("entry used outside of visit callback")
	}
	if e.Size > limit {
		w.skip(e.Path, "too-large", "")
		return nil, ErrSkipped
	}
	f, err := openQuietly(func(flag int) (*os.File, error) { return e.dir.OpenFile(e.Name, flag, 0) }, os.O_RDONLY|platform.ReadOpenFlags, &w.Stats.AtimeNotPreserved)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			w.skip(e.Path, "permission-denied", "")
		} else {
			w.skip(e.Path, "changed", "could-not-open")
		}
		return nil, ErrSkipped
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || !os.SameFile(e.info, fi) {
		w.skip(e.Path, "changed", "replaced-during-scan")
		return nil, ErrSkipped
	}
	var out []byte
	buf := make([]byte, readChunk)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			if int64(len(out)+n) > limit {
				w.skip(e.Path, "too-large", "grew-during-scan")
				return nil, ErrSkipped
			}
			out = append(out, buf[:n]...)
			w.Stats.BytesRead += int64(n)
			if w.Limiter != nil {
				w.Limiter.Bytes(int64(n))
			}
		}
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			w.skip(e.Path, "read-error", errnoText(err))
			return nil, ErrSkipped
		}
	}
}
