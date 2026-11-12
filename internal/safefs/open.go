package safefs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"kagiya/internal/platform"
	"kagiya/internal/throttle"
)

// Opener は、決まった場所にあるファイル（パッケージ管理データベースなど）を安全に開く。
// 走査（Walker）と同じ規則に従う: 触れる前にマウント表で判定し、シンボリックリンクを辿らず、通常ファイルだけを開く。
type Opener struct {
	Mounts    MountChecker // nil なら判定しない
	Limiter   *throttle.Limiter
	OnSkip    func(Skip)
	BytesRead int64
}

// File は読み取り専用で開いたファイル。必要な部分だけを読めるよう、位置を指定して読む。
type File struct {
	f    *os.File
	size int64
	o    *Opener
}

var errNotPlain = errors.New("not a plain file reachable without symbolic links")

func (o *Opener) skip(path, reason, detail string) error {
	if o.OnSkip != nil {
		o.OnSkip(Skip{Path: path, Reason: reason, Detail: detail})
	}
	return ErrSkipped
}

// Open は path を開く。
//   - 存在しない場合は fs.ErrNotExist（記録しない。候補のパスを順に試す用途のため）
//   - 読んではならない場所・権限不足の場合は、スキップを記録して ErrSkipped
//   - 途中にシンボリックリンクがある、通常ファイルでない場合はエラー（記録しない）
func (o *Opener) Open(path string) (*File, error) {
	if !isCleanAbs(path) || path == "/" {
		return nil, fmt.Errorf("%q: %w", path, errNotPlain)
	}
	segs := strings.Split(path[1:], "/")
	prefix := ""
	var last fs.FileInfo
	for i, seg := range segs {
		prefix += "/" + seg
		// 触れる前に判定する
		if o.Mounts != nil {
			if v, m := o.Mounts.Check(prefix); v != Allow {
				return nil, o.skip(path, v.Reason(), m.FSType)
			}
		}
		fi, err := os.Lstat(prefix)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil, fs.ErrNotExist
		case errors.Is(err, fs.ErrPermission):
			return nil, o.skip(path, "permission-denied", "")
		case err != nil:
			return nil, err
		}
		isLast := i == len(segs)-1
		if fi.Mode()&fs.ModeSymlink != 0 || (!isLast && !fi.IsDir()) || (isLast && !fi.Mode().IsRegular()) {
			return nil, fmt.Errorf("%q: %w", path, errNotPlain)
		}
		last = fi
	}
	f, err := os.OpenFile(path, os.O_RDONLY|platform.ReadOpenFlags, 0)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, fs.ErrNotExist
	case errors.Is(err, fs.ErrPermission):
		return nil, o.skip(path, "permission-denied", "")
	case err != nil:
		return nil, fmt.Errorf("%q: %w", path, errNotPlain)
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || !os.SameFile(last, fi) {
		f.Close()
		return nil, o.skip(path, "changed", "replaced-during-scan")
	}
	return &File{f: f, size: fi.Size(), o: o}, nil
}

// Size は開いた時点の大きさ。
func (f *File) Size() int64 { return f.size }

// ReadAt は位置を指定して読む（io.ReaderAt）。読んだ量は流量制限に申告する。
func (f *File) ReadAt(p []byte, off int64) (int, error) {
	n, err := f.f.ReadAt(p, off)
	if n > 0 {
		f.o.BytesRead += int64(n)
		if f.o.Limiter != nil {
			f.o.Limiter.Bytes(int64(n))
		}
	}
	return n, err
}

func (f *File) Close() error { return f.f.Close() }

const maxLinkHops = 40

// Resolve は、シンボリックリンクを含み得るパスを、リンクのない実際のパスに直す。
// OS に一括で解決させず、1要素ずつ進める。各要素は触れる前にマウント表で判定するので、
// リンクの行き先が読んではならない場所であれば、そこには触れずにスキップを記録して ErrSkipped を返す。
func (o *Opener) Resolve(path string) (string, error) {
	if !isCleanAbs(path) {
		return "", fmt.Errorf("%q: %w", path, errNotPlain)
	}
	rest := strings.Split(strings.TrimPrefix(path, "/"), "/")
	cur := "" // 解決済みの部分（ルートは空文字列で表す）
	hops := 0
	for len(rest) > 0 {
		seg := rest[0]
		rest = rest[1:]
		switch seg {
		case "", ".":
			continue
		case "..":
			if i := strings.LastIndexByte(cur, '/'); i >= 0 {
				cur = cur[:i]
			}
			continue
		}
		next := cur + "/" + seg
		if o.Mounts != nil {
			if v, m := o.Mounts.Check(next); v != Allow {
				return "", o.skip(path, v.Reason(), m.FSType)
			}
		}
		fi, err := os.Lstat(next)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return "", fs.ErrNotExist
		case errors.Is(err, fs.ErrPermission):
			return "", o.skip(path, "permission-denied", "")
		case err != nil:
			return "", err
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			cur = next
			continue
		}
		if hops++; hops > maxLinkHops {
			return "", fmt.Errorf("%q: too many symbolic links", path)
		}
		target, err := os.Readlink(next)
		if err != nil || target == "" || len(target) > 4096 {
			return "", fmt.Errorf("%q: %w", path, errNotPlain)
		}
		if strings.HasPrefix(target, "/") {
			cur = "" // 絶対パスのリンク: ルートからやり直す
		}
		rest = append(strings.Split(target, "/"), rest...)
		if len(rest) > 4096 {
			return "", fmt.Errorf("%q: %w", path, errNotPlain)
		}
	}
	if cur == "" {
		return "/", nil
	}
	return cur, nil
}
