package safefs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"kagiya/internal/platform"
	"kagiya/internal/throttle"
)

// Opener は、決まった場所にあるファイル（パッケージ管理データベースなど）を安全に開く。
// 走査（Walker）と同じ規則に従う: 触れる前にマウント表で判定し、シンボリックリンクを辿らず、通常ファイルだけを開く。
type Opener struct {
	Mounts MountChecker // nil なら判定しない
	// AllowPseudo は、擬似ファイルシステム（/proc など）のうち直接読んでよい場所。
	// 擬似ファイルシステムは探索しないが、OS の設定を得るための決まったファイルだけは読む。
	AllowPseudo []string
	Limiter     *throttle.Limiter
	OnSkip      func(Skip)
	BytesRead   int64
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
		if v, m := o.check(prefix); v != Allow {
			return nil, o.skip(path, v.Reason(), m.FSType)
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
		if v, m := o.check(next); v != Allow {
			return "", o.skip(path, v.Reason(), m.FSType)
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

// check は、パスに触れてよいかを判定する。
func (o *Opener) check(path string) (Verdict, Mount) {
	if o.Mounts == nil {
		return Allow, Mount{}
	}
	v, m := o.Mounts.Check(path)
	if v == SkipPseudoFS {
		for _, a := range o.AllowPseudo {
			// 許可された場所そのもの・その配下・そこへ至る途中のディレクトリ
			if path == a || strings.HasPrefix(path, a+"/") || strings.HasPrefix(a, path+"/") {
				return Allow, m
			}
		}
	}
	return v, m
}

const maxDirEntries = 10_000

// ReadDir は、ディレクトリ直下の通常ファイルの名前を整列して返す（リンクやサブディレクトリは含めない）。
// path はリンクを含まない実際のパスであること（必要なら先に Resolve する）。
func (o *Opener) ReadDir(path string) ([]string, error) {
	if !isCleanAbs(path) {
		return nil, fmt.Errorf("%q: %w", path, errNotPlain)
	}
	prefix := ""
	for _, seg := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if seg == "" {
			continue
		}
		prefix += "/" + seg
		if v, m := o.check(prefix); v != Allow {
			return nil, o.skip(path, v.Reason(), m.FSType)
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
		if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
			return nil, fmt.Errorf("%q: %w", path, errNotPlain)
		}
	}
	d, err := os.Open(path)
	if errors.Is(err, fs.ErrPermission) {
		return nil, o.skip(path, "permission-denied", "")
	}
	if err != nil {
		return nil, err
	}
	defer d.Close()
	ents, err := d.ReadDir(maxDirEntries)
	if err != nil && len(ents) == 0 && !errors.Is(err, io.EOF) {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		if e.Type().IsRegular() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// DirEntry はディレクトリ内の1項目。
type DirEntry struct {
	Name   string
	IsDir  bool
	IsLink bool
}

// ListNames は、ディレクトリ直下の項目（ファイル、リンク、サブディレクトリ）を名前順に返す。
// path はリンクを含まない実際のパスであること。
func (o *Opener) ListNames(path string) ([]DirEntry, error) {
	if !isCleanAbs(path) {
		return nil, fmt.Errorf("%q: %w", path, errNotPlain)
	}
	prefix := ""
	for _, seg := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if seg == "" {
			continue
		}
		prefix += "/" + seg
		if v, m := o.check(prefix); v != Allow {
			return nil, o.skip(path, v.Reason(), m.FSType)
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
		if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
			return nil, fmt.Errorf("%q: %w", path, errNotPlain)
		}
	}
	d, err := os.Open(path)
	if errors.Is(err, fs.ErrPermission) {
		return nil, o.skip(path, "permission-denied", "")
	}
	if err != nil {
		return nil, err
	}
	defer d.Close()
	ents, err := d.ReadDir(maxDirEntries)
	if err != nil && len(ents) == 0 && !errors.Is(err, io.EOF) {
		return nil, err
	}
	out := make([]DirEntry, 0, len(ents))
	for _, e := range ents {
		out = append(out, DirEntry{Name: e.Name(), IsDir: e.IsDir(), IsLink: e.Type()&fs.ModeSymlink != 0})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Glob は、最後の要素にだけワイルドカードを含むパターンに合うファイル（リンクを含む。ディレクトリは除く）を返す。
// ディレクトリ部分のリンクは安全に辿る。ディレクトリが存在しなければ空を返す。
func (o *Opener) Glob(pattern string) ([]string, error) {
	i := strings.LastIndexByte(pattern, '/')
	if i <= 0 || strings.ContainsAny(pattern[:i], "*?[") {
		return nil, fmt.Errorf("%q: unsupported pattern", pattern)
	}
	dir, base := pattern[:i], pattern[i+1:]
	real, err := o.Resolve(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ents, err := o.ListNames(real)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if e.IsDir {
			continue
		}
		if ok, _ := filepath.Match(base, e.Name); ok {
			out = append(out, dir+"/"+e.Name)
		}
	}
	return out, nil
}

// LinkTarget は、path がシンボリックリンクならその行き先を返す（行き先には触れない）。
func (o *Opener) LinkTarget(path string) (string, bool) {
	i := strings.LastIndexByte(path, '/')
	if i <= 0 {
		return "", false
	}
	dir, err := o.Resolve(path[:i])
	if err != nil {
		return "", false
	}
	p := dir + "/" + path[i+1:]
	if v, _ := o.check(p); v != Allow {
		return "", false
	}
	target, err := os.Readlink(p)
	if err != nil {
		return "", false
	}
	return target, true
}

// ReadFile は、リンクを安全に辿って実体を開き、limit バイトまで読む。大きさが 0 と報告される擬似ファイルも読める。
func (o *Opener) ReadFile(path string, limit int) ([]byte, error) {
	real, err := o.Resolve(path)
	if err != nil {
		return nil, err
	}
	f, err := o.Open(real)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 4096)
	for len(buf) <= limit {
		n, err := f.ReadAt(chunk, int64(len(buf)))
		buf = append(buf, chunk[:n]...)
		if err != nil || n == 0 {
			break
		}
	}
	if len(buf) > limit {
		return nil, fmt.Errorf("%q: file is too large", path)
	}
	return buf, nil
}
