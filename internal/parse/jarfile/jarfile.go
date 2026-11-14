// Package jarfile は、JAR（zip）の中身の一覧と、名前を指定したエントリを、上限つきで読む。
//
// 書き込まない（ディスクに展開せず、必要なエントリだけをメモリ上で読む）。入れ子の JAR は、名前として見えるだけで開かない。
// 壊れた zip や、展開すると巨大になる zip（zip 爆弾）でも止まらないよう、次の順に確かめる。
//
//  1. 全体の大きさ（上限を超える JAR は開かない）
//  2. 末尾の記録にある、エントリの数と中央ディレクトリの大きさ（上限を超えるものは、ディレクトリを読む前に断る）
//  3. エントリごとの名前（長すぎる、上の階層を指す、絶対パス、重複 → 一覧から外して問題として記録する）
//  4. 読むエントリの、申告された大きさと圧縮の倍率
//  5. 実際に展開して出てきた量（申告が偽りでも、上限を超えたところで止める）
//
// どのエントリを読むかは、呼び出す側が決まった名前だけを指定する（このパッケージは、中身を選ばない）。
package jarfile

import (
	"archive/zip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Limits は、読むものの上限。
type Limits struct {
	MaxArchiveSize int64 // JAR 全体の大きさ
	MaxEntries     int   // エントリの数
	MaxNameLen     int   // エントリの名前の長さ
	MaxEntrySize   int64 // 読むエントリの、展開後の大きさ
	MaxRatio       int64 // 読むエントリの、圧縮の倍率（展開後 ÷ 圧縮後）。0 なら確かめない
}

// Entry は、JAR の中のエントリ 1 つ。
type Entry struct {
	Name string
	Size uint64 // 展開後の大きさ（申告）
	Dir  bool

	file *zip.File
}

// Archive は、開いた JAR。
type Archive struct {
	Entries []Entry
	// 一覧から外したエントリなど、読めなかったものの説明
	Problems []string

	lim    Limits
	byName map[string]int
	dup    map[string]bool
}

const (
	eocdSignature = 0x06054b50
	eocdMinSize   = 22
	maxComment    = 65535
	dirEntrySize  = 46 // 中央ディレクトリの 1 件の、名前を除いた最小の大きさ
	maxProblems   = 32
)

// Open は、JAR の中身の一覧を読む。r は、size バイトの JAR 全体。
func Open(r io.ReaderAt, size int64, lim Limits) (*Archive, error) {
	if size < eocdMinSize {
		return nil, errors.New("not a zip file")
	}
	if size > lim.MaxArchiveSize {
		return nil, fmt.Errorf("the archive is larger than the limit (%d bytes)", lim.MaxArchiveSize)
	}
	if err := checkDirectory(r, size, lim); err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, err
	}
	if len(zr.File) > lim.MaxEntries {
		return nil, fmt.Errorf("the archive has more entries than the limit (%d)", lim.MaxEntries)
	}
	a := &Archive{lim: lim, byName: map[string]int{}, dup: map[string]bool{}}
	seen := map[string]bool{}
	for _, f := range zr.File {
		if seen[f.Name] {
			a.dup[f.Name] = true
		}
		seen[f.Name] = true
	}
	for _, f := range zr.File {
		if reason := badName(f.Name, lim.MaxNameLen); reason != "" {
			a.problem("an entry is skipped: " + reason)
			continue
		}
		if a.dup[f.Name] {
			if _, done := a.byName[f.Name]; !done {
				a.byName[f.Name] = -1
				a.problem("an entry name appears more than once and is skipped")
			}
			continue
		}
		a.byName[f.Name] = len(a.Entries)
		a.Entries = append(a.Entries, Entry{Name: f.Name, Size: f.UncompressedSize64, Dir: strings.HasSuffix(f.Name, "/"), file: f})
	}
	return a, nil
}

func (a *Archive) problem(s string) {
	if len(a.Problems) < maxProblems {
		a.Problems = append(a.Problems, s)
	}
}

// checkDirectory は、末尾の記録（End of central directory）を自分で読み、エントリの数と中央ディレクトリの大きさが上限と
// ファイルの大きさに収まることを、ディレクトリを読む前に確かめる。
func checkDirectory(r io.ReaderAt, size int64, lim Limits) error {
	n := int64(eocdMinSize + maxComment)
	if n > size {
		n = size
	}
	buf := make([]byte, n)
	if _, err := r.ReadAt(buf, size-n); err != nil && err != io.EOF {
		return err
	}
	for i := len(buf) - eocdMinSize; i >= 0; i-- {
		if binary.LittleEndian.Uint32(buf[i:]) != eocdSignature {
			continue
		}
		count := int64(binary.LittleEndian.Uint16(buf[i+10:]))
		dirSize := int64(binary.LittleEndian.Uint32(buf[i+12:]))
		// 0xFFFF / 0xFFFFFFFF は zip64（本当の値は別の記録にある）。その場合は、標準ライブラリが読んだ後の件数で確かめる
		if count != 0xffff && count > int64(lim.MaxEntries) {
			return fmt.Errorf("the archive declares more entries than the limit (%d)", lim.MaxEntries)
		}
		if dirSize != 0xffffffff && (dirSize > size || (count != 0xffff && count*dirEntrySize > dirSize)) {
			return errors.New("the central directory of the archive is inconsistent")
		}
		return nil
	}
	return errors.New("not a zip file")
}

// badName は、読まない名前なら、その理由を返す。
func badName(name string, max int) string {
	switch {
	case name == "" || len(name) > max:
		return "the name is empty or too long"
	case strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || strings.ContainsRune(name, 0):
		return "the name is an absolute path or has an unexpected character"
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return "the name points outside the archive"
		}
	}
	return ""
}

// Read は、名前を指定したエントリの中身を返す。上限を超えるもの、倍率が高すぎるもの、壊れているものは読まない。
func (a *Archive) Read(name string) ([]byte, error) {
	i, ok := a.byName[name]
	if !ok || i < 0 {
		return nil, errors.New("no such entry")
	}
	e := a.Entries[i]
	if e.Dir {
		return nil, errors.New("the entry is a directory")
	}
	f := e.file
	if f.UncompressedSize64 > uint64(a.lim.MaxEntrySize) {
		return nil, fmt.Errorf("the entry is larger than the limit (%d bytes)", a.lim.MaxEntrySize)
	}
	if a.lim.MaxRatio > 0 && f.UncompressedSize64 > uint64(a.lim.MaxRatio)*(f.CompressedSize64+1) {
		return nil, errors.New("the compression ratio of the entry is too high")
	}
	if f.Method != zip.Store && f.Method != zip.Deflate {
		return nil, errors.New("the entry uses an unsupported compression method")
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	// 申告された大きさを信用せず、上限 + 1 バイトまでしか読まない
	data, err := io.ReadAll(io.LimitReader(rc, a.lim.MaxEntrySize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > a.lim.MaxEntrySize || uint64(len(data)) != f.UncompressedSize64 {
		return nil, errors.New("the entry does not have the size it declares")
	}
	return data, nil
}
