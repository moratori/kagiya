// Package jarfile は、JAR（zip）の中身の一覧と、名前を指定したエントリを、上限つきで読む。
//
// 書き込まない（ディスクに展開せず、必要なエントリだけをメモリ上で読む）。入れ子の JAR は、名前として見えるだけで開かない。
// 壊れた zip や、展開すると巨大になる zip（zip 爆弾）でも止まらないよう、次の順に確かめる。
//
//  1. 全体の大きさ（上限を超える JAR は開かない）
//  2. 中央ディレクトリのヘッダの数（自分で数え、上限を超えたところで断る。標準ライブラリは、末尾の記録が申告する件数を信用せず、
//     ディレクトリを壊れたヘッダに当たるまで全件読んで確保するので、渡す前に数える）
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
	"unicode/utf8"
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
	span, err := checkDirectory(r, size, lim)
	if err != nil {
		return nil, err
	}
	// 念のため、標準ライブラリが一覧を読む間の読み取り量にも上限を付ける（数えた範囲の 2 倍と、末尾の記録を探す分）
	guard := &budgetReader{r: r, left: 2*span + 4*(eocdMinSize+maxComment) + 1<<20}
	zr, err := zip.NewReader(guard, size)
	if err != nil {
		return nil, err
	}
	guard.unlimited = true // エントリの中身を読むときの上限は、Read が別に確かめる
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

// budgetReader は、読み取りの総量に上限を付ける。
type budgetReader struct {
	r         io.ReaderAt
	left      int64
	unlimited bool
}

func (b *budgetReader) ReadAt(p []byte, off int64) (int, error) {
	if !b.unlimited {
		if b.left -= int64(len(p)); b.left < 0 {
			return 0, errors.New("the directory of the archive is larger than expected")
		}
	}
	return b.r.ReadAt(p, off)
}

const (
	dirHeaderSignature  = 0x02014b50
	zip64LocatorSig     = 0x07064b50
	zip64EndSig         = 0x06064b50
	zip64LocatorSize    = 20
	zip64EndSize        = 56
	directoryReadWindow = 64 << 10
)

// checkDirectory は、末尾の記録（End of central directory）を自分で読み、中央ディレクトリのヘッダを自分で数えて、
// エントリの数が上限に収まることを確かめる。数えるのは、標準ライブラリが読み始めうる位置（申告された開始位置と、
// 「ディレクトリの終わり − 申告された大きさ」）の両方から。返すのは、数えた範囲の大きさ（バイト）。
func checkDirectory(r io.ReaderAt, size int64, lim Limits) (span int64, err error) {
	n := int64(eocdMinSize + maxComment)
	if n > size {
		n = size
	}
	buf := make([]byte, n)
	if _, err := r.ReadAt(buf, size-n); err != nil && err != io.EOF {
		return 0, err
	}
	for i := len(buf) - eocdMinSize; i >= 0; i-- {
		if binary.LittleEndian.Uint32(buf[i:]) != eocdSignature {
			continue
		}
		end := size - n + int64(i) // ディレクトリの終わり（末尾の記録の位置）
		count := uint64(binary.LittleEndian.Uint16(buf[i+10:]))
		dirSize := uint64(binary.LittleEndian.Uint32(buf[i+12:]))
		dirOffset := uint64(binary.LittleEndian.Uint32(buf[i+16:]))
		if count == 0xffff || dirSize == 0xffffffff || dirOffset == 0xffffffff {
			// zip64: 本当の値は、手前の別の記録にある
			var z [zip64LocatorSize + zip64EndSize]byte
			loc := end - zip64LocatorSize
			if loc < 0 {
				return 0, errors.New("the central directory of the archive is inconsistent")
			}
			if _, err := r.ReadAt(z[:zip64LocatorSize], loc); err != nil || binary.LittleEndian.Uint32(z[:]) != zip64LocatorSig {
				return 0, errors.New("the central directory of the archive is inconsistent")
			}
			at := binary.LittleEndian.Uint64(z[8:])
			if size < zip64EndSize || at > uint64(size-zip64EndSize) {
				return 0, errors.New("the central directory of the archive is inconsistent")
			}
			rec := z[zip64LocatorSize:]
			if _, err := r.ReadAt(rec, int64(at)); err != nil || binary.LittleEndian.Uint32(rec) != zip64EndSig {
				return 0, errors.New("the central directory of the archive is inconsistent")
			}
			count = binary.LittleEndian.Uint64(rec[32:])
			dirSize = binary.LittleEndian.Uint64(rec[40:])
			dirOffset = binary.LittleEndian.Uint64(rec[48:])
			end = int64(at)
		}
		if count > uint64(lim.MaxEntries) {
			return 0, fmt.Errorf("the archive declares more entries than the limit (%d)", lim.MaxEntries)
		}
		if dirSize > uint64(end) || dirOffset > uint64(size) {
			return 0, errors.New("the central directory of the archive is inconsistent")
		}
		starts := []int64{end - int64(dirSize)}
		if int64(dirOffset) != starts[0] {
			starts = append(starts, int64(dirOffset))
		}
		for _, start := range starts {
			n, err := countHeaders(r, start, size, lim.MaxEntries)
			if err != nil {
				return 0, err
			}
			if n > span {
				span = n
			}
		}
		return span, nil
	}
	return 0, errors.New("not a zip file")
}

// countHeaders は、start から並ぶ中央ディレクトリのヘッダを、ヘッダでないものに当たるまで数える。
// max を超えたところでエラーにする（残りは読まない）。返すのは、読み進めた範囲の大きさ。
func countHeaders(r io.ReaderAt, start, size int64, max int) (span int64, err error) {
	window := make([]byte, directoryReadWindow)
	var have []byte // window のうち、まだ使っていない部分
	pos := start    // have の先頭の、ファイルの中の位置
	count := 0
	for {
		if len(have) < dirEntrySize {
			if pos >= size {
				break
			}
			n, err := r.ReadAt(window, pos)
			if n < dirEntrySize {
				if err != nil && err != io.EOF {
					return 0, err
				}
				break
			}
			have = window[:n]
		}
		if binary.LittleEndian.Uint32(have) != dirHeaderSignature {
			break
		}
		if count++; count > max {
			return 0, fmt.Errorf("the archive has more entries than the limit (%d)", max)
		}
		// 名前・追加の欄・コメントの長さ
		skip := dirEntrySize + int(binary.LittleEndian.Uint16(have[28:])) + int(binary.LittleEndian.Uint16(have[30:])) + int(binary.LittleEndian.Uint16(have[32:]))
		pos += int64(skip)
		if skip <= len(have) {
			have = have[skip:]
		} else {
			have = nil // 窓の外まで飛ぶ。次の位置から読み直す
		}
	}
	return pos - start, nil
}

// badName は、読まない名前なら、その理由を返す。
func badName(name string, max int) string {
	switch {
	case name == "" || len(name) > max:
		return "the name is empty or too long"
	case strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || strings.ContainsRune(name, 0):
		return "the name is an absolute path or has an unexpected character"
	case !utf8.ValidString(name):
		return "the name is not valid UTF-8"
	}
	for _, r := range name {
		// 制御文字、書字方向を変える文字、幅のない文字（結果の表示を偽る材料になる）
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) || (r >= 0x200b && r <= 0x200f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0xfeff {
			return "the name has a control character"
		}
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
