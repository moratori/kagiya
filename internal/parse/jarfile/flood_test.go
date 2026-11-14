package jarfile

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"io"
	"strconv"
	"testing"
)

// 以下は、独立したレビュー（2026-11-14）の指摘 A-1 への対応。
// 標準ライブラリの zip の読み取りは、末尾の記録が申告する件数（16 ビット）を信用せず、中央ディレクトリを、壊れたヘッダに当たるまで
// 全件読んで確保する。件数の上限を「読み終えた後」に確かめるのでは遅いので、標準ライブラリに渡す前に、自分でヘッダを数える。

// counting は、読んだ総バイト数を数える。
type counting struct {
	r io.ReaderAt
	n int64
}

func (c *counting) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.r.ReadAt(p, off)
	c.n += int64(n)
	return n, err
}

// flood は、名前の長さ 0 の中央ディレクトリのヘッダ（46 バイト）を n 件並べ、末尾の記録を付けたものを作る。
// declared は、末尾の記録に書くディレクトリの大きさ（0 なら正直に 46 × n）。ディレクトリの開始位置は 0 と書く。
func flood(n int, declared uint32) []byte {
	h := make([]byte, 46)
	binary.LittleEndian.PutUint32(h, 0x02014b50)
	data := bytes.Repeat(h, n)
	if declared == 0 {
		declared = uint32(46 * n)
	}
	eocd := make([]byte, 22)
	binary.LittleEndian.PutUint32(eocd, 0x06054b50)
	binary.LittleEndian.PutUint16(eocd[8:], uint16(n))
	binary.LittleEndian.PutUint16(eocd[10:], uint16(n))
	binary.LittleEndian.PutUint32(eocd[12:], declared)
	binary.LittleEndian.PutUint32(eocd[16:], 0)
	return append(data, eocd...)
}

func TestDirectoryFloodIsRejectedEarly(t *testing.T) {
	lim := Limits{MaxArchiveSize: 64 << 20, MaxEntries: 1000, MaxNameLen: 256, MaxEntrySize: 4096, MaxRatio: 100}
	for name, data := range map[string][]byte{
		// 約 33 万件（約 15 MiB）。末尾の記録の件数は 16 ビットなので、申告は「5 件」になる（65536 × 5 + 5 件）。大きさの申告は正直
		"honest size": flood(65536*5+5, 0),
		// ディレクトリの大きさを小さく偽る（標準ライブラリは、申告された開始位置にヘッダがあれば、そこから読む）
		"small declared size": flood(65536*5+5, 46*5),
	} {
		c := &counting{r: bytes.NewReader(data)}
		a, err := Open(c, int64(len(data)), lim)
		if err == nil {
			t.Errorf("%s: must be rejected (entries = %d)", name, len(a.Entries))
		}
		// 上限（1,000 件 = 46 KB）を少し超えたところで読むのをやめる。ディレクトリ全体（約 15 MiB）を読んではいけない
		if c.n > 1<<20 {
			t.Errorf("%s: read %d bytes before rejecting; the directory must not be read to the end", name, c.n)
		}
	}
}

// 件数の多い、ふつうの JAR（zip64 の形になる）は、上限の内なら開ける。上限を超えるものは、全体を読む前に断る。
func TestManyEntries(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for i := 0; i < 70000; i++ {
		if _, err := w.CreateHeader(&zip.FileHeader{Name: "c/" + strconv.Itoa(i) + ".class", Method: zip.Store}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	a, err := Open(bytes.NewReader(data), int64(len(data)), Limits{MaxArchiveSize: 64 << 20, MaxEntries: 200000, MaxNameLen: 256})
	if err != nil || len(a.Entries) != 70000 {
		t.Fatalf("a large but valid archive must open: %v", err)
	}
	c := &counting{r: bytes.NewReader(data)}
	if _, err := Open(c, int64(len(data)), Limits{MaxArchiveSize: 64 << 20, MaxEntries: 1000, MaxNameLen: 256}); err == nil {
		t.Error("more entries than the limit must be rejected")
	}
	if c.n > 1<<20 {
		t.Errorf("read %d bytes before rejecting", c.n)
	}
}

// 先頭に別のデータ（起動スクリプトなど）が付いた JAR も、これまでどおり開ける。
func TestPrefixedArchive(t *testing.T) {
	data := append([]byte("#!/bin/bash\nexit 0\n"), build(t, item{"META-INF/MANIFEST.MF", []byte("Manifest-Version: 1.0\r\n"), zip.Deflate}, item{"a.txt", []byte("x"), zip.Store})...)
	a := open(t, data, small)
	if len(a.Entries) != 2 {
		t.Fatalf("entries = %+v", a.Entries)
	}
	if b, err := a.Read("META-INF/MANIFEST.MF"); err != nil || !bytes.HasPrefix(b, []byte("Manifest-Version")) {
		t.Errorf("read = %q %v", b, err)
	}
}

// 名前に制御文字や、UTF-8 として不正な並びを含むエントリは、一覧に入れない（結果の表示を偽る材料になるため。指摘 A-22）。
func TestControlCharactersInNames(t *testing.T) {
	data := build(t, item{"lib/a\nb.jar", []byte("x"), zip.Store}, item{"lib/\x1b[31mred.jar", []byte("x"), zip.Store},
		item{"lib/\xff\xfe.jar", []byte("x"), zip.Store}, item{"lib/del\x7f.jar", []byte("x"), zip.Store},
		item{"lib/rtl‮gpj.jar", []byte("x"), zip.Store}, item{"lib/日本語.jar", []byte("x"), zip.Store})
	a := open(t, data, small)
	if len(a.Entries) != 1 || a.Entries[0].Name != "lib/日本語.jar" {
		t.Errorf("entries = %+v", a.Entries)
	}
	if len(a.Problems) != 5 {
		t.Errorf("problems = %v", a.Problems)
	}
}

func FuzzOpen(f *testing.F) {
	f.Add(flood(3, 0))
	f.Add(flood(2000, 46))
	f.Add([]byte("PK\x05\x06" + "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	fw, _ := w.Create("a.txt")
	fw.Write([]byte("x"))
	w.Close()
	f.Add(buf.Bytes())
	f.Add(append([]byte("#!/bin/sh\n"), buf.Bytes()...))
	lim := Limits{MaxArchiveSize: 1 << 20, MaxEntries: 100, MaxNameLen: 64, MaxEntrySize: 1024, MaxRatio: 100}
	f.Fuzz(func(t *testing.T, data []byte) {
		a, err := Open(bytes.NewReader(data), int64(len(data)), lim)
		if err != nil {
			return
		}
		if len(a.Entries) > lim.MaxEntries {
			t.Fatalf("entries = %d", len(a.Entries))
		}
		for _, e := range a.Entries {
			a.Read(e.Name)
		}
	})
}
