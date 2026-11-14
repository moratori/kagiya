package jarfile

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

type item struct {
	name   string
	data   []byte
	method uint16
}

func build(t *testing.T, items ...item) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, it := range items {
		f, err := w.CreateHeader(&zip.FileHeader{Name: it.name, Method: it.method})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(it.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func open(t *testing.T, data []byte, lim Limits) *Archive {
	t.Helper()
	a, err := Open(bytes.NewReader(data), int64(len(data)), lim)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

var small = Limits{MaxArchiveSize: 1 << 20, MaxEntries: 100, MaxNameLen: 256, MaxEntrySize: 4096, MaxRatio: 100}

// 中身の一覧（名前と大きさ）を読める。入れ子の JAR は、名前として見えるだけで、開かない。
func TestList(t *testing.T) {
	data := build(t,
		item{"META-INF/MANIFEST.MF", []byte("Manifest-Version: 1.0\r\nSpring-Boot-Version: 3.5.16\r\n"), zip.Deflate},
		item{"BOOT-INF/classes/application.properties", []byte("server.port=8443\n"), zip.Deflate},
		item{"BOOT-INF/lib/tomcat-embed-core-10.1.55.jar", build(t, item{"inner.txt", []byte("x"), zip.Store}), zip.Store},
		item{"BOOT-INF/classes/", nil, zip.Store},
	)
	a := open(t, data, small)
	if len(a.Problems) != 0 {
		t.Errorf("problems = %v", a.Problems)
	}
	names := []string{}
	for _, e := range a.Entries {
		names = append(names, e.Name)
	}
	if strings.Join(names, "|") != "META-INF/MANIFEST.MF|BOOT-INF/classes/application.properties|BOOT-INF/lib/tomcat-embed-core-10.1.55.jar|BOOT-INF/classes/" {
		t.Errorf("names = %v", names)
	}
	if e := a.Entries[1]; e.Size != 17 || e.Dir {
		t.Errorf("entry = %+v", e)
	}
	if !a.Entries[3].Dir {
		t.Error("a name ending with / is a directory")
	}
	got, err := a.Read("BOOT-INF/classes/application.properties")
	if err != nil || string(got) != "server.port=8443\n" {
		t.Errorf("read = %q, %v", got, err)
	}
	if _, err := a.Read("no/such/entry"); err == nil {
		t.Error("a missing entry must be an error")
	}
	if _, err := a.Read("BOOT-INF/classes/"); err == nil {
		t.Error("a directory cannot be read")
	}
}

// 上限: 全体の大きさ、エントリの数、名前の長さ。超えたものは開かない。
func TestLimits(t *testing.T) {
	data := build(t, item{"a.txt", []byte("a"), zip.Store}, item{"b.txt", []byte("b"), zip.Store}, item{"c.txt", []byte("c"), zip.Store})
	lim := small
	lim.MaxEntries = 2
	if _, err := Open(bytes.NewReader(data), int64(len(data)), lim); err == nil {
		t.Error("too many entries must be refused")
	}
	lim = small
	lim.MaxArchiveSize = int64(len(data)) - 1
	if _, err := Open(bytes.NewReader(data), int64(len(data)), lim); err == nil {
		t.Error("an oversized archive must be refused")
	}
	long := build(t, item{strings.Repeat("n", 300) + ".txt", []byte("x"), zip.Store}, item{"ok.txt", []byte("x"), zip.Store})
	a := open(t, long, small)
	if len(a.Entries) != 1 || a.Entries[0].Name != "ok.txt" || len(a.Problems) == 0 {
		t.Errorf("an entry with an overlong name must be dropped and reported: %d entries, %v", len(a.Entries), a.Problems)
	}
}

// 展開すると大きくなるもの（zip 爆弾）は読まない。申告された大きさ、圧縮の倍率、実際に出てきた量のどれでも止める。
func TestBomb(t *testing.T) {
	zeros := make([]byte, 256<<10) // 256 KiB のゼロ。圧縮すると数百バイトになる
	data := build(t, item{"BOOT-INF/classes/application.yml", zeros, zip.Deflate}, item{"small.txt", bytes.Repeat([]byte("ab"), 600), zip.Deflate})
	a := open(t, data, small)
	if _, err := a.Read("BOOT-INF/classes/application.yml"); err == nil {
		t.Error("an entry larger than the limit must not be read")
	}
	// 大きさは上限以内でも、圧縮の倍率が高すぎるものは読まない
	lim := small
	lim.MaxEntrySize = 1 << 20
	lim.MaxRatio = 10
	a = open(t, data, lim)
	if _, err := a.Read("BOOT-INF/classes/application.yml"); err == nil {
		t.Error("an entry with too high a compression ratio must not be read")
	}
	// 申告の大きさを小さく偽ったもの: 実際に出てきた量で止める
	forged := append([]byte{}, data...)
	patchSize(t, forged, "BOOT-INF/classes/application.yml", 100)
	lim = small
	lim.MaxRatio = 0 // 倍率では止めない
	if a, err := Open(bytes.NewReader(forged), int64(len(forged)), lim); err == nil {
		if got, err := a.Read("BOOT-INF/classes/application.yml"); err == nil {
			t.Errorf("a forged size must not let %d bytes through", len(got))
		}
	}
}

// patchSize は、中央ディレクトリとローカルヘッダの「展開後の大きさ」を書き換える（申告を偽った zip を作る）。
func patchSize(t *testing.T, data []byte, name string, size uint32) {
	t.Helper()
	n := 0
	for i := 0; i+46 < len(data); i++ {
		switch {
		case bytes.Equal(data[i:i+4], []byte("PK\x01\x02")) && int(binary.LittleEndian.Uint16(data[i+28:])) == len(name) && string(data[i+46:i+46+len(name)]) == name:
			binary.LittleEndian.PutUint32(data[i+24:], size)
			n++
		case bytes.Equal(data[i:i+4], []byte("PK\x03\x04")) && int(binary.LittleEndian.Uint16(data[i+26:])) == len(name) && i+30+len(name) <= len(data) && string(data[i+30:i+30+len(name)]) == name:
			binary.LittleEndian.PutUint32(data[i+22:], size)
			n++
		}
	}
	if n == 0 {
		t.Fatal("entry not found")
	}
}

// おかしな名前（上の階層を指す、絶対パス、重複）は、問題として記録し、読まない。
func TestNames(t *testing.T) {
	data := build(t,
		item{"../etc/passwd", []byte("x"), zip.Store}, item{"/abs.txt", []byte("x"), zip.Store}, item{"a/../../b.txt", []byte("x"), zip.Store},
		item{"dup.txt", []byte("1"), zip.Store}, item{"dup.txt", []byte("2"), zip.Store}, item{"back\\slash.txt", []byte("x"), zip.Store},
		item{"ok.txt", []byte("x"), zip.Store})
	a := open(t, data, small)
	if len(a.Entries) != 1 || a.Entries[0].Name != "ok.txt" {
		t.Errorf("entries = %+v", a.Entries)
	}
	if len(a.Problems) < 4 {
		t.Errorf("problems = %v", a.Problems)
	}
	if _, err := a.Read("dup.txt"); err == nil {
		t.Error("a duplicated name must not be read (which one is used is ambiguous)")
	}
}

// 壊れた zip や zip でないものは、エラーになるだけで止まらない。
func TestBroken(t *testing.T) {
	good := build(t, item{"a.txt", []byte("hello"), zip.Deflate})
	for name, data := range map[string][]byte{
		"empty":       {},
		"not a zip":   []byte("this is not a zip file at all, just text"),
		"truncated":   good[:len(good)-10],
		"only header": good[:20],
	} {
		if _, err := Open(bytes.NewReader(data), int64(len(data)), small); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	// 中央ディレクトリの件数を偽ったもの（実際より多い）
	forged := append([]byte{}, good...)
	i := bytes.LastIndex(forged, []byte("PK\x05\x06"))
	binary.LittleEndian.PutUint16(forged[i+8:], 60000)
	binary.LittleEndian.PutUint16(forged[i+10:], 60000)
	if _, err := Open(bytes.NewReader(forged), int64(len(forged)), small); err == nil {
		t.Error("a forged entry count over the limit must be refused before reading the directory")
	}
	// データが壊れているエントリ（CRC が合わない）は読めない
	bad := append([]byte{}, good...)
	j := bytes.Index(bad, []byte("a.txt")) + len("a.txt")
	bad[j] ^= 0xff
	if a, err := Open(bytes.NewReader(bad), int64(len(bad)), small); err == nil {
		if _, err := a.Read("a.txt"); err == nil {
			t.Error("corrupted data must not be returned")
		}
	}
}
