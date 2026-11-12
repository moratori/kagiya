package elfdyn

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// build はテスト用の最小の ELF（プログラムヘッダ2つ、動的セクション、文字列表）を組み立てる。
// 実物のバイナリはリポジトリに置かないため、形式に従って自作する（実物との照合は検証ラボで行う）。
func build(class64 bool, bo binary.ByteOrder, needed []string, soname, rpath, runpath string) []byte {
	const vbase = 0x400000
	strtab := []byte{0}
	add := func(s string) uint64 {
		off := uint64(len(strtab))
		strtab = append(strtab, s...)
		strtab = append(strtab, 0)
		return off
	}
	type dyn struct{ tag, val uint64 }
	var dyns []dyn
	for _, n := range needed {
		dyns = append(dyns, dyn{1, add(n)})
	}
	if soname != "" {
		dyns = append(dyns, dyn{14, add(soname)})
	}
	if rpath != "" {
		dyns = append(dyns, dyn{15, add(rpath)})
	}
	if runpath != "" {
		dyns = append(dyns, dyn{29, add(runpath)})
	}
	ehsize, phsize, dynsize := 52, 32, 8
	if class64 {
		ehsize, phsize, dynsize = 64, 56, 16
	}
	phoff := ehsize
	dynoff := phoff + 2*phsize
	ndyn := len(dyns) + 3 // STRTAB, STRSZ, NULL
	stroff := dynoff + ndyn*dynsize
	dyns = append(dyns, dyn{5, vbase + uint64(stroff)}, dyn{10, uint64(len(strtab))}, dyn{0, 0})
	total := stroff + len(strtab)
	b := make([]byte, total)
	copy(b, []byte{0x7f, 'E', 'L', 'F'})
	if class64 {
		b[4] = 2
	} else {
		b[4] = 1
	}
	if bo == binary.LittleEndian {
		b[5] = 1
	} else {
		b[5] = 2
	}
	b[6] = 1
	bo.PutUint16(b[16:], 3) // ET_DYN
	if class64 {
		bo.PutUint16(b[18:], 183) // aarch64
		bo.PutUint64(b[32:], uint64(phoff))
		bo.PutUint16(b[54:], uint16(phsize))
		bo.PutUint16(b[56:], 2)
	} else {
		bo.PutUint16(b[18:], 40) // arm
		bo.PutUint32(b[28:], uint32(phoff))
		bo.PutUint16(b[42:], uint16(phsize))
		bo.PutUint16(b[44:], 2)
	}
	ph := func(i int, typ uint32, off, vaddr, filesz uint64) {
		p := b[phoff+i*phsize:]
		bo.PutUint32(p[0:], typ)
		if class64 {
			bo.PutUint64(p[8:], off)
			bo.PutUint64(p[16:], vaddr)
			bo.PutUint64(p[32:], filesz)
			bo.PutUint64(p[40:], filesz)
		} else {
			bo.PutUint32(p[4:], uint32(off))
			bo.PutUint32(p[8:], uint32(vaddr))
			bo.PutUint32(p[16:], uint32(filesz))
			bo.PutUint32(p[20:], uint32(filesz))
		}
	}
	ph(0, 1, 0, vbase, uint64(total))                                    // PT_LOAD
	ph(1, 2, uint64(dynoff), vbase+uint64(dynoff), uint64(ndyn*dynsize)) // PT_DYNAMIC
	for i, d := range dyns {
		p := b[dynoff+i*dynsize:]
		if class64 {
			bo.PutUint64(p[0:], d.tag)
			bo.PutUint64(p[8:], d.val)
		} else {
			bo.PutUint32(p[0:], uint32(d.tag))
			bo.PutUint32(p[4:], uint32(d.val))
		}
	}
	copy(b[stroff:], strtab)
	return b
}

func TestReadDynamicSection(t *testing.T) {
	cases := []struct {
		name    string
		class64 bool
		bo      binary.ByteOrder
	}{
		{"elf64-le", true, binary.LittleEndian},
		{"elf64-be", true, binary.BigEndian},
		{"elf32-le", false, binary.LittleEndian},
		{"elf32-be", false, binary.BigEndian},
	}
	for _, c := range cases {
		data := build(c.class64, c.bo, []string{"libssl.so.3", "libcrypto.so.3", "libc.so.6"}, "libfoo.so.1", "", "$ORIGIN/../lib:/opt/app/lib")
		info, err := Read(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if strings.Join(info.Needed, ",") != "libssl.so.3,libcrypto.so.3,libc.so.6" || info.SOName != "libfoo.so.1" ||
			strings.Join(info.RunPath, "|") != "$ORIGIN/../lib|/opt/app/lib" || len(info.RPath) != 0 {
			t.Errorf("%s: %+v", c.name, info)
		}
		wantClass, wantMachine := 32, uint16(40)
		if c.class64 {
			wantClass, wantMachine = 64, 183
		}
		if info.Class != wantClass || info.Machine != wantMachine || info.LittleEndian != (c.bo == binary.LittleEndian) {
			t.Errorf("%s: class=%d machine=%d le=%v", c.name, info.Class, info.Machine, info.LittleEndian)
		}
	}
	data := build(true, binary.LittleEndian, []string{"liba.so"}, "", "/old/rpath", "")
	info, _ := Read(bytes.NewReader(data), int64(len(data)))
	if strings.Join(info.RPath, "|") != "/old/rpath" {
		t.Errorf("RPath = %v", info.RPath)
	}
}

func TestReadRejectsNonELFAndNeverPanics(t *testing.T) {
	for _, in := range [][]byte{nil, []byte("#!/bin/sh\n"), {0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1}, 20)} {
		if _, err := Read(bytes.NewReader(in), int64(len(in))); err == nil {
			t.Errorf("Read(%q) must fail", in)
		}
	}
	data := build(true, binary.LittleEndian, []string{"libssl.so.3", "libcrypto.so.3"}, "x.so", "/a", "/b")
	for i := range data {
		Read(bytes.NewReader(data[:i]), int64(i))
		m := append([]byte(nil), data...)
		m[i] ^= 0xff
		Read(bytes.NewReader(m), int64(len(m)))
	}
}

// 検証ラボで採取した実物のバイナリについて、readelf の報告と突き合わせる。
// KAGIYA_LAB_ELF にラボの出力（lab/out/elf）を指定したときだけ実行する。
func TestAgainstLabBinaries(t *testing.T) {
	root := os.Getenv("KAGIYA_LAB_ELF")
	if root == "" {
		t.Skip("KAGIYA_LAB_ELF is not set")
	}
	dirs, _ := filepath.Glob(filepath.Join(root, "*", "truth.tsv"))
	checked := 0
	for _, tsv := range dirs {
		dir := filepath.Dir(tsv)
		want := map[string]map[string][]string{} // バイナリ名 → 種別 → 値
		b, _ := os.ReadFile(tsv)
		for _, l := range strings.Split(string(b), "\n") {
			c := strings.Split(l, "\t")
			if len(c) < 4 {
				continue
			}
			if want[c[0]] == nil {
				want[c[0]] = map[string][]string{}
			}
			want[c[0]][c[2]] = append(want[c[0]][c[2]], c[3])
		}
		for name, w := range want {
			data, err := os.ReadFile(filepath.Join(dir, "bin", name))
			if err != nil {
				continue
			}
			info, err := Read(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Errorf("%s/%s: %v", filepath.Base(dir), name, err)
				continue
			}
			eq := func(kind string, got []string) {
				g, x := append([]string(nil), got...), append([]string(nil), w[kind]...)
				sort.Strings(g)
				sort.Strings(x)
				if strings.Join(g, ",") != strings.Join(x, ",") {
					t.Errorf("%s/%s %s: got %v, readelf says %v", filepath.Base(dir), name, kind, g, x)
				}
			}
			eq("needed", info.Needed)
			var so []string
			if info.SOName != "" {
				so = []string{info.SOName}
			}
			eq("soname", so)
			var rp, rr []string
			if len(info.RPath) > 0 {
				rp = []string{strings.Join(info.RPath, ":")}
			}
			if len(info.RunPath) > 0 {
				rr = []string{strings.Join(info.RunPath, ":")}
			}
			eq("rpath", rp)
			eq("runpath", rr)
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no lab binaries found")
	}
	t.Logf("%d binaries match readelf", checked)
}

func FuzzRead(f *testing.F) {
	f.Add(build(true, binary.LittleEndian, []string{"libssl.so.3"}, "", "", ""))
	f.Fuzz(func(t *testing.T, b []byte) { Read(bytes.NewReader(b), int64(len(b))) })
}
