package elfdyn

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"kagiya/internal/parse/elfdyn/elftest"
)

func build(class64 bool, bo binary.ByteOrder, needed []string, soname, rpath, runpath string) []byte {
	return elftest.Build(class64, bo, needed, soname, rpath, runpath)
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
