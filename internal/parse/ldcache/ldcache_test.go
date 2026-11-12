package ldcache

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ldconfig -p の行: "\tlibssl.so.3 (libc6,AArch64) => /lib64/libssl.so.3"
var ldconfigLine = regexp.MustCompile(`^\s+(\S+) \(.*\) => (\S+)$`)

func truth(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if m := ldconfigLine.FindStringSubmatch(l); m != nil {
			out = append(out, m[1]+" => "+m[2])
		}
	}
	sort.Strings(out)
	return out
}

func TestParseAgainstLdconfig(t *testing.T) {
	for _, name := range []string{"ubi9", "ubuntu1604"} {
		data, err := os.ReadFile("testdata/" + name + ".ld.so.cache")
		if err != nil {
			t.Fatal(err)
		}
		entries, err := Parse(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var got []string
		for _, e := range entries {
			got = append(got, e.Name+" => "+e.Path)
		}
		sort.Strings(got)
		want := truth(t, "testdata/"+name+".ldconfig-p.txt")
		if len(want) < 100 {
			t.Fatalf("%s: only %d lines of truth", name, len(want))
		}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("%s: %d entries, want %d (as reported by ldconfig -p)", name, len(got), len(want))
			for i := 0; i < len(got) && i < len(want); i++ {
				if got[i] != want[i] {
					t.Errorf("  first difference at %d: got %q, want %q", i, got[i], want[i])
					break
				}
			}
		}
	}
}

func TestLookup(t *testing.T) {
	data, _ := os.ReadFile("testdata/ubi9.ld.so.cache")
	entries, _ := Parse(data)
	var paths []string
	for _, e := range entries {
		if e.Name == "libcrypto.so.3" {
			paths = append(paths, e.Path)
		}
	}
	if len(paths) != 1 || paths[0] != "/lib64/libcrypto.so.3" {
		t.Errorf("libcrypto.so.3 => %v", paths)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	for _, in := range [][]byte{nil, []byte("hello"), []byte("glibc-ld.so.cache1.1"), append([]byte("glibc-ld.so.cache1.1"), 0xff, 0xff, 0xff, 0x7f, 0, 0, 0, 0)} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) must fail", in)
		}
	}
	data, _ := os.ReadFile("testdata/ubuntu1604.ld.so.cache")
	for i := 0; i < len(data); i += 37 {
		Parse(data[:i])
		m := append([]byte(nil), data...)
		m[i] ^= 0xff
		Parse(m)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte("glibc-ld.so.cache1.1"))
	f.Fuzz(func(t *testing.T, b []byte) { Parse(b) })
}
