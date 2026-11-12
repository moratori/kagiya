package pkgdb

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func gunzip(t testing.TB, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func lines(t testing.TB, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return out
}

// rpm -qa --qf '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n' と同じ形にする。
func rpmLines(pkgs []Package) []string {
	out := make([]string, len(pkgs))
	// rpm は値のない項目を "(none)" と表示する（署名鍵を表す gpg-pubkey にはアーキテクチャもソースもない）。
	none := func(s string) string {
		if s == "" {
			return "(none)"
		}
		return s
	}
	for i, p := range pkgs {
		out[i] = fmt.Sprintf("%s\t%d\t%s\t%s\t%s\t%s", p.Name, p.Epoch, p.Version, p.Release, none(p.Arch), none(p.SourceRPM))
	}
	sort.Strings(out)
	return out
}

func same(t *testing.T, what string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: got %d packages, want %d\n got: %v\nwant: %v", what, len(got), len(want), head(got), head(want))
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s: entry %d differs\n got: %q\nwant: %q", what, i, got[i], want[i])
			return
		}
	}
}

func head(s []string) []string {
	if len(s) > 6 {
		return s[:6]
	}
	return s
}

// RHEL 8.10 の rpm（4.14.3、Berkeley DB）が作ったデータベース。正解は同じ rpm の rpm -qa。
func TestRPMBerkeleyDB(t *testing.T) {
	data := gunzip(t, "testdata/rpm-bdb-el8/Packages.gz")
	pkgs, failed, err := ReadRPMBDB(bytes.NewReader(data), int64(len(data)))
	if err != nil || failed != 0 {
		t.Fatalf("err=%v failed=%d", err, failed)
	}
	same(t, "bdb", rpmLines(pkgs), lines(t, "testdata/rpm-bdb-el8/expected.tsv"))
	for _, p := range pkgs {
		if p.Name == "openssl-libs" && (p.Epoch != 1 || p.Version != "1.1.1k" || p.Release != "18.el8_6" || p.Vendor == "" || p.License == "") {
			t.Errorf("openssl-libs = %+v", p)
		}
	}
}

// RHEL 9.9 の rpm（4.16.1.3、SQLite）が作ったデータベース。
func TestRPMSQLite(t *testing.T) {
	data := gunzip(t, "testdata/rpm-sqlite-el9/rpmdb.sqlite.gz")
	pkgs, failed, err := ReadRPMSQLite(bytes.NewReader(data), int64(len(data)), nil, 0)
	if err != nil || failed != 0 {
		t.Fatalf("err=%v failed=%d", err, failed)
	}
	same(t, "sqlite", rpmLines(pkgs), lines(t, "testdata/rpm-sqlite-el9/expected.tsv"))
}

// 変更が先行書き込みログ（WAL）にだけ入っていて、本体ファイルにはまだ反映されていない状態。
// 本体だけを読むと 4 件（古い内容）、WAL を合わせて読むと 3 件（正しい内容）。
func TestRPMSQLiteWithUncheckpointedWAL(t *testing.T) {
	db := gunzip(t, "testdata/rpm-sqlite-wal/rpmdb.sqlite.gz")
	wal := gunzip(t, "testdata/rpm-sqlite-wal/rpmdb.sqlite-wal.gz")
	want := lines(t, "testdata/rpm-sqlite-wal/expected.tsv")

	pkgs, failed, err := ReadRPMSQLite(bytes.NewReader(db), int64(len(db)), bytes.NewReader(wal), int64(len(wal)))
	if err != nil || failed != 0 {
		t.Fatalf("err=%v failed=%d", err, failed)
	}
	same(t, "sqlite+wal", rpmLines(pkgs), want)

	stale, _, err := ReadRPMSQLite(bytes.NewReader(db), int64(len(db)), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) != len(want)+1 {
		t.Errorf("without the WAL the fixture must show the stale content (%d packages), got %d", len(want)+1, len(stale))
	}

	// 壊れた WAL（チェックサム不一致）は使わず、本体の内容にとどめる
	bad := append([]byte(nil), wal...)
	bad[len(bad)/2] ^= 0xff
	got, _, err := ReadRPMSQLite(bytes.NewReader(db), int64(len(db)), bytes.NewReader(bad), int64(len(bad)))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) && len(got) != len(want)+1 {
		t.Errorf("corrupt WAL: got %d packages", len(got))
	}
}

// dpkg の状態ファイル。正解は dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\t${source:Package}\t${source:Version}\n'
func TestDpkgStatus(t *testing.T) {
	for _, dir := range []string{"dpkg-ubuntu2404", "dpkg-ubuntu1604"} {
		f, err := os.Open(filepath.Join("testdata", dir, "status.excerpt"))
		if err != nil {
			t.Fatal(err)
		}
		pkgs, err := ParseDpkgStatus(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, p := range pkgs {
			abbrev := "?? "
			switch p.Status {
			case "install ok installed":
				abbrev = "ii "
			case "deinstall ok config-files":
				abbrev = "rc "
			}
			if (abbrev == "ii ") != p.Installed {
				t.Errorf("%s: %s: Installed=%v for status %q", dir, p.Name, p.Installed, p.Status)
			}
			got = append(got, fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s", p.Name, p.Version, p.Arch, abbrev, p.SourceName, p.SourceVersion))
		}
		sort.Strings(got)
		var want []string
		for _, l := range lines(t, filepath.Join("testdata", dir, "expected.tsv")) {
			if !strings.Contains(l, "\tun \t") { // 未導入で状態ファイルに記録のないもの
				want = append(want, l)
			}
		}
		same(t, dir, got, want)
	}
}

func TestDpkgStatusEdgeCases(t *testing.T) {
	in := "Package: a\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\nDescription: x\n continued line\n .\n more\n\n\n" +
		"Package: b\nStatus: install ok installed\nSource: src-b (2.0-1)\nVersion: 2.0-1+b1\nArchitecture: all\n" // 末尾に空行なし
	pkgs, err := ParseDpkgStatus(strings.NewReader(in))
	if err != nil || len(pkgs) != 2 {
		t.Fatalf("pkgs=%+v err=%v", pkgs, err)
	}
	if pkgs[0].SourceName != "a" || pkgs[0].SourceVersion != "1.0" {
		t.Errorf("source defaults to the package itself: %+v", pkgs[0])
	}
	if pkgs[1].SourceName != "src-b" || pkgs[1].SourceVersion != "2.0-1" || pkgs[1].Version != "2.0-1+b1" {
		t.Errorf("source with explicit version: %+v", pkgs[1])
	}
}

func TestParseRPMHeaderRejectsGarbage(t *testing.T) {
	for _, in := range [][]byte{nil, {0, 0, 0, 1}, bytes.Repeat([]byte{0xff}, 64), make([]byte, 16)} {
		if _, err := ParseRPMHeader(in); err == nil {
			t.Errorf("ParseRPMHeader(%x) must fail", in)
		}
	}
}

// 壊れたデータベースで panic せず、際限なく読み続けもしない。
func TestNeverPanics(t *testing.T) {
	bdb := gunzip(t, "testdata/rpm-bdb-el8/Packages.gz")
	sq := gunzip(t, "testdata/rpm-sqlite-wal/rpmdb.sqlite.gz")
	wal := gunzip(t, "testdata/rpm-sqlite-wal/rpmdb.sqlite-wal.gz")
	for i := 0; i < len(bdb); i += len(bdb)/150 + 1 {
		ReadRPMBDB(bytes.NewReader(bdb[:i]), int64(i))
		m := append([]byte(nil), bdb...)
		m[i] ^= 0xff
		ReadRPMBDB(bytes.NewReader(m), int64(len(m)))
	}
	for i := 0; i < len(sq); i += len(sq)/150 + 1 {
		ReadRPMSQLite(bytes.NewReader(sq[:i]), int64(i), nil, 0)
		m := append([]byte(nil), sq...)
		m[i] ^= 0xff
		ReadRPMSQLite(bytes.NewReader(m), int64(len(m)), bytes.NewReader(wal), int64(len(wal)))
	}
	for i := 0; i < len(wal); i += len(wal)/100 + 1 {
		ReadRPMSQLite(bytes.NewReader(sq), int64(len(sq)), bytes.NewReader(wal[:i]), int64(i))
	}
}

// 検証ラボで採取した実際のシステムのデータベース（数百パッケージ）との突き合わせ。
// KAGIYA_LAB_PKGDB にラボの出力ディレクトリ（lab/out）を指定したときだけ実行する。
func TestAgainstLabSystemDatabases(t *testing.T) {
	root := os.Getenv("KAGIYA_LAB_PKGDB")
	if root == "" {
		t.Skip("KAGIYA_LAB_PKGDB is not set")
	}
	n := 0
	dirs, _ := filepath.Glob(filepath.Join(root, "rpmdb", "*", "system"))
	for _, d := range dirs {
		want := lines(t, filepath.Join(d, "expected.tsv"))
		var pkgs []Package
		var failed int
		var err error
		if b, e := os.ReadFile(filepath.Join(d, "db", "Packages")); e == nil {
			pkgs, failed, err = ReadRPMBDB(bytes.NewReader(b), int64(len(b)))
		} else {
			b, e := os.ReadFile(filepath.Join(d, "db", "rpmdb.sqlite"))
			if e != nil {
				t.Fatalf("%s: no database found", d)
			}
			w, _ := os.ReadFile(filepath.Join(d, "db", "rpmdb.sqlite-wal"))
			pkgs, failed, err = ReadRPMSQLite(bytes.NewReader(b), int64(len(b)), bytes.NewReader(w), int64(len(w)))
		}
		if err != nil || failed != 0 {
			t.Errorf("%s: err=%v failed=%d", d, err, failed)
		}
		same(t, d, rpmLines(pkgs), want)
		t.Logf("%s: %d packages match rpm -qa", d, len(pkgs))
		n++
	}
	dpkgs, _ := filepath.Glob(filepath.Join(root, "dpkg", "*", "status.full"))
	for _, p := range dpkgs {
		f, _ := os.Open(p)
		pkgs, err := ParseDpkgStatus(f)
		f.Close()
		if err != nil {
			t.Errorf("%s: %v", p, err)
		}
		var got []string
		for _, pk := range pkgs {
			if pk.Installed {
				got = append(got, fmt.Sprintf("%s\t%s\t%s\t%s\t%s", pk.Name, pk.Version, pk.Arch, pk.SourceName, pk.SourceVersion))
			}
		}
		sort.Strings(got)
		var want []string
		for _, l := range lines(t, filepath.Join(filepath.Dir(p), "expected.full.tsv")) {
			c := strings.Split(l, "\t")
			if len(c) == 6 && c[3] == "ii " {
				want = append(want, strings.Join([]string{c[0], c[1], c[2], c[4], c[5]}, "\t"))
			}
		}
		sort.Strings(want)
		same(t, p, got, want)
		t.Logf("%s: %d installed packages match dpkg-query", p, len(got))
		n++
	}
	if n == 0 {
		t.Fatal("no lab databases found")
	}
}

func FuzzRPMHeader(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 3, 232, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) { ParseRPMHeader(b) })
}

func FuzzDatabases(f *testing.F) {
	f.Add(gunzip(f, "testdata/rpm-bdb-el8/Packages.gz")[:8192], []byte{})
	f.Fuzz(func(t *testing.T, a, b []byte) {
		ReadRPMBDB(bytes.NewReader(a), int64(len(a)))
		ReadRPMSQLite(bytes.NewReader(a), int64(len(a)), bytes.NewReader(b), int64(len(b)))
	})
}
