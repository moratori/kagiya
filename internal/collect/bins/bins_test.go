//go:build unix

package bins

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kagiya/internal/inventory"
	"kagiya/internal/logx"
	"kagiya/internal/model"
	"kagiya/internal/parse/elfdyn/elftest"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

func elf64(needed []string, soname, runpath string, strs ...string) []byte {
	b := elftest.Build(true, binary.LittleEndian, needed, soname, "", runpath)
	for _, s := range strs {
		b = append(b, s...)
		b = append(b, 0)
	}
	return b
}

func put(t *testing.T, path string, data []byte) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

// ldCache は新形式の ld.so.cache を組み立てる。
func ldCache(entries [][2]string) []byte {
	const hdr, ent = 48, 24
	strs := []byte{}
	offs := make([][2]uint32, len(entries))
	base := uint32(hdr + ent*len(entries))
	for i, e := range entries {
		for j := 0; j < 2; j++ {
			offs[i][j] = base + uint32(len(strs))
			strs = append(strs, e[j]...)
			strs = append(strs, 0)
		}
	}
	b := make([]byte, hdr+ent*len(entries))
	copy(b, "glibc-ld.so.cache1.1")
	binary.LittleEndian.PutUint32(b[20:], uint32(len(entries)))
	binary.LittleEndian.PutUint32(b[24:], uint32(len(strs)))
	for i := range entries {
		e := b[hdr+ent*i:]
		binary.LittleEndian.PutUint32(e[0:], 0x0a03)
		binary.LittleEndian.PutUint32(e[4:], offs[i][0])
		binary.LittleEndian.PutUint32(e[8:], offs[i][1])
	}
	return append(b, strs...)
}

// RHEL 9 系の配置を模した環境（配置は実物で確認したもの。版文字列も実物に埋め込まれていた形）。
func setup(t *testing.T) (string, *model.Inventory) {
	t.Helper()
	p, _ := filepath.EvalSymlinks(t.TempDir())
	put(t, p+"/usr/lib64/libcrypto.so.3.5.9", elf64([]string{"libc.so.6"}, "libcrypto.so.3", "", "OpenSSL 3.5.9 29 Sep 2026"))
	put(t, p+"/usr/lib64/libssl.so.3.5.9", elf64([]string{"libcrypto.so.3", "libc.so.6"}, "libssl.so.3", ""))
	os.Symlink("libcrypto.so.3.5.9", p+"/usr/lib64/libcrypto.so.3")
	os.Symlink("libssl.so.3.5.9", p+"/usr/lib64/libssl.so.3")
	os.Symlink("usr/lib64", p+"/lib64")
	// キャッシュには別アーキテクチャ（32bit）の同名ライブラリが先に載っている
	put(t, p+"/usr/lib/libcrypto.so.3", elftest.Build(false, binary.LittleEndian, nil, "libcrypto.so.3", "", ""))
	put(t, p+"/etc/ld.so.cache", ldCache([][2]string{
		{"libcrypto.so.3", "/usr/lib/libcrypto.so.3"},
		{"libssl.so.3", "/lib64/libssl.so.3"},
		{"libcrypto.so.3", "/lib64/libcrypto.so.3"},
	}))
	// nginx: ビルド時の OpenSSL の版文字列が埋め込まれている（実行時に使われるライブラリの版とは限らない）
	put(t, p+"/usr/sbin/nginx", elf64([]string{"libssl.so.3", "libcrypto.so.3", "libc.so.6"}, "", "", "nginx/1.20.1", "OpenSSL 3.5.8 25 Aug 2026"))
	// httpd: 本体は暗号ライブラリにリンクせず、実行時に読み込むモジュールがリンクしている
	put(t, p+"/usr/sbin/httpd", elf64([]string{"libc.so.6"}, "", "", "Apache/2.4.62 (Red Hat Enterprise Linux)", "Apache/2.4.62"))
	put(t, p+"/usr/lib64/httpd/modules/mod_ssl.so", elf64([]string{"libssl.so.3", "libcrypto.so.3"}, "mod_ssl.so", ""))
	// sshd: 互換性判定用の紛らわしい文字列を含む。専用の探索パス（RUNPATH）に独自のライブラリを持つ
	put(t, p+"/usr/sbin/sshd", elf64([]string{"libcrypto.so.3"}, "", "$ORIGIN/../libexec/private", "OpenSSH_2", "OpenSSH_3.0", "OpenSSH_9.9p1"))
	put(t, p+"/usr/libexec/private/libcrypto.so.3", elf64(nil, "libcrypto.so.3", "", "OpenSSL 3.0.1 14 Dec 2021"))

	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	b := inventory.NewBuilder(rs, logx.New(io.Discard, time.Now))
	b.AddPackage(model.Package{Manager: "rpm", Name: "nginx-core", Epoch: 2, Version: "1.20.1", Release: "32.el9_9.1", Role: "web-server"})
	b.AddPackage(model.Package{Manager: "rpm", Name: "openssl-libs", Epoch: 1, Version: "3.5.9", Release: "1.el9_9", Role: "crypto-library"})
	(&Collector{Prefix: p, Opener: &safefs.Opener{OnSkip: b.Skip}, Builder: b, Rules: rs}).Collect()
	return p, b.Inventory()
}

func TestCollectComponents(t *testing.T) {
	p, inv := setup(t)
	byID := map[string]model.Component{}
	for _, c := range inv.Components {
		byID[c.ID] = c
	}
	if len(inv.Skipped) != 0 {
		t.Errorf("skipped: %+v", inv.Skipped)
	}

	libID := "lib:openssl:" + p + "/usr/lib64/libcrypto.so.3.5.9"
	sslID := "lib:openssl:" + p + "/usr/lib64/libssl.so.3.5.9"
	lib, ok := byID[libID]
	if !ok {
		t.Fatalf("libcrypto component missing; have %v", keys(byID))
	}
	if lib.Kind != "library" || lib.Name != "openssl" || lib.Version == nil || lib.Version.Value != "3.5.9" || lib.Version.Source != "binary-string" {
		t.Errorf("libcrypto = %+v version=%+v", lib, lib.Version)
	}
	if lib.Package == nil || lib.Package.Name != "openssl-libs" || lib.Package.Version != "3.5.9" || lib.Package.Release != "1.el9_9" || lib.Package.Epoch != 1 {
		t.Errorf("libcrypto package = %+v", lib.Package)
	}

	nginx, ok := byID["app:nginx:"+p+"/usr/sbin/nginx"]
	if !ok {
		t.Fatalf("nginx component missing; have %v", keys(byID))
	}
	if nginx.Kind != "application" || nginx.Version == nil || nginx.Version.Value != "1.20.1" {
		t.Errorf("nginx = %+v version=%+v", nginx, nginx.Version)
	}
	if nginx.Package == nil || nginx.Package.Name != "nginx-core" || nginx.Package.Release != "32.el9_9.1" {
		t.Errorf("nginx package = %+v", nginx.Package)
	}
	links := map[string]model.Link{}
	for _, l := range nginx.Links {
		links[l.SOName] = l
	}
	// 32bit の同名ライブラリではなく、同じアーキテクチャのものに解決される。リンク（/lib64、libcrypto.so.3）は実体まで辿る。
	if l := links["libcrypto.so.3"]; l.Component != libID || l.Path != p+"/usr/lib64/libcrypto.so.3.5.9" || l.Via != "needed" || l.ResolvedBy != "ld.so.cache" {
		t.Errorf("nginx -> libcrypto link = %+v", l)
	}
	if l := links["libssl.so.3"]; l.Component != sslID {
		t.Errorf("nginx -> libssl link = %+v", l)
	}
	if _, ok := links["libc.so.6"]; ok {
		t.Error("libraries without a rule must not be listed")
	}

	// httpd: モジュール経由でのリンクとして記録される
	httpd := byID["app:httpd:"+p+"/usr/sbin/httpd"]
	if httpd.Version == nil || httpd.Version.Value != "2.4.62" {
		t.Errorf("httpd version = %+v", httpd.Version)
	}
	viaModule := 0
	for _, l := range httpd.Links {
		if l.Via == "module" && l.Module == p+"/usr/lib64/httpd/modules/mod_ssl.so" && (l.Component == libID || l.Component == sslID) {
			viaModule++
		}
	}
	if viaModule != 2 {
		t.Errorf("httpd links = %+v", httpd.Links)
	}

	// sshd: 紛らわしい文字列ではなく正しい版。専用の探索パスにあるライブラリが優先される。
	sshd := byID["app:openssh:"+p+"/usr/sbin/sshd"]
	if sshd.Version == nil || sshd.Version.Value != "9.9p1" {
		t.Errorf("sshd version = %+v", sshd.Version)
	}
	if len(sshd.Links) != 1 || sshd.Links[0].Path != p+"/usr/libexec/private/libcrypto.so.3" || sshd.Links[0].ResolvedBy != "runpath" {
		t.Errorf("sshd links = %+v", sshd.Links)
	}
	priv := byID["lib:openssl:"+p+"/usr/libexec/private/libcrypto.so.3"]
	if priv.Version == nil || priv.Version.Value != "3.0.1" {
		t.Errorf("private libcrypto = %+v", priv.Version)
	}
	// libssl には版文字列がない（実物でも同じ）。版は不明のまま、パッケージ情報だけが付く。
	if ssl := byID[sslID]; ssl.Version != nil || ssl.Package == nil {
		t.Errorf("libssl = %+v version=%+v", ssl, ssl.Version)
	}
}

func TestUnresolvedLibraryIsRecorded(t *testing.T) {
	p, _ := filepath.EvalSymlinks(t.TempDir())
	put(t, p+"/usr/sbin/nginx", elf64([]string{"libssl.so.3"}, "", "", "nginx/1.24.0"))
	rs, _ := ruleset.Builtin()
	b := inventory.NewBuilder(rs, logx.New(io.Discard, time.Now))
	(&Collector{Prefix: p, Opener: &safefs.Opener{OnSkip: b.Skip}, Builder: b, Rules: rs}).Collect()
	inv := b.Inventory()
	if len(inv.Components) != 1 || len(inv.Components[0].Links) != 1 {
		t.Fatalf("components = %+v", inv.Components)
	}
	if l := inv.Components[0].Links[0]; l.SOName != "libssl.so.3" || l.Path != "" || l.Component != "" || l.ResolvedBy != "unresolved" {
		t.Errorf("link = %+v", l)
	}
}

func TestNothingInstalled(t *testing.T) {
	p, _ := filepath.EvalSymlinks(t.TempDir())
	rs, _ := ruleset.Builtin()
	b := inventory.NewBuilder(rs, logx.New(io.Discard, time.Now))
	(&Collector{Prefix: p, Opener: &safefs.Opener{OnSkip: b.Skip}, Builder: b, Rules: rs}).Collect()
	if inv := b.Inventory(); len(inv.Components) != 0 || len(inv.Skipped) != 0 {
		t.Errorf("inv = %+v", inv)
	}
}

func keys(m map[string]model.Component) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
