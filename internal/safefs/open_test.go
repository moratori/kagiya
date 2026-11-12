//go:build unix

package safefs

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"
)

func TestOpenerReadsRegularFile(t *testing.T) {
	root := tmpDir(t)
	write(t, root+"/db/Packages", "0123456789")
	o := &Opener{}
	f, err := o.Open(root + "/db/Packages")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.Size() != 10 {
		t.Errorf("Size = %d", f.Size())
	}
	buf := make([]byte, 4)
	if n, err := f.ReadAt(buf, 3); err != nil || n != 4 || string(buf) != "3456" {
		t.Errorf("ReadAt = %d %v %q", n, err, buf)
	}
	if _, err := f.ReadAt(buf, 8); !errors.Is(err, io.EOF) {
		t.Errorf("ReadAt past the end: err = %v, want io.EOF", err)
	}
	if o.BytesRead < 4 {
		t.Errorf("BytesRead = %d", o.BytesRead)
	}
}

func TestOpenerRefusals(t *testing.T) {
	root := tmpDir(t)
	write(t, root+"/real/file", "x")
	os.Symlink(root+"/real", root+"/linkdir")
	os.Symlink(root+"/real/file", root+"/real/linkfile")
	var skips []Skip
	o := &Opener{OnSkip: func(s Skip) { skips = append(skips, s) }}

	// 存在しない: 記録せずに「ない」と分かるエラーを返す（候補のパスを順に試す用途のため）
	if _, err := o.Open(root + "/real/missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: err = %v, want fs.ErrNotExist", err)
	}
	// 途中や末端にシンボリックリンクがある、通常ファイルでない、絶対パスでない: 開かない
	for _, p := range []string{root + "/linkdir/file", root + "/real/linkfile", root + "/real", "relative/file", root + "/real/../real/file"} {
		if f, err := o.Open(p); err == nil {
			f.Close()
			t.Errorf("Open(%q) must fail", p)
		}
	}
	if len(skips) != 0 {
		t.Errorf("unexpected skip records: %+v", skips)
	}

	// 読んではならない場所: 触れずにスキップを記録する
	o.Mounts = &fakeMounts{denied: map[string]string{root + "/real": "nfs4"}}
	if _, err := o.Open(root + "/real/file"); !errors.Is(err, ErrSkipped) {
		t.Errorf("file on a denied mount: err = %v, want ErrSkipped", err)
	}
	if len(skips) != 1 || skips[0].Reason != "network-fs" || skips[0].Detail != "nfs4" {
		t.Errorf("skips = %+v", skips)
	}
}

func TestOpenerPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores permission bits")
	}
	root := tmpDir(t)
	write(t, root+"/secret", "x")
	os.Chmod(root+"/secret", 0)
	var skips []Skip
	o := &Opener{OnSkip: func(s Skip) { skips = append(skips, s) }}
	if _, err := o.Open(root + "/secret"); !errors.Is(err, ErrSkipped) {
		t.Errorf("err = %v, want ErrSkipped", err)
	}
	if len(skips) != 1 || skips[0].Reason != "permission-denied" {
		t.Errorf("skips = %+v", skips)
	}
}

// 共有ライブラリは「libcrypto.so.3 → libcrypto.so.3.5.9」のようにシンボリックリンクで置かれ、
// /lib64 自体が /usr/lib64 へのリンクであることも多い。リンクは自前で1段ずつ解決し、その都度マウント表で判定する。
func TestOpenerResolve(t *testing.T) {
	root := tmpDir(t)
	write(t, root+"/usr/lib64/libcrypto.so.3.5.9", "lib")
	os.Symlink("libcrypto.so.3.5.9", root+"/usr/lib64/libcrypto.so.3") // 相対リンク
	os.Symlink("usr/lib64", root+"/lib64")                             // ディレクトリへの相対リンク
	os.Symlink(root+"/lib64/libcrypto.so.3", root+"/abs.so")           // 絶対リンク（さらにリンクを経由）
	os.Symlink("../usr/lib64/../lib64/libcrypto.so.3", root+"/lib64up.so")
	os.Mkdir(root+"/d", 0o755)
	os.Symlink("../lib64/libcrypto.so.3", root+"/d/rel.so")
	os.Symlink("loop2", root+"/loop1")
	os.Symlink("loop1", root+"/loop2")
	os.Symlink("nowhere", root+"/dangling")

	o := &Opener{}
	want := root + "/usr/lib64/libcrypto.so.3.5.9"
	for _, p := range []string{want, root + "/usr/lib64/libcrypto.so.3", root + "/lib64/libcrypto.so.3", root + "/abs.so", root + "/d/rel.so"} {
		got, err := o.Resolve(p)
		if err != nil || got != want {
			t.Errorf("Resolve(%q) = %q, %v; want %q", p, got, err, want)
		}
	}
	if _, err := o.Resolve(root + "/loop1"); err == nil {
		t.Error("symlink loop must fail")
	}
	if _, err := o.Resolve(root + "/dangling"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("dangling link: err = %v, want fs.ErrNotExist", err)
	}
	if _, err := o.Resolve("relative"); err == nil {
		t.Error("relative path must fail")
	}
	// 解決した結果は Open でそのまま開ける
	real, _ := o.Resolve(root + "/abs.so")
	f, err := o.Open(real)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

// リンクの行き先が読んではならない場所なら、そこには触れずにスキップを記録する。
func TestOpenerResolveStopsAtDeniedMount(t *testing.T) {
	root := tmpDir(t)
	write(t, root+"/nfs/lib/libx.so", "x")
	os.Symlink(root+"/nfs/lib/libx.so", root+"/libx.so")
	var skips []Skip
	m := &fakeMounts{denied: map[string]string{root + "/nfs": "nfs4"}}
	o := &Opener{Mounts: m, OnSkip: func(s Skip) { skips = append(skips, s) }}
	if _, err := o.Resolve(root + "/libx.so"); !errors.Is(err, ErrSkipped) {
		t.Errorf("err = %v, want ErrSkipped", err)
	}
	if len(skips) != 1 || skips[0].Reason != "network-fs" {
		t.Errorf("skips = %+v", skips)
	}
}

func TestOpenerReadDir(t *testing.T) {
	root := tmpDir(t)
	write(t, root+"/d/b.cnf", "b")
	write(t, root+"/d/a.cnf", "a")
	os.Mkdir(root+"/d/sub", 0o755)
	os.Symlink(root+"/d/a.cnf", root+"/d/link.cnf")
	o := &Opener{}
	names, err := o.ReadDir(root + "/d")
	if err != nil {
		t.Fatal(err)
	}
	// 通常ファイルの名前だけを、整列して返す（リンクやディレクトリは含めない）
	if len(names) != 2 || names[0] != "a.cnf" || names[1] != "b.cnf" {
		t.Errorf("names = %v", names)
	}
	if _, err := o.ReadDir(root + "/d/a.cnf"); err == nil {
		t.Error("ReadDir on a file must fail")
	}
	if _, err := o.ReadDir(root + "/missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing dir: %v", err)
	}
	o.Mounts = &fakeMounts{denied: map[string]string{root + "/d": "cifs"}}
	if _, err := o.ReadDir(root + "/d"); !errors.Is(err, ErrSkipped) {
		t.Errorf("denied dir: %v", err)
	}
}

// 擬似ファイルシステム（/proc など）は探索しないが、許可した特定の場所だけは直接読める。
type pseudoMounts struct{ prefix string }

func (m pseudoMounts) Check(p string) (Verdict, Mount) {
	if p == m.prefix || strings.HasPrefix(p, m.prefix+"/") {
		return SkipPseudoFS, Mount{FSType: "proc"}
	}
	return Allow, Mount{FSType: "ext4"}
}
func (m pseudoMounts) ByDevice(uint32, uint32) (Verdict, Mount, bool) { return Allow, Mount{}, false }

func TestOpenerAllowPseudo(t *testing.T) {
	root := tmpDir(t)
	write(t, root+"/proc/sys/crypto/fips_enabled", "1\n")
	write(t, root+"/proc/1/environ", "SECRET=x")
	o := &Opener{Mounts: pseudoMounts{root + "/proc"}, AllowPseudo: []string{root + "/proc/sys/crypto"}}
	f, err := o.Open(root + "/proc/sys/crypto/fips_enabled")
	if err != nil {
		t.Fatalf("allowed pseudo file: %v", err)
	}
	f.Close()
	if _, err := o.Open(root + "/proc/1/environ"); !errors.Is(err, ErrSkipped) {
		t.Errorf("other pseudo files must stay off limits: %v", err)
	}
}
