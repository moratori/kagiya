//go:build unix

package safefs

import (
	"errors"
	"io"
	"io/fs"
	"os"
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
