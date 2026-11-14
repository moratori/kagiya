//go:build unix

package safefs

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
)

func tmpDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

type result struct {
	files []string
	skips map[string]Skip
}

func run(t *testing.T, w *Walker, root string) result {
	t.Helper()
	res := result{skips: map[string]Skip{}}
	w.OnSkip = func(s Skip) { res.skips[strings.TrimPrefix(s.Path, root)] = s }
	err := w.Walk(context.Background(), root, func(e *Entry) error {
		res.files = append(res.files, strings.TrimPrefix(e.Path, root))
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	sort.Strings(res.files)
	return res
}

func TestWalkVisitsRegularFilesOnly(t *testing.T) {
	root := tmpDir(t)
	write(t, root+"/a.pem", "A")
	write(t, root+"/sub/b.crt", "B")
	write(t, root+"/sub/deep/c.txt", "C")
	outside := tmpDir(t)
	write(t, outside+"/secret.pem", "S")
	// シンボリックリンク（ファイル・ディレクトリ）は辿らない
	os.Symlink(outside+"/secret.pem", root+"/link.pem")
	os.Symlink(outside, root+"/linkdir")
	// FIFO は開かない（開くと止まる）
	if err := syscall.Mkfifo(root+"/fifo", 0o644); err != nil {
		t.Fatal(err)
	}

	w := &Walker{}
	res := run(t, w, root)
	want := []string{"/a.pem", "/sub/b.crt", "/sub/deep/c.txt"}
	if strings.Join(res.files, ",") != strings.Join(want, ",") {
		t.Errorf("visited %v, want %v", res.files, want)
	}
	if w.Stats.Symlinks != 2 || w.Stats.Special != 1 || w.Stats.Files != 3 {
		t.Errorf("stats = %+v", w.Stats)
	}
}

func TestWalkExcludes(t *testing.T) {
	root := tmpDir(t)
	write(t, root+"/keep/a.pem", "A")
	write(t, root+"/skipme/b.pem", "B")
	write(t, root+"/keep/x.log", "L")
	ex, _ := NewExcludes([]string{root + "/skipme", "*.log"})
	res := run(t, &Walker{Excludes: ex}, root)
	if strings.Join(res.files, ",") != "/keep/a.pem" {
		t.Errorf("visited %v", res.files)
	}
	if s := res.skips["/skipme"]; s.Reason != "excluded" {
		t.Errorf("skip record for excluded dir = %+v", s)
	}
	if s := res.skips["/keep/x.log"]; s.Reason != "excluded" {
		t.Errorf("skip record for excluded file = %+v", s)
	}
}

func TestWalkRecordsPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores permission bits")
	}
	root := tmpDir(t)
	write(t, root+"/ok/a.pem", "A")
	write(t, root+"/locked/b.pem", "B")
	os.Chmod(root+"/locked", 0)
	t.Cleanup(func() { os.Chmod(root+"/locked", 0o755) })
	write(t, root+"/ok/unreadable.pem", "U")
	os.Chmod(root+"/ok/unreadable.pem", 0)

	res := result{skips: map[string]Skip{}}
	w := &Walker{OnSkip: func(s Skip) { res.skips[strings.TrimPrefix(s.Path, root)] = s }}
	var readErr error
	err := w.Walk(context.Background(), root, func(e *Entry) error {
		if strings.HasSuffix(e.Path, "unreadable.pem") {
			_, readErr = e.ReadAll()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if s := res.skips["/locked"]; s.Reason != "permission-denied" {
		t.Errorf("skip for unreadable dir = %+v", s)
	}
	if !errors.Is(readErr, ErrSkipped) {
		t.Errorf("ReadAll on unreadable file: err = %v, want ErrSkipped", readErr)
	}
	if s := res.skips["/ok/unreadable.pem"]; s.Reason != "permission-denied" {
		t.Errorf("skip for unreadable file = %+v", s)
	}
}

// 偽のマウント表: 指定した接頭辞の配下をネットワーク FS とみなす。
type fakeMounts struct {
	denied  map[string]string // パス接頭辞 → 種別
	checked []string
	byDev   map[[2]uint32]Verdict
}

func (f *fakeMounts) Check(p string) (Verdict, Mount) {
	f.checked = append(f.checked, p)
	for prefix, fstype := range f.denied {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return SkipNetworkFS, Mount{MountPoint: prefix, FSType: fstype}
		}
	}
	return Allow, Mount{MountPoint: "/", FSType: "ext4", Major: 8, Minor: 1}
}

func (f *fakeMounts) ByDevice(major, minor uint32) (Verdict, Mount, bool) {
	v, ok := f.byDev[[2]uint32{major, minor}]
	return v, Mount{Major: major, Minor: minor}, ok
}

// fakeDevice は、どのディレクトリも、fakeMounts が「許可」で返すマウントと同じデバイス（8:1）にあることにする。
// 実際のデバイス番号は実行環境によって違い、そのままだと「マウント表と合わないデバイス」として起点ごと読み飛ばされる環境がある
// （CI の amd64 の実行環境で起きた）。
func fakeDevice(fs.FileInfo) (uint32, uint32, bool) { return 8, 1, true }

func TestWalkSkipsNetworkFSWithoutTouching(t *testing.T) {
	root := tmpDir(t)
	write(t, root+"/local/a.pem", "A")
	write(t, root+"/mnt/share/b.pem", "B")
	m := &fakeMounts{denied: map[string]string{root + "/mnt/share": "nfs4"}}
	res := run(t, &Walker{Mounts: m, devOf: fakeDevice}, root)
	if strings.Join(res.files, ",") != "/local/a.pem" {
		t.Errorf("visited %v", res.files)
	}
	s := res.skips["/mnt/share"]
	if s.Reason != "network-fs" || s.Detail != "nfs4" {
		t.Errorf("skip record = %+v", s)
	}
	for _, p := range m.checked {
		if strings.HasPrefix(p, root+"/mnt/share/") {
			t.Errorf("walker looked below a denied mount: %s", p)
		}
	}
}

func TestWalkRootOnDeniedMountIsSkipped(t *testing.T) {
	root := tmpDir(t)
	write(t, root+"/a.pem", "A")
	m := &fakeMounts{denied: map[string]string{filepath.Dir(root): "cifs"}}
	res := run(t, &Walker{Mounts: m, devOf: fakeDevice}, root)
	if len(res.files) != 0 {
		t.Errorf("visited %v", res.files)
	}
	if s := res.skips[""]; s.Reason != "network-fs" || s.Detail != "cifs" {
		t.Errorf("skip record = %+v (all: %v)", s, res.skips)
	}
}

// 開いたディレクトリのデバイス番号がマウント表の想定と違う場合（表の取得後に別のものがマウントされた等）は読まない。
func TestWalkDeviceMismatch(t *testing.T) {
	root := tmpDir(t)
	write(t, root+"/same/a.pem", "A")
	write(t, root+"/newmount/b.pem", "B")
	write(t, root+"/knownlocal/c.pem", "C")
	write(t, root+"/knownnfs/d.pem", "D")
	m := &fakeMounts{byDev: map[[2]uint32]Verdict{{8, 2}: Allow, {0, 77}: SkipNetworkFS}}
	w := &Walker{Mounts: m}
	w.devOf = func(fi fs.FileInfo) (uint32, uint32, bool) {
		switch fi.Name() {
		case "newmount":
			return 0, 99, true // マウント表にないデバイス
		case "knownlocal":
			return 8, 2, true // 表にある別のローカルデバイス
		case "knownnfs":
			return 0, 77, true // 表にあるネットワーク FS のデバイス
		}
		return 8, 1, true
	}
	res := run(t, w, root)
	if strings.Join(res.files, ",") != "/knownlocal/c.pem,/same/a.pem" {
		t.Errorf("visited %v", res.files)
	}
	if s := res.skips["/newmount"]; s.Reason != "unknown-fs" || s.Detail != "device-mismatch" {
		t.Errorf("skip for unknown device = %+v", s)
	}
	if s := res.skips["/knownnfs"]; s.Reason != "network-fs" {
		t.Errorf("skip for nfs device = %+v", s)
	}
}

func TestWalkSkipDirs(t *testing.T) {
	root := tmpDir(t)
	write(t, root+"/out/result.json", "{}")
	write(t, root+"/a.pem", "A")
	res := run(t, &Walker{SkipDirs: []string{root + "/out"}}, root)
	if strings.Join(res.files, ",") != "/a.pem" {
		t.Errorf("visited %v", res.files)
	}
}

func TestWalkMaxDepth(t *testing.T) {
	root := tmpDir(t)
	write(t, root+"/1/2/3/deep.pem", "D")
	write(t, root+"/1/shallow.pem", "S")
	res := run(t, &Walker{MaxDepth: 2}, root)
	if strings.Join(res.files, ",") != "/1/shallow.pem" {
		t.Errorf("visited %v", res.files)
	}
	if s := res.skips["/1/2/3"]; s.Reason != "too-deep" {
		t.Errorf("skip = %+v (all %v)", s, res.skips)
	}
}

func TestWalkRejectsBadRoots(t *testing.T) {
	root := tmpDir(t)
	os.Mkdir(root+"/real", 0o755)
	os.Symlink(root+"/real", root+"/link")
	w := &Walker{}
	noop := func(*Entry) error { return nil }
	for _, r := range []string{"relative", root + "/link", root + "/link/x", root + "/../x", root + "/missing"} {
		if err := w.Walk(context.Background(), r, noop); err == nil {
			t.Errorf("Walk(%q) must fail", r)
		}
	}
}

func TestWalkStopsOnCancel(t *testing.T) {
	root := tmpDir(t)
	for _, n := range []string{"a", "b", "c", "d"} {
		write(t, root+"/"+n+".pem", n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	n := 0
	err := (&Walker{}).Walk(ctx, root, func(*Entry) error { n++; cancel(); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if n != 1 {
		t.Errorf("visited %d files after cancel, want 1", n)
	}
}

func TestEntryReadAll(t *testing.T) {
	root := tmpDir(t)
	write(t, root+"/small.pem", "hello")
	write(t, root+"/big.pem", strings.Repeat("x", 2000))
	skips := map[string]Skip{}
	w := &Walker{MaxFileSize: 1000, OnSkip: func(s Skip) { skips[filepath.Base(s.Path)] = s }}
	got := map[string]string{}
	errs := map[string]error{}
	err := w.Walk(context.Background(), root, func(e *Entry) error {
		b, err := e.ReadAll()
		got[e.Name], errs[e.Name] = string(b), err
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got["small.pem"] != "hello" || errs["small.pem"] != nil {
		t.Errorf("small: %q, %v", got["small.pem"], errs["small.pem"])
	}
	if !errors.Is(errs["big.pem"], ErrSkipped) || got["big.pem"] != "" {
		t.Errorf("big: len=%d err=%v", len(got["big.pem"]), errs["big.pem"])
	}
	if s := skips["big.pem"]; s.Reason != "too-large" {
		t.Errorf("skip = %+v", s)
	}
	if w.Stats.BytesRead != 5 {
		t.Errorf("BytesRead = %d, want 5", w.Stats.BytesRead)
	}
}

// 確認（lstat）と読み取りの間にファイルがシンボリックリンクへ差し替えられても、リンク先を読まない。
func TestEntryReadAllDetectsSwapToSymlink(t *testing.T) {
	root := tmpDir(t)
	write(t, root+"/a.pem", "original")
	outside := tmpDir(t)
	write(t, outside+"/secret", "SECRET")
	var data []byte
	var rerr error
	skips := 0
	w := &Walker{OnSkip: func(Skip) { skips++ }}
	w.Walk(context.Background(), root, func(e *Entry) error {
		os.Remove(root + "/a.pem")
		os.Symlink(outside+"/secret", root+"/a.pem")
		data, rerr = e.ReadAll()
		return nil
	})
	if !errors.Is(rerr, ErrSkipped) || len(data) != 0 || skips != 1 {
		t.Errorf("data=%q err=%v skips=%d; want skipped without reading the link target", data, rerr, skips)
	}
}

func TestMountTableByDevice(t *testing.T) {
	mounts, _ := ParseMountInfo(strings.NewReader(sampleMountInfo))
	tbl := NewMountTable(mounts, DefaultPolicy())
	if v, m, ok := tbl.ByDevice(8, 1); !ok || v != Allow || m.MountPoint != "/boot" {
		t.Errorf("ByDevice(8,1) = %v %+v %v", v, m, ok)
	}
	if v, _, ok := tbl.ByDevice(0, 45); !ok || v != SkipNetworkFS {
		t.Errorf("ByDevice(0,45) = %v %v", v, ok)
	}
	if _, _, ok := tbl.ByDevice(9, 9); ok {
		t.Error("ByDevice for unknown device must report not found")
	}
}

// zfsMounts は、すべての場所が ZFS の上にあることにする。
type zfsMounts struct{}

func (zfsMounts) Check(p string) (Verdict, Mount) {
	return Allow, Mount{MountPoint: "/", FSType: "zfs", Major: 8, Minor: 1}
}
func (zfsMounts) ByDevice(major, minor uint32) (Verdict, Mount, bool) {
	return Allow, Mount{}, false
}

// ZFS の .zfs（スナップショットの入口）には入らない。開くと、カーネルがスナップショットを自動でマウントする
// （＝システムのマウントの状態を変える）ため（独立したレビューの指摘 A-10）。ZFS 以外では、同じ名前でもふつうのディレクトリ。
func TestWalkSkipsZFSSnapshotDirectory(t *testing.T) {
	root := tmpDir(t)
	write(t, root+"/.zfs/snapshot/daily/etc/a.pem", "x")
	write(t, root+"/keep/b.pem", "x")
	res := run(t, &Walker{Mounts: zfsMounts{}, devOf: fakeDevice}, root)
	if strings.Join(res.files, ",") != "/keep/b.pem" {
		t.Errorf("files = %v", res.files)
	}
	if s := res.skips["/.zfs"]; s.Reason != "pseudo-fs" {
		t.Errorf("skip record = %+v", s)
	}
	res = run(t, &Walker{Mounts: &fakeMounts{}, devOf: fakeDevice}, root)
	if len(res.files) != 2 {
		t.Errorf("on other filesystems a directory named .zfs is an ordinary one: %v", res.files)
	}
}
