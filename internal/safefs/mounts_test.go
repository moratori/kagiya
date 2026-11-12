package safefs

import (
	"strings"
	"testing"
)

const sampleMountInfo = `22 28 0:21 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
23 28 0:22 / /proc rw,nosuid,nodev,noexec,relatime shared:14 - proc proc rw
28 1 253:0 / / rw,relatime shared:1 - xfs /dev/mapper/rhel-root rw,attr2,inode64
40 28 8:1 / /boot rw,relatime shared:20 - ext4 /dev/sda1 rw
50 28 0:45 / /mnt/share rw,relatime shared:30 - nfs4 filer01:/export/share rw,vers=4.2,addr=10.0.0.5
51 28 0:46 / /mnt/win\040share rw,relatime shared:31 - cifs //fs01/dept rw,vers=3.0
52 28 0:47 / /net rw,relatime shared:32 - autofs /etc/auto.net rw,fd=5,indirect
53 28 0:48 / /home/alice/remote rw,nosuid,nodev - fuse.sshfs alice@host:/ rw,user_id=1000
54 28 0:49 / /opt/weird rw - fuse.somethingnew src rw
55 50 8:17 / /mnt/share/localdisk rw,relatime - ext4 /dev/sdb1 rw
56 28 0:50 / /run rw,nosuid,nodev - tmpfs tmpfs rw,mode=755
57 28 8:33 /sub /data rw master:5 propagate_from:2 - btrfs /dev/sdc1 rw
`

func TestParseMountInfo(t *testing.T) {
	mounts, err := ParseMountInfo(strings.NewReader(sampleMountInfo))
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 12 {
		t.Fatalf("got %d mounts, want 12", len(mounts))
	}
	root := mounts[2]
	if root.ID != 28 || root.ParentID != 1 || root.Major != 253 || root.Minor != 0 ||
		root.MountPoint != "/" || root.FSType != "xfs" || root.Source != "/dev/mapper/rhel-root" {
		t.Errorf("root mount parsed wrongly: %+v", root)
	}
	// 8進エスケープ（空白）の復元
	if got := mounts[5].MountPoint; got != "/mnt/win share" {
		t.Errorf("escaped mount point = %q, want %q", got, "/mnt/win share")
	}
	// 任意個のオプションフィールド（master:5 propagate_from:2）を読み飛ばせる
	last := mounts[11]
	if last.FSType != "btrfs" || last.Root != "/sub" || last.MountPoint != "/data" {
		t.Errorf("mount with multiple optional fields parsed wrongly: %+v", last)
	}
}

func TestParseMountInfoRejectsMalformed(t *testing.T) {
	for _, in := range []string{
		"28 1 253:0 / / rw,relatime shared:1 xfs /dev/x rw\n", // 区切り " - " がない
		"x 1 253:0 / / rw - xfs /dev/x rw\n",                  // ID が数値でない
		"28 1 253 / / rw - xfs /dev/x rw\n",                   // major:minor が不正
	} {
		if _, err := ParseMountInfo(strings.NewReader(in)); err == nil {
			t.Errorf("expected error for %q", in)
		}
	}
}

func TestClassify(t *testing.T) {
	p := DefaultPolicy()
	cases := map[string]Verdict{
		"xfs": Allow, "ext4": Allow, "btrfs": Allow, "tmpfs": Allow, "overlay": Allow,
		"nfs": SkipNetworkFS, "nfs4": SkipNetworkFS, "cifs": SkipNetworkFS, "smb3": SkipNetworkFS,
		"ceph": SkipNetworkFS, "glusterfs": SkipNetworkFS, "fuse.glusterfs": SkipNetworkFS,
		"lustre": SkipNetworkFS, "9p": SkipNetworkFS, "fuse.sshfs": SkipNetworkFS, "davfs": SkipNetworkFS,
		"autofs": SkipAutomount,
		"proc":   SkipPseudoFS, "sysfs": SkipPseudoFS, "devtmpfs": SkipPseudoFS, "cgroup2": SkipPseudoFS,
		"fuse.somethingnew": SkipUnknownFS, "brandnewfs": SkipUnknownFS, "": SkipUnknownFS,
	}
	for fs, want := range cases {
		if got := p.Classify(fs); got != want {
			t.Errorf("Classify(%q) = %v, want %v", fs, got, want)
		}
	}
}

func TestVerdictReason(t *testing.T) {
	cases := map[Verdict]string{
		Allow: "", SkipNetworkFS: "network-fs", SkipAutomount: "automount",
		SkipPseudoFS: "pseudo-fs", SkipUnknownFS: "unknown-fs",
	}
	for v, want := range cases {
		if got := v.Reason(); got != want {
			t.Errorf("Verdict(%d).Reason() = %q, want %q", v, got, want)
		}
	}
}

func TestMountTableCheck(t *testing.T) {
	mounts, err := ParseMountInfo(strings.NewReader(sampleMountInfo))
	if err != nil {
		t.Fatal(err)
	}
	tbl := NewMountTable(mounts, DefaultPolicy())

	cases := []struct {
		path   string
		want   Verdict
		fstype string // 判定根拠となったマウントの種別
	}{
		{"/", Allow, "xfs"},
		{"/etc/ssl/certs/ca.pem", Allow, "xfs"},
		{"/boot/grub", Allow, "ext4"},
		{"/mnt/share", SkipNetworkFS, "nfs4"},
		{"/mnt/share/dir/file.pem", SkipNetworkFS, "nfs4"},
		// 前方一致の境界: /mnt/share2 は /mnt/share 配下ではない
		{"/mnt/share2/file", Allow, "xfs"},
		{"/mnt/win share/x", SkipNetworkFS, "cifs"},
		{"/net", SkipAutomount, "autofs"},
		{"/net/somehost/export", SkipAutomount, "autofs"},
		{"/home/alice/remote/key", SkipNetworkFS, "fuse.sshfs"},
		{"/home/alice/.ssh/id_rsa", Allow, "xfs"},
		{"/opt/weird/x", SkipUnknownFS, "fuse.somethingnew"},
		// ネットワークFS配下にマウントされたローカルFS: 到達に NFS を経由するためスキップ
		{"/mnt/share/localdisk/file", SkipNetworkFS, "nfs4"},
		{"/proc/1/exe", SkipPseudoFS, "proc"},
		{"/run/secrets", Allow, "tmpfs"},
		{"/data/x", Allow, "btrfs"},
	}
	for _, c := range cases {
		got, m := tbl.Check(c.path)
		if got != c.want || m.FSType != c.fstype {
			t.Errorf("Check(%q) = (%v, %s), want (%v, %s)", c.path, got, m.FSType, c.want, c.fstype)
		}
	}
}

func TestMountTableCheckRequiresCleanAbsolutePath(t *testing.T) {
	mounts, _ := ParseMountInfo(strings.NewReader(sampleMountInfo))
	tbl := NewMountTable(mounts, DefaultPolicy())
	// 相対パスや ".." を含むパスは判定をすり抜け得るので、安全側（不明）に倒す
	for _, p := range []string{"relative/path", "/etc/../mnt/share/x", "", "/etc//ssl"} {
		if got, _ := tbl.Check(p); got != SkipUnknownFS {
			t.Errorf("Check(%q) = %v, want SkipUnknownFS", p, got)
		}
	}
}

// 同じマウントポイントに重ねてマウントされた場合は、後のもの（最上位）が有効。
func TestMountTableOvermount(t *testing.T) {
	in := `28 1 253:0 / / rw - xfs /dev/root rw
60 28 0:60 / /srv rw - autofs /etc/auto.srv rw,direct
61 60 0:61 / /srv rw - nfs4 filer:/srv rw
70 28 8:49 / /var rw - ext4 /dev/sdd1 rw
`
	mounts, err := ParseMountInfo(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	tbl := NewMountTable(mounts, DefaultPolicy())
	got, m := tbl.Check("/srv/www")
	if got != SkipNetworkFS || m.FSType != "nfs4" {
		t.Errorf("Check(/srv/www) = (%v, %s), want (SkipNetworkFS, nfs4)", got, m.FSType)
	}
	if got, _ := tbl.Check("/var/log"); got != Allow {
		t.Errorf("Check(/var/log) = %v, want Allow", got)
	}
}
