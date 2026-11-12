// Package safefs はスキャン対象のファイルに触れる唯一の経路。
// ネットワークファイルシステム等、触れると通信が起き得る場所を「触れる前に」判定する。
package safefs

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Mount は /proc/self/mountinfo の1行。
type Mount struct {
	ID, ParentID int
	Major, Minor uint32
	Root         string // マウント元ファイルシステム内でのルート
	MountPoint   string
	FSType       string
	Source       string
}

// ParseMountInfo は /proc/<pid>/mountinfo 形式を読む。
// 形式: ID 親ID major:minor root mountpoint オプション [任意フィールド...] - 種別 ソース スーパーオプション
func ParseMountInfo(r io.Reader) ([]Mount, error) {
	var mounts []Mount
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		if strings.TrimSpace(text) == "" {
			continue
		}
		m, err := parseMountInfoLine(text)
		if err != nil {
			return nil, fmt.Errorf("mountinfo line %d: %w", line, err)
		}
		mounts = append(mounts, m)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return mounts, nil
}

func parseMountInfoLine(text string) (Mount, error) {
	var m Mount
	f := strings.Fields(text)
	sep := -1
	for i := 6; i < len(f); i++ {
		if f[i] == "-" {
			sep = i
			break
		}
	}
	if sep < 0 || len(f) < sep+3 {
		return m, fmt.Errorf("malformed line")
	}
	var err error
	if m.ID, err = strconv.Atoi(f[0]); err != nil {
		return m, fmt.Errorf("bad mount ID")
	}
	if m.ParentID, err = strconv.Atoi(f[1]); err != nil {
		return m, fmt.Errorf("bad parent ID")
	}
	maj, min, ok := strings.Cut(f[2], ":")
	if !ok {
		return m, fmt.Errorf("bad device number")
	}
	majN, err1 := strconv.ParseUint(maj, 10, 32)
	minN, err2 := strconv.ParseUint(min, 10, 32)
	if err1 != nil || err2 != nil {
		return m, fmt.Errorf("bad device number")
	}
	m.Major, m.Minor = uint32(majN), uint32(minN)
	m.Root = unescapeMountField(f[3])
	m.MountPoint = unescapeMountField(f[4])
	m.FSType = f[sep+1]
	m.Source = unescapeMountField(f[sep+2])
	return m, nil
}

// unescapeMountField は \040（空白）等の3桁8進エスケープを復元する。
func unescapeMountField(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Verdict はあるパスに触れてよいかの判定。
type Verdict int

const (
	Allow Verdict = iota
	SkipNetworkFS
	SkipAutomount
	SkipPseudoFS
	SkipUnknownFS
)

// Reason は結果 JSON の skipped[].reason に使う理由コード。Allow は空文字列。
func (v Verdict) Reason() string {
	switch v {
	case SkipNetworkFS:
		return "network-fs"
	case SkipAutomount:
		return "automount"
	case SkipPseudoFS:
		return "pseudo-fs"
	case SkipUnknownFS:
		return "unknown-fs"
	}
	return ""
}

func (v Verdict) String() string {
	if v == Allow {
		return "allow"
	}
	return v.Reason()
}

// Policy はファイルシステム種別の分類表。どれにも載っていない種別は不明として読まない（安全側）。
type Policy struct {
	Local, Network, Automount, Pseudo map[string]bool
}

func set(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// DefaultPolicy は内包の分類表。
func DefaultPolicy() Policy {
	return Policy{
		Local: set(
			"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs", "reiserfs", "bcachefs",
			"tmpfs", "ramfs", "vfat", "msdos", "exfat", "ntfs", "ntfs3", "fuseblk",
			"iso9660", "udf", "squashfs", "erofs", "overlay", "ecryptfs",
		),
		Network: set(
			"nfs", "nfs3", "nfs4", "cifs", "smb", "smb2", "smb3", "smbfs",
			"ceph", "fuse.ceph", "fuse.ceph-fuse", "glusterfs", "fuse.glusterfs",
			"lustre", "gpfs", "beegfs", "9p", "afs", "coda", "ncpfs", "ncp",
			"davfs", "davfs2", "fuse.davfs2", "pvfs2", "orangefs", "ocfs2", "gfs2",
			"fuse.sshfs", "fuse.s3fs", "fuse.rclone", "fuse.gcsfuse", "fuse.blobfuse", "fuse.blobfuse2",
			"fuse.gvfsd-fuse",
			// ハイパーバイザの共有フォルダ: 実体がホスト側のネットワーク共有であり得る
			"virtiofs", "vboxsf", "vmhgfs", "fuse.vmhgfs-fuse",
		),
		Automount: set("autofs"),
		Pseudo: set(
			"proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "securityfs", "debugfs",
			"tracefs", "pstore", "bpf", "configfs", "fusectl", "mqueue", "hugetlbfs", "binfmt_misc",
			"selinuxfs", "efivarfs", "rpc_pipefs", "nsfs", "fuse.lxcfs", "fuse.portal",
		),
	}
}

// Classify は種別ひとつを分類する。
func (p Policy) Classify(fstype string) Verdict {
	switch {
	case p.Network[fstype]:
		return SkipNetworkFS
	case p.Automount[fstype]:
		return SkipAutomount
	case p.Pseudo[fstype]:
		return SkipPseudoFS
	case p.Local[fstype]:
		return Allow
	}
	return SkipUnknownFS
}

// MountTable はパスからマウントを引き、触れてよいかを判定する。
type MountTable struct {
	mounts []Mount
	byID   map[int]int // マウント ID → mounts の添字
	policy Policy
}

func NewMountTable(mounts []Mount, p Policy) *MountTable {
	t := &MountTable{mounts: mounts, byID: make(map[int]int, len(mounts)), policy: p}
	for i, m := range mounts {
		t.byID[m.ID] = i
	}
	return t
}

// Check は、絶対かつ正規化済みのパスについて判定と、その根拠となったマウントを返す。
// システムコールは発行しない。パス自身のマウントが許可でも、そこへ至る親マウントに
// ネットワークFS・自動マウントがあればスキップとする（到達に通信を伴うため）。
func (t *MountTable) Check(path string) (Verdict, Mount) {
	if !isCleanAbs(path) {
		return SkipUnknownFS, Mount{}
	}
	idx := -1
	for i, m := range t.mounts {
		if !underMountPoint(path, m.MountPoint) {
			continue
		}
		// より深いマウントポイントを優先。同じ深さなら後に現れたもの（重ねマウントの最上位）。
		if idx < 0 || len(m.MountPoint) >= len(t.mounts[idx].MountPoint) {
			idx = i
		}
	}
	if idx < 0 {
		return SkipUnknownFS, Mount{}
	}
	own := t.mounts[idx]
	verdict, basis := t.policy.Classify(own.FSType), own

	// 親マウントをルート側へ辿る。最もルートに近い通信系マウントを根拠とする。
	seen := map[int]bool{own.ID: true}
	cur := own
	for {
		pi, ok := t.byID[cur.ParentID]
		if !ok || seen[t.mounts[pi].ID] {
			break
		}
		cur = t.mounts[pi]
		seen[cur.ID] = true
		if v := t.policy.Classify(cur.FSType); v == SkipNetworkFS || v == SkipAutomount {
			if cur.MountPoint == basis.MountPoint && (verdict == SkipNetworkFS || verdict == SkipAutomount) {
				continue // 同じ場所への重ねマウントは最上位を根拠のままにする
			}
			verdict, basis = v, cur
		}
	}
	return verdict, basis
}

func isCleanAbs(p string) bool {
	if p == "/" {
		return true
	}
	if !strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return false
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

func underMountPoint(path, mp string) bool {
	if mp == "/" {
		return true
	}
	return path == mp || strings.HasPrefix(path, mp+"/")
}

// ByDevice はデバイス番号からマウントを引き、その種別の判定を返す。
func (t *MountTable) ByDevice(major, minor uint32) (Verdict, Mount, bool) {
	for i := len(t.mounts) - 1; i >= 0; i-- {
		if m := t.mounts[i]; m.Major == major && m.Minor == minor {
			return t.policy.Classify(m.FSType), m, true
		}
	}
	return SkipUnknownFS, Mount{}, false
}
