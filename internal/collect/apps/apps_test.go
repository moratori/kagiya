//go:build unix

package apps

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kagiya/internal/inventory"
	"kagiya/internal/logx"
	"kagiya/internal/model"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

func collect(t *testing.T, name string, prepare func(prefix string, b *inventory.Builder)) (string, *model.Inventory) {
	t.Helper()
	prefix, _ := filepath.EvalSymlinks(t.TempDir())
	if name != "" {
		src := filepath.Join("testdata", name)
		filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
			rel, _ := filepath.Rel(src, p)
			if d.IsDir() {
				return os.MkdirAll(filepath.Join(prefix, rel), 0o755)
			}
			b, _ := os.ReadFile(p)
			return os.WriteFile(filepath.Join(prefix, rel), b, 0o644)
		})
	}
	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	b := inventory.NewBuilder(rs, logx.New(io.Discard, time.Now))
	if prepare != nil {
		prepare(prefix, b)
	}
	(&Collector{Prefix: prefix, Opener: &safefs.Opener{OnSkip: b.Skip}, Builder: b, Rules: rs}).Collect()
	return prefix, b.Inventory()
}

// link は、サービスの有効化を表すリンクを実物と同じ形に作る。
func link(t *testing.T, prefix, target, linkPath string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(prefix+linkPath), 0o755)
	if err := os.Symlink(target, prefix+linkPath); err != nil {
		t.Fatal(err)
	}
}

func find(inv *model.Inventory, param string) []model.Setting {
	var out []model.Setting
	for _, s := range inv.Settings {
		if s.Parameter == param {
			out = append(out, s)
		}
	}
	return out
}

func effective(t *testing.T, inv *model.Inventory, param string) model.Setting {
	t.Helper()
	var out []model.Setting
	for _, s := range find(inv, param) {
		if s.Effective {
			out = append(out, s)
		}
	}
	if len(out) != 1 {
		t.Fatalf("%s: %d effective settings, want 1 (all: %+v)", param, len(out), find(inv, param))
	}
	return out[0]
}

// RHEL 8.10: 暗号ポリシーは sshd の起動引数として渡され、sshd_config の記載より優先される。
// 期待値は、同じ環境で `sshd -T $CRYPTO_POLICY` が報告した値。
func TestOpenSSHRHEL8(t *testing.T) {
	prefix, inv := collect(t, "rhel8", func(p string, b *inventory.Builder) {
		link(t, p, "/usr/lib/systemd/system/sshd.service", "/etc/systemd/system/multi-user.target.wants/sshd.service")
	})
	if len(inv.Services) != 1 {
		t.Fatalf("services = %+v", inv.Services)
	}
	svc := inv.Services[0]
	if svc.App != "openssh" || svc.Activity.Level != "enabled" || len(svc.Activity.Evidence) == 0 ||
		svc.Activity.Evidence[0].Path != prefix+"/etc/systemd/system/multi-user.target.wants/sshd.service" {
		t.Errorf("service = %+v", svc)
	}
	c := effective(t, inv, "ssh.ciphers")
	if strings.Join(c.Values, ",") != "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes256-cbc,aes128-gcm@openssh.com,aes128-ctr,aes128-cbc" {
		t.Errorf("ciphers = %v", c.Values)
	}
	if c.Layer != "os-policy" || c.Source != "command-line" || c.Direction != "inbound" || c.Basis != "configured" ||
		c.Location.Path != prefix+"/etc/crypto-policies/back-ends/opensshserver.config" || c.Location.Line != 1 || c.Service != svc.ID {
		t.Errorf("ciphers setting = %+v", c)
	}
	if k := effective(t, inv, "ssh.kex-algorithms"); k.Values[0] != "curve25519-sha256" || k.Source != "command-line" {
		t.Errorf("kex = %+v", k)
	}
	keys := find(inv, "ssh.host-key")
	if len(keys) != 3 || keys[0].Basis != "configured" || keys[0].Values[0] != "/etc/ssh/ssh_host_rsa_key" || !keys[0].Effective {
		t.Errorf("host keys = %+v", keys)
	}
	if len(inv.Skipped) != 0 {
		t.Errorf("skipped = %+v", inv.Skipped)
	}
}

// RHEL 8.10 の落とし穴: sshd_config に Ciphers を書いても、起動引数で渡されるポリシーが優先されて効かない。
func TestOpenSSHRHEL8ConfigIsShadowedByPolicy(t *testing.T) {
	_, inv := collect(t, "rhel8", func(p string, b *inventory.Builder) {
		f, _ := os.OpenFile(p+"/etc/ssh/sshd_config", os.O_APPEND|os.O_WRONLY, 0)
		f.WriteString("Ciphers aes128-ctr\n")
		f.Close()
	})
	all := find(inv, "ssh.ciphers")
	if len(all) != 2 {
		t.Fatalf("ciphers settings = %+v", all)
	}
	eff := effective(t, inv, "ssh.ciphers")
	if eff.Source != "command-line" || len(eff.Values) != 7 {
		t.Errorf("effective = %+v", eff)
	}
	for _, s := range all {
		if s.Source == "config-file" && (s.Effective || s.Values[0] != "aes128-ctr" || s.Layer != "app-config") {
			t.Errorf("shadowed setting = %+v", s)
		}
	}
	// 有効化のリンクがなければ「導入のみ」
	if inv.Services[0].Activity.Level != "installed" {
		t.Errorf("activity = %+v", inv.Services[0].Activity)
	}
}

// RHEL 8.10: /etc/sysconfig/sshd で CRYPTO_POLICY を空にすると、ポリシーから外れる（実物のコメントにある手順）。
func TestOpenSSHRHEL8OptOut(t *testing.T) {
	_, inv := collect(t, "rhel8", func(p string, b *inventory.Builder) {
		f, _ := os.OpenFile(p+"/etc/sysconfig/sshd", os.O_APPEND|os.O_WRONLY, 0)
		f.WriteString("CRYPTO_POLICY=\n")
		f.Close()
	})
	if s := find(inv, "ssh.ciphers"); len(s) != 0 {
		t.Errorf("ciphers must not be configured after opting out: %+v", s)
	}
}

// RHEL 9.9: ポリシーは sshd_config.d/50-redhat.conf からの Include で、設定ファイルとして読み込まれる。
func TestOpenSSHRHEL9(t *testing.T) {
	prefix, inv := collect(t, "rhel9", func(p string, b *inventory.Builder) {
		link(t, p, "/usr/lib/systemd/system/sshd.service", "/etc/systemd/system/multi-user.target.wants/sshd.service")
	})
	c := effective(t, inv, "ssh.ciphers")
	if strings.Join(c.Values, ",") != "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr" {
		t.Errorf("ciphers = %v", c.Values)
	}
	if c.Layer != "os-policy" || c.Source != "config-file" || c.Location.Path != prefix+"/etc/crypto-policies/back-ends/opensshserver.config" {
		t.Errorf("ciphers setting = %+v", c)
	}
	if r := effective(t, inv, "ssh.required-rsa-size"); r.Values[0] != "2048" {
		t.Errorf("RequiredRSASize = %+v", r)
	}
	// HostKey の記載がないので、sshd の既定の場所を参照先として記録する
	keys := find(inv, "ssh.host-key")
	if len(keys) != 3 || keys[0].Basis != "default" || keys[2].Values[0] != "/etc/ssh/ssh_host_ed25519_key" {
		t.Errorf("host keys = %+v", keys)
	}
	if inv.Services[0].Activity.Level != "enabled" || len(inv.Skipped) != 0 {
		t.Errorf("service = %+v skipped = %+v", inv.Services[0], inv.Skipped)
	}
}

// Ubuntu 24.04: サービスではなくソケット（ssh.socket）が有効化されている。暗号の設定は書かれていない。
func TestOpenSSHUbuntu2404(t *testing.T) {
	prefix, inv := collect(t, "ubuntu2404", func(p string, b *inventory.Builder) {
		link(t, p, "/lib/systemd/system/ssh.socket", "/etc/systemd/system/sockets.target.wants/ssh.socket")
	})
	svc := inv.Services[0]
	if svc.Activity.Level != "enabled" || svc.Activity.Evidence[0].Path != prefix+"/etc/systemd/system/sockets.target.wants/ssh.socket" {
		t.Errorf("service = %+v", svc)
	}
	for _, s := range inv.Settings {
		if s.Parameter != "ssh.host-key" {
			t.Errorf("unexpected setting %+v", s)
		}
	}
	if len(find(inv, "ssh.host-key")) != 3 {
		t.Errorf("host keys = %+v", find(inv, "ssh.host-key"))
	}
}

// Ubuntu 16.04: HostKey が4つ明記されている（DSA を含む）。
func TestOpenSSHUbuntu1604(t *testing.T) {
	_, inv := collect(t, "ubuntu1604", func(p string, b *inventory.Builder) {
		link(t, p, "/lib/systemd/system/ssh.service", "/etc/systemd/system/multi-user.target.wants/ssh.service")
	})
	keys := find(inv, "ssh.host-key")
	if len(keys) != 4 || keys[1].Values[0] != "/etc/ssh/ssh_host_dsa_key" || keys[1].Basis != "configured" {
		t.Errorf("host keys = %+v", keys)
	}
	if inv.Services[0].Activity.Level != "enabled" {
		t.Errorf("activity = %+v", inv.Services[0].Activity)
	}
}

// 同じ項目が複数あるときは最初のものが有効。Match ブロックの中は条件付きの設定として区別する。
func TestOpenSSHFirstValueWinsAndMatchScope(t *testing.T) {
	_, inv := collect(t, "", func(p string, b *inventory.Builder) {
		os.MkdirAll(p+"/etc/ssh", 0o755)
		os.WriteFile(p+"/etc/ssh/sshd_config", []byte("Ciphers aes256-ctr\nCiphers aes128-ctr\nKexAlgorithms +diffie-hellman-group1-sha1\nMatch User legacy\n  Ciphers 3des-cbc\n"), 0o644)
	})
	all := find(inv, "ssh.ciphers")
	if len(all) != 3 || !all[0].Effective || all[1].Effective || all[2].Effective || all[2].Scope != "Match User legacy" || all[0].Scope != "" {
		t.Errorf("ciphers = %+v", all)
	}
	// 既定の一覧への追加・削除（+ - ^）は、そのまま区別して記録する
	if k := effective(t, inv, "ssh.kex-algorithms"); k.Modifier != "+" || k.Values[0] != "diffie-hellman-group1-sha1" {
		t.Errorf("kex = %+v", k)
	}
	// 設定ファイルはあるがバイナリも有効化も見つからない
	if inv.Services[0].Activity.Level != "unknown" {
		t.Errorf("activity = %+v", inv.Services[0].Activity)
	}
}

// 設定値として妥当でない値は出力しない。
func TestOpenSSHSuspiciousValuesAreNotEmitted(t *testing.T) {
	_, inv := collect(t, "", func(p string, b *inventory.Builder) {
		os.MkdirAll(p+"/etc/ssh", 0o755)
		os.WriteFile(p+"/etc/ssh/sshd_config", []byte("Ciphers aes256-ctr;$(id)\nHostKey relative/path\nBanner /etc/secret-banner\nRequiredRSASize lots\n"), 0o644)
	})
	for _, s := range inv.Settings {
		if s.Basis == "configured" {
			t.Errorf("unexpected setting: %+v", s)
		}
	}
	if len(inv.Skipped) != 3 {
		t.Errorf("skipped = %+v", inv.Skipped)
	}
}

// マスクされたユニット（/dev/null へのリンク）は起動しない。
func TestOpenSSHMaskedUnit(t *testing.T) {
	_, inv := collect(t, "rhel9", func(p string, b *inventory.Builder) {
		link(t, p, "/usr/lib/systemd/system/sshd.service", "/etc/systemd/system/multi-user.target.wants/sshd.service")
		link(t, p, "/dev/null", "/etc/systemd/system/sshd.service")
	})
	a := inv.Services[0].Activity
	if a.Level != "installed" || len(a.Evidence) == 0 || a.Evidence[0].Kind != "unit-masked" {
		t.Errorf("activity = %+v", a)
	}
}

// 設定から参照されている鍵には、そのサービスの「利用の確からしさ」が付く。参照されていない鍵には付かない。
func TestActivityOfReferencedKeys(t *testing.T) {
	var hostKey, stray string
	_, inv := collect(t, "rhel9", func(p string, b *inventory.Builder) {
		link(t, p, "/usr/lib/systemd/system/sshd.service", "/etc/systemd/system/multi-user.target.wants/sshd.service")
		hostKey, stray = p+"/etc/ssh/ssh_host_ed25519_key", p+"/root/old_key"
		b.Asset("key:private:test1", func() model.Asset { return model.Asset{Type: "private-key"} })
		b.Occur("key:private:test1", "fscrawl", model.Location{Kind: "file", Path: hostKey}, nil)
		b.Asset("key:private:test2", func() model.Asset { return model.Asset{Type: "private-key"} })
		b.Occur("key:private:test2", "fscrawl", model.Location{Kind: "file", Path: stray}, nil)
	})
	got := map[string]*model.Activity{}
	for _, o := range inv.Occurrences {
		got[o.Location.Path] = o.Activity
	}
	a := got[hostKey]
	if a == nil || a.Level != "enabled" || len(a.Evidence) == 0 || a.Evidence[0].Kind != "config-reference" || a.Evidence[0].Detail != "ssh.host-key" {
		t.Errorf("host key activity = %+v", a)
	}
	if a := got[stray]; a == nil || a.Level != "unknown" {
		t.Errorf("stray key activity = %+v", a)
	}
}

func TestNothingInstalled(t *testing.T) {
	_, inv := collect(t, "", nil)
	if len(inv.Services) != 0 || len(inv.Settings) != 0 || len(inv.Skipped) != 0 {
		t.Errorf("inv = %+v", inv)
	}
}
