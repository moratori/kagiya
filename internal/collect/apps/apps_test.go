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

// service は、指定したアプリのサービスを返す（同じテストデータに複数のアプリの設定が入っているため）。
func service(t *testing.T, inv *model.Inventory, app string) model.Service {
	t.Helper()
	for _, s := range inv.Services {
		if s.App == app {
			return s
		}
	}
	t.Fatalf("service %s not found in %+v", app, inv.Services)
	return model.Service{}
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
	svc := service(t, inv, "openssh")
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
	if service(t, inv, "openssh").Activity.Level != "installed" {
		t.Errorf("activity = %+v", service(t, inv, "openssh").Activity)
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
	if service(t, inv, "openssh").Activity.Level != "enabled" || len(inv.Skipped) != 0 {
		t.Errorf("service = %+v skipped = %+v", service(t, inv, "openssh"), inv.Skipped)
	}
}

// Ubuntu 24.04: サービスではなくソケット（ssh.socket）が有効化されている。暗号の設定は書かれていない。
func TestOpenSSHUbuntu2404(t *testing.T) {
	prefix, inv := collect(t, "ubuntu2404", func(p string, b *inventory.Builder) {
		link(t, p, "/lib/systemd/system/ssh.socket", "/etc/systemd/system/sockets.target.wants/ssh.socket")
	})
	svc := service(t, inv, "openssh")
	if svc.Activity.Level != "enabled" || svc.Activity.Evidence[0].Path != prefix+"/etc/systemd/system/sockets.target.wants/ssh.socket" {
		t.Errorf("service = %+v", svc)
	}
	for _, s := range inv.Settings {
		if s.Service == svc.ID && s.Parameter != "ssh.host-key" {
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
	if service(t, inv, "openssh").Activity.Level != "enabled" {
		t.Errorf("activity = %+v", service(t, inv, "openssh").Activity)
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
	if service(t, inv, "openssh").Activity.Level != "unknown" {
		t.Errorf("activity = %+v", service(t, inv, "openssh").Activity)
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
	a := service(t, inv, "openssh").Activity
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

func byParam(inv *model.Inventory, service string) map[string][]model.Setting {
	out := map[string][]model.Setting{}
	for _, s := range inv.Settings {
		if s.Service == service {
			key := s.Direction + ":" + s.Parameter
			out[key] = append(out[key], s)
		}
	}
	return out
}

func values(ss []model.Setting) string {
	var out []string
	for _, s := range ss {
		out = append(out, strings.Join(s.Values, " "))
	}
	return strings.Join(out, " | ")
}

// RHEL 9.9 の nginx: 既定の設定には TLS の設定がない。TLS のサーバーを足した場合の読み取りを確かめる。
func TestNginxRHEL9(t *testing.T) {
	prefix, inv := collect(t, "rhel9", nil)
	if s := byParam(inv, "svc:nginx"); len(s) != 0 {
		t.Errorf("default nginx.conf has no TLS settings, got %v", s)
	}
	prefix, inv = collect(t, "rhel9", func(p string, b *inventory.Builder) {
		os.MkdirAll(p+"/etc/nginx/conf.d", 0o755)
		os.WriteFile(p+"/etc/nginx/conf.d/tls.conf", []byte(`server {
    listen 443 ssl http2;
    listen 8080;
    server_name www.example.jp;
    ssl_certificate /etc/pki/tls/certs/www.crt;
    ssl_certificate_key /etc/pki/tls/private/www.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers PROFILE=SYSTEM;
    ssl_ecdh_curve X25519:prime256v1;
    ssl_prefer_server_ciphers on;
    ssl_password_file /etc/nginx/secret.pass;
    location / {
        proxy_pass https://backend.internal;
        proxy_ssl_protocols TLSv1.2;
        proxy_ssl_ciphers HIGH:!aNULL;
        proxy_ssl_certificate /etc/nginx/client.crt;
        proxy_ssl_certificate_key $client_key_path;
    }
}
`), 0o644)
	})
	s := byParam(inv, "svc:nginx")
	scope := "server www.example.jp"
	check := func(key, want string) {
		t.Helper()
		ss := s[key]
		if len(ss) != 1 || values(ss) != want || ss[0].Scope != scope || !ss[0].Effective || ss[0].Basis != "configured" || ss[0].Layer != "app-config" {
			t.Errorf("%s = %q (%+v), want %q", key, values(ss), ss, want)
		}
	}
	check("inbound:tls.listen", "443 ssl http2") // TLS を使う待ち受けだけを記録する
	check("inbound:tls.protocols", "TLSv1.2 TLSv1.3")
	check("inbound:tls.ciphers", "PROFILE=SYSTEM")
	check("inbound:tls.groups", "X25519 prime256v1")
	check("inbound:tls.prefer-server-ciphers", "on")
	check("inbound:tls.certificate", "/etc/pki/tls/certs/www.crt")
	check("inbound:tls.private-key", "/etc/pki/tls/private/www.key")
	// 上流への接続（送信側）は方向を区別する
	check("outbound:tls.protocols", "TLSv1.2")
	check("outbound:tls.ciphers", "HIGH !aNULL")
	check("outbound:tls.certificate", "/etc/nginx/client.crt")
	if c := s["inbound:tls.certificate"][0]; c.Location.Path != prefix+"/etc/nginx/conf.d/tls.conf" || c.Location.Line != 5 || c.ReferencedPaths[0] != prefix+"/etc/pki/tls/certs/www.crt" {
		t.Errorf("certificate setting = %+v", c)
	}
	// 変数を含むパスは、どのファイルか分からないので記録しない（問題としては数えない）
	if _, ok := s["outbound:tls.private-key"]; ok {
		t.Error("a path containing a variable must not be recorded")
	}
	// 許可リストにない項目（パスワードファイルなど）は記録しない
	for _, st := range inv.Settings {
		if strings.Contains(strings.Join(st.Values, " "), "secret.pass") {
			t.Errorf("unexpected setting %+v", st)
		}
	}
	reasons := map[string]int{}
	for _, k := range inv.Skipped {
		reasons[k.Reason]++
	}
	if reasons["not-interpreted"] != 1 || len(inv.Skipped) != 1 {
		t.Errorf("skipped = %+v", inv.Skipped)
	}
}

// Ubuntu 24.04 の nginx: http の階層に ssl_protocols と ssl_prefer_server_ciphers が書かれている（実物）。
func TestNginxUbuntu2404(t *testing.T) {
	_, inv := collect(t, "ubuntu2404", func(p string, b *inventory.Builder) {
		link(t, p, "/etc/nginx/sites-available/default", "/etc/nginx/sites-enabled/default")
	})
	s := byParam(inv, "svc:nginx")
	if got := values(s["inbound:tls.protocols"]); got != "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3" || s["inbound:tls.protocols"][0].Scope != "http" {
		t.Errorf("tls.protocols = %q %+v", got, s["inbound:tls.protocols"])
	}
	if got := values(s["inbound:tls.prefer-server-ciphers"]); got != "on" {
		t.Errorf("prefer-server-ciphers = %q", got)
	}
	if len(s) != 2 {
		t.Errorf("settings = %v", s)
	}
}

// RHEL 9.9 の Apache httpd: conf.d/ssl.conf が既定で取り込まれる（実物）。
func TestApacheRHEL9(t *testing.T) {
	prefix, inv := collect(t, "rhel9", nil)
	s := byParam(inv, "svc:httpd")
	vh := "VirtualHost _default_:443"
	for key, want := range map[string]string{
		"inbound:tls.enabled":               "on",
		"inbound:tls.ciphers":               "PROFILE=SYSTEM",
		"inbound:tls.prefer-server-ciphers": "on",
		"inbound:tls.certificate":           "/etc/pki/tls/certs/localhost.crt",
		"inbound:tls.private-key":           "/etc/pki/tls/private/localhost.key",
		"outbound:tls.ciphers":              "PROFILE=SYSTEM", // SSLProxyCipherSuite
	} {
		if ss := s[key]; len(ss) != 1 || values(ss) != want || ss[0].Scope != vh {
			t.Errorf("%s = %q (%+v), want %q", key, values(ss), ss, want)
		}
	}
	if ss := s["inbound:tls.listen"]; values(ss) != "443 https" || ss[0].Scope != "" {
		t.Errorf("tls.listen = %+v", ss)
	}
	if c := s["inbound:tls.private-key"][0]; c.Location.Path != prefix+"/etc/httpd/conf.d/ssl.conf" || c.ReferencedPaths[0] != prefix+"/etc/pki/tls/private/localhost.key" {
		t.Errorf("private key setting = %+v", c)
	}
	var svc model.Service
	for _, x := range inv.Services {
		if x.App == "httpd" {
			svc = x
		}
	}
	if len(svc.Notes) != 0 {
		t.Errorf("notes = %v", svc.Notes)
	}
}

// Ubuntu 24.04 の Apache: 既定では TLS のモジュールもサイトも有効になっていない。有効にするとリンクが作られる。
func TestApacheUbuntu2404(t *testing.T) {
	_, inv := collect(t, "ubuntu2404", nil)
	if s := byParam(inv, "svc:httpd"); len(s) != 0 {
		t.Errorf("TLS is not enabled by default, got %v", s)
	}
	var notes []string
	for _, x := range inv.Services {
		if x.App == "httpd" {
			notes = x.Notes
		}
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "ssl_module") {
		t.Errorf("notes = %v", notes)
	}

	_, inv = collect(t, "ubuntu2404", func(p string, b *inventory.Builder) {
		link(t, p, "../mods-available/ssl.load", "/etc/apache2/mods-enabled/ssl.load")
		link(t, p, "../mods-available/ssl.conf", "/etc/apache2/mods-enabled/ssl.conf")
		link(t, p, "../sites-available/default-ssl.conf", "/etc/apache2/sites-enabled/default-ssl.conf")
	})
	s := byParam(inv, "svc:httpd")
	if got := values(s["inbound:tls.ciphers"]); got != "HIGH !aNULL" || s["inbound:tls.ciphers"][0].Scope != "" {
		t.Errorf("tls.ciphers = %q", got)
	}
	if got := values(s["inbound:tls.protocols"]); got != "all -SSLv3" {
		t.Errorf("tls.protocols = %q", got)
	}
	if got := values(s["inbound:tls.listen"]); got != "443" { // ports.conf の <IfModule ssl_module> の中
		t.Errorf("tls.listen = %q", got)
	}
	if ss := s["inbound:tls.certificate"]; values(ss) != "/etc/ssl/certs/ssl-cert-snakeoil.pem" || ss[0].Scope != "VirtualHost *:443" {
		t.Errorf("tls.certificate = %+v", ss)
	}
	if got := values(s["inbound:tls.enabled"]); got != "on" {
		t.Errorf("tls.enabled = %q", got)
	}
}
