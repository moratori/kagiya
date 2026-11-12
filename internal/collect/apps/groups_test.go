//go:build unix

package apps

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kagiya/internal/inventory"
	"kagiya/internal/model"
)

// 以下の期待値は、検証ラボで実際に各サーバーを起動し、鍵交換のグループを1つずつ指定したハンドシェイクで
// 受け入れるかどうかを確かめた結果（RHEL 9.9 / 10.3、Ubuntu 24.04.5、Debian 13）。設定ファイルも、そのときと同じ内容。

const (
	// 暗号ポリシー（DEFAULT）が生成した、システムの openssl.cnf の Groups
	rhel9PolicyGroups  = "*X25519:secp256r1:X448:secp521r1:secp384r1:ffdhe2048:ffdhe3072:ffdhe4096:ffdhe6144:ffdhe8192"
	rhel10PolicyGroups = "*?X25519MLKEM768:?x25519_mlkem768:?SecP256r1MLKEM768:?p256_mlkem768:?SecP384r1MLKEM1024:?p384_mlkem1024/*?X25519:?secp256r1:?X448:?secp521r1:?secp384r1:?ffdhe2048:?ffdhe3072:?ffdhe4096:?ffdhe6144:?ffdhe8192"
	// RHEL 9.9 で、指定のないサーバーが受け入れたグループ（暗号ポリシーの順）
	rhel9Groups = "X25519 P-256 X448 P-521 P-384 ffdhe2048 ffdhe3072 ffdhe4096 ffdhe6144 ffdhe8192"
)

// withGroups は、システムの openssl.cnf の Groups（OS 設定のコレクタが読んだ結果）を足す。
func withGroups(groups string, prepare func(p string, b *inventory.Builder)) func(p string, b *inventory.Builder) {
	return func(p string, b *inventory.Builder) {
		if groups != "" {
			b.AddOSSetting(model.OSSetting{ID: "openssl.system_default.Groups", Value: groups, Path: "/etc/crypto-policies/back-ends/opensslcnf.config", Line: 9})
		}
		prepare(p, b)
	}
}

func groupsOf(t *testing.T, inv *model.Inventory, svc, scope string) model.EffectiveValue {
	t.Helper()
	e := eff(t, inv, svc, "tls.groups", scope)
	if e.Status != "resolved" {
		t.Fatalf("tls.groups [%s] is not resolved: %+v", scope, e)
	}
	return e
}

// 指定がなければ、システムの openssl.cnf の Groups（RHEL では暗号ポリシー）に従う。
// RHEL 9.9 のポリシーには耐量子のハイブリッドが入っていないので、OpenSSL 3.5 の既定（X25519MLKEM768 を含む）にはならない。
func TestGroupsFollowSystemPolicy(t *testing.T) {
	nginx := map[string]string{nginxConf: "server { listen 127.0.0.1:8443 ssl; server_name default.lab.test; " + nginxCerts + " }\n"}
	_, inv := collect(t, "rhel9", withGroups(rhel9PolicyGroups, rhel9Web(t, "3.5.9", "1.el9_9", nginx)))
	e := groupsOf(t, inv, "svc:nginx", "server default.lab.test")
	if strings.Join(e.Values, " ") != rhel9Groups || e.Confidence != "high" || e.Direction != "inbound" {
		t.Errorf("RHEL 9 nginx groups = %+v", e)
	}
	if layers(e) != "os-policy/override library/expand os-policy/security-level" {
		t.Errorf("steps = %s", layers(e))
	}
	if s := e.Steps[1].Source; s == nil || s.Package != "openssl-libs" || s.Version != "3.5.9-1.el9_9" {
		t.Errorf("library source = %+v", e.Steps[1].Source)
	}

	// RHEL 10.3 のポリシーは、ハイブリッドを先頭に足している。ライブラリが知らない別名（?x25519_mlkem768 など）は無視される
	_, inv = collect(t, "rhel9", withGroups(rhel10PolicyGroups, rhel9Web(t, "3.5.9", "1.el10_3", nginx)))
	e = groupsOf(t, inv, "svc:nginx", "server default.lab.test")
	if strings.Join(e.Values, " ") != "X25519MLKEM768 SecP256r1MLKEM768 SecP384r1MLKEM1024 X25519 P-256 X448 P-521 P-384 ffdhe2048 ffdhe3072 ffdhe4096 ffdhe6144 ffdhe8192" {
		t.Errorf("RHEL 10 nginx groups = %v", e.Values)
	}

	// システムの設定に Groups がなければ、ライブラリの既定（Debian 13 の OpenSSL 3.5.7 は X25519MLKEM768 を含む）
	_, inv = collect(t, "", func(p string, b *inventory.Builder) {
		b.AddPackage(model.Package{Manager: "dpkg", Name: "haproxy", Version: "3.0.11-1+deb13u4", Role: "proxy"})
		b.AddPackage(model.Package{Manager: "dpkg", Name: "libssl3t64", Version: "3.5.7-1~deb13u3", Role: "crypto-library"})
		writeCert(t, p+"/etc/lab/rsa.crt", "rsa")
		os.MkdirAll(filepath.Dir(p+haproxyCfg), 0o755)
		os.WriteFile(p+haproxyCfg, []byte("global\n"+haproxyBase+"frontend fe_default\n    bind 127.0.0.1:8443 ssl crt /etc/lab/rsa.crt\n"), 0o644)
	})
	e = groupsOf(t, inv, "svc:haproxy", "frontend fe_default bind 127.0.0.1:8443")
	if strings.Join(e.Values, " ") != "X25519MLKEM768 X25519 P-256 X448 P-384 P-521 ffdhe2048 ffdhe3072" || !strings.HasPrefix(layers(e), "library/default") {
		t.Errorf("Debian 13 haproxy groups = %v (%s)", e.Values, layers(e))
	}
}

// アプリの設定でグループを指定した場合: 外側の指定の引き継ぎと、内側での書き換え。
func TestGroupsFromApplicationConfig(t *testing.T) {
	// nginx: ssl_ecdh_curve。「auto」は指定なしと同じ
	_, inv := collect(t, "rhel9", withGroups(rhel9PolicyGroups, rhel9Web(t, "3.5.9", "1.el9_9", map[string]string{nginxConf: `ssl_ecdh_curve secp384r1:X25519;
server { listen 127.0.0.1:8443 ssl; server_name inherit.lab.test; ` + nginxCerts + ` }
server { listen 127.0.0.1:8444 ssl; server_name override.lab.test; ` + nginxCerts + ` ssl_ecdh_curve prime256v1; }
server { listen 127.0.0.1:8445 ssl; server_name auto.lab.test; ` + nginxCerts + ` ssl_ecdh_curve auto; }
`})))
	e := groupsOf(t, inv, "svc:nginx", "server inherit.lab.test")
	if strings.Join(e.Values, " ") != "P-384 X25519" || e.Steps[0].Layer != "app-config" || e.Steps[0].Setting == "" {
		t.Errorf("nginx inherit = %+v", e)
	}
	if o := groupsOf(t, inv, "svc:nginx", "server override.lab.test"); strings.Join(o.Values, " ") != "P-256" {
		t.Errorf("nginx override = %v", o.Values)
	}
	if a := groupsOf(t, inv, "svc:nginx", "server auto.lab.test"); strings.Join(a.Values, " ") != rhel9Groups {
		t.Errorf("nginx auto = %v", a.Values)
	}

	// Apache: SSLOpenSSLConfCmd Groups / Curves。この指定だけなら、暗号スイートの実効値も求められる（他の指定があると求めない）
	_, inv = collect(t, "rhel9", withGroups(rhel9PolicyGroups, rhel9Web(t, "3.5.9", "1.el9_9", map[string]string{apacheConf: "SSLOpenSSLConfCmd Groups secp384r1:X25519\nListen 127.0.0.1:8443\nListen 127.0.0.1:8444\n" +
		"<VirtualHost 127.0.0.1:8443>\n    SSLEngine on\n" + apacheCerts + "</VirtualHost>\n" +
		"<VirtualHost 127.0.0.1:8444>\n    SSLEngine on\n" + apacheCerts + "    SSLOpenSSLConfCmd Curves prime256v1\n</VirtualHost>\n"})))
	if e := groupsOf(t, inv, "svc:httpd", "VirtualHost 127.0.0.1:8443"); strings.Join(e.Values, " ") != "P-384 X25519" {
		t.Errorf("apache inherit = %v", e.Values)
	}
	if e := groupsOf(t, inv, "svc:httpd", "VirtualHost 127.0.0.1:8444"); strings.Join(e.Values, " ") != "P-256" {
		t.Errorf("apache override = %v", e.Values)
	}
	checkSuites(t, eff(t, inv, "svc:httpd", "tls.ciphers", "VirtualHost 127.0.0.1:8443"), 27, "e08c4d6580e60588", "high")

	// HAProxy: 全体の ssl-default-bind-curves と、bind の行の curves
	_, inv = collect(t, "rhel9", withGroups(rhel9PolicyGroups, haproxyRHEL9(t, map[string]string{haproxyCfg: "global\n    ssl-default-bind-curves secp384r1:X25519\n" + haproxyBase +
		"frontend fe_inherit\n    bind 127.0.0.1:8443 ssl " + haproxyCrt + "\nfrontend fe_override\n    bind 127.0.0.1:8444 ssl " + haproxyCrt + " curves prime256v1\n"})))
	if e := groupsOf(t, inv, "svc:haproxy", "frontend fe_inherit bind 127.0.0.1:8443"); strings.Join(e.Values, " ") != "P-384 X25519" {
		t.Errorf("haproxy inherit = %v", e.Values)
	}
	if e := groupsOf(t, inv, "svc:haproxy", "frontend fe_override bind 127.0.0.1:8444"); strings.Join(e.Values, " ") != "P-256" {
		t.Errorf("haproxy override = %v", e.Values)
	}
}

// stunnel は、自分の既定のグループ（X25519:P-256:X448:P-521:P-384）を持つ。システムの設定やライブラリの既定には従わないので、
// OpenSSL 3.5 の上でも、耐量子のハイブリッドを受け入れない。
func TestGroupsStunnelOwnDefault(t *testing.T) {
	_, inv := collect(t, "rhel9", withGroups(rhel9PolicyGroups, stunnelRHEL9(t, map[string]string{stunnelConf: stunnelHead +
		"[default]\naccept = 127.0.0.1:8443\n" + stunnelRSA})))
	e := groupsOf(t, inv, "svc:stunnel", "stunnel.conf [default]")
	if strings.Join(e.Values, " ") != "X25519 P-256 X448 P-521 P-384" || e.Steps[0].Layer != "app-default" || e.Steps[0].Source == nil || e.Steps[0].Source.Package != "stunnel" {
		t.Errorf("stunnel default groups = %+v", e)
	}
	_, inv = collect(t, "rhel9", withGroups(rhel9PolicyGroups, stunnelRHEL9(t, map[string]string{stunnelConf: stunnelHead + "curves = secp384r1:X25519\n" +
		"[inherit]\naccept = 127.0.0.1:8443\n" + stunnelRSA + "[override]\naccept = 127.0.0.1:8444\n" + stunnelRSA + "curves = prime256v1\n"})))
	if e := groupsOf(t, inv, "svc:stunnel", "stunnel.conf [inherit]"); strings.Join(e.Values, " ") != "P-384 X25519" {
		t.Errorf("stunnel inherit = %v", e.Values)
	}
	if e := groupsOf(t, inv, "svc:stunnel", "stunnel.conf [override]"); strings.Join(e.Values, " ") != "P-256" {
		t.Errorf("stunnel override = %v", e.Values)
	}
}

// 求められない場合と、確度が下がる場合。
func TestGroupsLimits(t *testing.T) {
	nginx := func(extra string) map[string]string {
		return map[string]string{nginxConf: "server { listen 127.0.0.1:8443 ssl; server_name default.lab.test; " + nginxCerts + " " + extra + " }\n"}
	}
	scope := "server default.lab.test"
	// 補間（OpenSSL のリリースだけが違う）→ 確度を一段下げ、実測した版を注記に残す
	_, inv := collect(t, "rhel9", withGroups(rhel9PolicyGroups, rhel9Web(t, "3.5.9", "2.el9_9", nginx(""))))
	e := groupsOf(t, inv, "svc:nginx", scope)
	if e.Confidence != "medium" || !strings.Contains(strings.Join(e.Notes, " "), "3.5.9-1.el9_9") {
		t.Errorf("interpolated: %+v", e)
	}
	// その版の OpenSSL が拒否する指定（知らない名前）→ 求めない
	_, inv = collect(t, "rhel9", withGroups(rhel9PolicyGroups, rhel9Web(t, "3.5.9", "1.el9_9", nginx("ssl_ecdh_curve X25519:NOSUCHGROUP;"))))
	if e := eff(t, inv, "svc:nginx", "tls.groups", scope); e.Status != "unresolved" || !strings.Contains(e.Reason, "group") {
		t.Errorf("invalid list: %+v", e)
	}
	// 対応表のない版（OpenSSL 1.0.2 は、グループを測れていない）→ 求めない
	_, inv = collect(t, "", func(p string, b *inventory.Builder) {
		b.AddPackage(model.Package{Manager: "dpkg", Name: "haproxy", Version: "1.6.3-1ubuntu0.3", Role: "proxy"})
		b.AddPackage(model.Package{Manager: "dpkg", Name: "libssl1.0.0", Version: "1.0.2g-1ubuntu4.20", Role: "crypto-library"})
		writeCert(t, p+"/etc/lab/rsa.crt", "rsa")
		os.MkdirAll(filepath.Dir(p+haproxyCfg), 0o755)
		os.WriteFile(p+haproxyCfg, []byte("global\n"+haproxyBase+"frontend fe_default\n    bind 127.0.0.1:8443 ssl crt /etc/lab/rsa.crt\n"), 0o644)
	})
	if e := eff(t, inv, "svc:haproxy", "tls.groups", "frontend fe_default bind 127.0.0.1:8443"); e.Status != "unresolved" || !strings.Contains(e.Reason, "libssl1.0.0 1.0.2g-1ubuntu4.20") {
		t.Errorf("no group table: %+v", e)
	}
	// 暗号スイートのほうは、従来どおり求まる（グループが求まらなくても影響しない）
	checkSuites(t, eff(t, inv, "svc:haproxy", "tls.ciphers", "frontend fe_default bind 127.0.0.1:8443"), 30, "0034b8492620755c", "high")
}
