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

// 以下の期待値（スイートの数と集合のハッシュ）は、検証ラボで実際に stunnel を起動し、ハンドシェイクで受け入れるスイートを
// 数え上げた結果（RHEL 9.9: stunnel 5.71-2.el9、Ubuntu 24.04.5: stunnel4 3:5.72-1build2、Ubuntu 16.04.7: stunnel4 3:5.30-1ubuntu0.1）。
// 設定ファイルも、そのときに使ったものと同じ内容。

const (
	stunnelConf = "/etc/stunnel/stunnel.conf"
	stunnelRSA  = "cert = /etc/lab/rsa.crt\nkey = /etc/lab/rsa.key\nconnect = 127.0.0.1:9\n"
	stunnelEC   = "cert = /etc/lab/ec.crt\nkey = /etc/lab/ec.key\nconnect = 127.0.0.1:9\n"
	stunnelHead = "pid = /run/stunnel-lab.pid\nforeground = no\n"
	// stunnel 自身の TLS 1.3 の既定（バイナリに埋め込まれた文字列）
	stunnelTLS13 = "TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_CHACHA20_POLY1305_SHA256"
)

func stunnelRHEL9(t *testing.T, files map[string]string) func(p string, b *inventory.Builder) {
	prepare := rhel9Web(t, "3.5.9", "1.el9_9", files)
	return func(p string, b *inventory.Builder) {
		b.AddPackage(model.Package{Manager: "rpm", Name: "stunnel", Version: "5.71", Release: "2.el9", Role: "proxy"})
		prepare(p, b)
	}
}

// 暗号の指定がないサービスは、stunnel に埋め込まれた既定（RHEL では PROFILE=SYSTEM）になる。
// TLS 1.3 のスイートは、システムの暗号ポリシー（4 個）ではなく、stunnel 自身の既定（3 個）になる。
func TestStunnelEffectiveCiphersDefault(t *testing.T) {
	_, inv := collect(t, "rhel9", stunnelRHEL9(t, map[string]string{stunnelConf: stunnelHead +
		"[rsa]\naccept = 127.0.0.1:8443\n" + stunnelRSA + "[ec]\naccept = 127.0.0.1:8444\n" + stunnelEC}))
	e := eff(t, inv, "svc:stunnel", "tls.ciphers", "stunnel.conf [rsa]")
	checkSuites(t, e, 23, "1aae0270f9f74ce1", "high")
	if !strings.HasPrefix(layers(e), "app-default/default os-policy/profile library/expand") {
		t.Errorf("steps = %s", layers(e))
	}
	if s := e.Steps[0].Source; s == nil || s.Package != "stunnel" || s.Version != "5.71-2.el9" {
		t.Errorf("app default source = %+v", e.Steps[0].Source)
	}
	e13 := eff(t, inv, "svc:stunnel", "tls.ciphersuites-tls13", "stunnel.conf [rsa]")
	if e13.Status != "resolved" || strings.Join(e13.Values, ",") != stunnelTLS13 || e13.Steps[0].Layer != "app-default" || e13.Steps[0].Source == nil {
		t.Errorf("TLS 1.3 = %+v", e13)
	}
	// ECDSA の証明書だけを持つサービス
	checkSuites(t, eff(t, inv, "svc:stunnel", "tls.ciphers", "stunnel.conf [ec]"), 8, "9fc1d4987559029c", "high")
}

// 全体に書いた値はサービスに引き継がれ、サービスに書けばそちらが効く。stunnel は組み込みの DH パラメータを持つ。
func TestStunnelEffectiveCiphersInheritAndOverride(t *testing.T) {
	_, inv := collect(t, "rhel9", stunnelRHEL9(t, map[string]string{stunnelConf: stunnelHead + "ciphers = HIGH:!aNULL:!MD5:!kRSA\n" +
		"[inherit]\naccept = 127.0.0.1:8443\n" + stunnelRSA +
		"[override]\naccept = 127.0.0.1:8444\n" + stunnelRSA + "ciphers = ECDHE+AESGCM:DHE+AESGCM:AES128-SHA\n" +
		"[out]\nclient = yes\naccept = 127.0.0.1:8025\nconnect = mail.example.jp:465\n"}))
	e := eff(t, inv, "svc:stunnel", "tls.ciphers", "stunnel.conf [inherit]")
	checkSuites(t, e, 26, "02de241f6306d23f", "high")
	var set model.Setting
	for _, s := range inv.Settings {
		if s.ID == e.Steps[0].Setting {
			set = s
		}
	}
	if set.Scope != "stunnel.conf" || set.Location.Line != 3 {
		t.Errorf("the inherited value must point at the global setting, got %+v", set)
	}
	checkSuites(t, eff(t, inv, "svc:stunnel", "tls.ciphers", "stunnel.conf [override]"), 5, "c912afa74ee150e6", "high")
	// 外向きの接続（client = yes）のサービスには、サーバーとしての実効値を出さない
	for _, x := range inv.EffectiveValues {
		if x.Service == "svc:stunnel" && strings.Contains(x.Scope, "[out]") {
			t.Errorf("unexpected effective value for a client service: %+v", x)
		}
	}
}

// TLS 1.3 のスイートを設定で指定した場合（全体の指定の引き継ぎと、サービスでの書き換え）。
func TestStunnelEffectiveTLS13(t *testing.T) {
	_, inv := collect(t, "rhel9", stunnelRHEL9(t, map[string]string{stunnelConf: stunnelHead + "ciphersuites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256\n" +
		"[inherit]\naccept = 127.0.0.1:8443\n" + stunnelRSA +
		"[override]\naccept = 127.0.0.1:8444\n" + stunnelRSA + "ciphersuites = TLS_AES_128_GCM_SHA256\n"}))
	e := eff(t, inv, "svc:stunnel", "tls.ciphersuites-tls13", "stunnel.conf [inherit]")
	if strings.Join(e.Values, ",") != "TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256" || e.Steps[0].Layer != "app-config" || e.Steps[0].Setting == "" {
		t.Errorf("inherited TLS 1.3 suites = %+v", e)
	}
	if o := eff(t, inv, "svc:stunnel", "tls.ciphersuites-tls13", "stunnel.conf [override]"); strings.Join(o.Values, ",") != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("overridden TLS 1.3 suites = %+v", o)
	}
	checkSuites(t, eff(t, inv, "svc:stunnel", "tls.ciphers", "stunnel.conf [inherit]"), 23, "1aae0270f9f74ce1", "high")
}

// Debian 系: 設定は /etc/stunnel/ の下の *.conf のそれぞれが 1 つの起動単位。既定の暗号文字列は版で違う。
func TestStunnelDebianFamily(t *testing.T) {
	prepare := func(version, sslPkg, sslVersion string, files map[string]string) func(p string, b *inventory.Builder) {
		return func(p string, b *inventory.Builder) {
			b.AddPackage(model.Package{Manager: "dpkg", Name: "stunnel4", Version: version, Role: "proxy"})
			b.AddPackage(model.Package{Manager: "dpkg", Name: sslPkg, Version: sslVersion, Role: "crypto-library"})
			writeCert(t, p+"/etc/lab/rsa.crt", "rsa")
			writeCert(t, p+"/etc/lab/ec.crt", "ec")
			for name, content := range files {
				os.MkdirAll(filepath.Dir(p+name), 0o755)
				os.WriteFile(p+name, []byte(content), 0o644)
			}
		}
	}
	conf := stunnelHead + "[rsa]\naccept = 127.0.0.1:8443\n" + stunnelRSA
	// Ubuntu 24.04: 既定は HIGH:!aNULL:!SSLv2:!DH:!kDHEPSK（DH を含まない）。設定ファイルの名前は任意
	_, inv := collect(t, "", prepare("3:5.72-1build2", "libssl3t64", "3.0.13-0ubuntu3.16", map[string]string{
		"/etc/stunnel/mail.conf": conf, "/etc/stunnel/README": "[ignored]\naccept = 1\n"}))
	e := eff(t, inv, "svc:stunnel", "tls.ciphers", "mail.conf [rsa]")
	checkSuites(t, e, 27, "5dfeb7077eecb123", "high")
	for _, x := range inv.EffectiveValues {
		if strings.Contains(x.Scope, "ignored") {
			t.Errorf("only *.conf files are read: %+v", x)
		}
	}
	// Ubuntu 16.04（stunnel 5.30）: 埋め込まれた既定がなく、OpenSSL の既定のままになる。TLS 1.3 はない
	_, inv = collect(t, "", prepare("3:5.30-1ubuntu0.1", "libssl1.0.0", "1.0.2g-1ubuntu4.20", map[string]string{stunnelConf: conf}))
	e = eff(t, inv, "svc:stunnel", "tls.ciphers", "stunnel.conf [rsa]")
	checkSuites(t, e, 30, "0034b8492620755c", "high")
	if !strings.HasPrefix(layers(e), "app-default/default library/default library/expand") {
		t.Errorf("steps = %s", layers(e))
	}
	for _, x := range inv.EffectiveValues {
		if x.Service == "svc:stunnel" && x.Parameter == "tls.ciphersuites-tls13" {
			t.Errorf("OpenSSL 1.0.2 has no TLS 1.3: %+v", x)
		}
	}
	// 証明書の指定がないサービスは、種類による絞り込みをしない（確度は一段下）
	_, inv = collect(t, "", prepare("3:5.72-1build2", "libssl3t64", "3.0.13-0ubuntu3.16", map[string]string{
		stunnelConf: stunnelHead + "[nocert]\naccept = 127.0.0.1:8443\nconnect = 127.0.0.1:9\n"}))
	if e := eff(t, inv, "svc:stunnel", "tls.ciphers", "stunnel.conf [nocert]"); e.Status != "resolved" || e.Confidence != "medium" {
		t.Errorf("no certificate: %+v", e)
	}
}
