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

// 以下の期待値（スイートの数と集合のハッシュ）は、検証ラボで実際に HAProxy を起動し、ハンドシェイクで受け入れるスイートを
// 数え上げた結果（RHEL 9.9: haproxy 2.8.14-3.el9_8.2、Ubuntu 24.04.5: haproxy 2.8.30-0ubuntu0.24.04.2、
// Ubuntu 16.04.7: haproxy 1.6.3-1ubuntu0.3）。設定ファイルも、そのときに使ったものと同じ内容。

const (
	haproxyCfg  = "/etc/haproxy/haproxy.cfg"
	haproxyCrt  = "crt /etc/lab/rsa.crt crt /etc/lab/ec.crt"
	haproxyBase = "defaults\n    mode http\n    timeout connect 5s\n    timeout client 5s\n    timeout server 5s\n"
	haproxyAlt  = "ECDHE+AESGCM:DHE+AESGCM:AES128-SHA"
)

func haproxyRHEL9(t *testing.T, files map[string]string) func(p string, b *inventory.Builder) {
	prepare := rhel9Web(t, "3.5.9", "1.el9_9", files)
	return func(p string, b *inventory.Builder) {
		b.AddPackage(model.Package{Manager: "rpm", Name: "haproxy", Version: "2.8.14", Release: "3.el9_8.2", Role: "tls-server"})
		prepare(p, b)
	}
}

func layers(e model.EffectiveValue) string {
	var out []string
	for _, s := range e.Steps {
		out = append(out, s.Layer+"/"+s.Op)
	}
	return strings.Join(out, " ")
}

// 暗号の指定が何もなければ、HAProxy は何も設定せず、OpenSSL のシステム既定（RHEL では暗号ポリシー）のままになる。
func TestHAProxyEffectiveCiphersSystemDefault(t *testing.T) {
	_, inv := collect(t, "rhel9", haproxyRHEL9(t, map[string]string{haproxyCfg: "global\n    maxconn 100\n" + haproxyBase +
		"frontend fe_default\n    bind 127.0.0.1:8443 ssl " + haproxyCrt + "\n    bind 127.0.0.1:8080\n" +
		"frontend fe_override\n    bind 127.0.0.1:8444 ssl " + haproxyCrt + " ciphers " + haproxyAlt + "\n"}))
	scope := "frontend fe_default bind 127.0.0.1:8443"
	e := eff(t, inv, "svc:haproxy", "tls.ciphers", scope)
	checkSuites(t, e, 22, "2acef5700c9db216", "high")
	if layers(e) != "app-default/default os-policy/override library/expand os-policy/security-level app-config/filter-certificates app-default/filter-dh-parameters" {
		t.Errorf("steps = %s", layers(e))
	}
	if s := e.Steps[0].Source; s == nil || s.Package != "haproxy" || s.Version != "2.8.14-3.el9_8.2" {
		t.Errorf("app default source = %+v", e.Steps[0].Source)
	}
	if e13 := eff(t, inv, "svc:haproxy", "tls.ciphersuites-tls13", scope); sortedJoin(e13.Values) != rhel9TLS13 {
		t.Errorf("TLS 1.3 = %+v", e13)
	}
	// bind の行で暗号を指定した場合。この版の HAProxy は、DH パラメータの指定がなければ DHE を使わない
	o := eff(t, inv, "svc:haproxy", "tls.ciphers", "frontend fe_override bind 127.0.0.1:8444")
	checkSuites(t, o, 5, "17ba9bb9c3d4f766", "high")
	if o.Steps[0].Layer != "app-config" || o.Steps[0].Setting == "" {
		t.Errorf("steps[0] = %+v", o.Steps[0])
	}
	// TLS を使わない bind には実効値を出さない
	for _, x := range inv.EffectiveValues {
		if x.Service == "svc:haproxy" && strings.Contains(x.Scope, "8080") {
			t.Errorf("unexpected effective value for a plain bind: %+v", x)
		}
	}
	// 設定に書かれた値の記録（bind の行の指定は、その frontend の範囲に記録する）
	var found bool
	for _, s := range inv.Settings {
		if s.Service == "svc:haproxy" && s.Parameter == "tls.ciphers" && s.Scope == "frontend fe_override" && strings.Join(s.Values, ":") == haproxyAlt {
			found = s.Location.Line == 12 && strings.HasSuffix(s.Location.Path, haproxyCfg)
		}
	}
	if !found {
		t.Errorf("the bind-level cipher setting is not recorded: %+v", byParam(inv, "svc:haproxy"))
	}
}

// 全体の指定（ssl-default-bind-ciphers）は bind に引き継がれ、bind の行に書けばそちらが効く。DH パラメータの長さの指定があれば DHE も使える。
func TestHAProxyEffectiveCiphersInheritAndOverride(t *testing.T) {
	_, inv := collect(t, "rhel9", haproxyRHEL9(t, map[string]string{haproxyCfg: "global\n    maxconn 100\n    ssl-default-bind-ciphers HIGH:!aNULL:!MD5:!kRSA\n    tune.ssl.default-dh-param 2048\n" + haproxyBase +
		"frontend fe_inherit\n    bind 127.0.0.1:8443 ssl " + haproxyCrt + "\n" +
		"frontend fe_override\n    bind 127.0.0.1:8444 ssl " + haproxyCrt + " ciphers " + haproxyAlt + "\n"}))
	e := eff(t, inv, "svc:haproxy", "tls.ciphers", "frontend fe_inherit bind 127.0.0.1:8443")
	checkSuites(t, e, 39, "c08400076f551c06", "high")
	var set model.Setting
	for _, s := range inv.Settings {
		if s.ID == e.Steps[0].Setting {
			set = s
		}
	}
	if set.Scope != "global" || set.Location.Line != 3 {
		t.Errorf("the inherited value must point at the global setting, got %+v", set)
	}
	checkSuites(t, eff(t, inv, "svc:haproxy", "tls.ciphers", "frontend fe_override bind 127.0.0.1:8444"), 7, "17da0592b5fe6045", "high")

	// PROFILE=SYSTEM（RHEL のパッケージの設定ファイルが全体に書いている値）
	_, inv = collect(t, "rhel9", haproxyRHEL9(t, map[string]string{haproxyCfg: "global\n    ssl-default-bind-ciphers PROFILE=SYSTEM\n" + haproxyBase +
		"listen ls_packaged\n    bind 127.0.0.1:8443 ssl " + haproxyCrt + "\n"}))
	checkSuites(t, eff(t, inv, "svc:haproxy", "tls.ciphers", "listen ls_packaged bind 127.0.0.1:8443"), 22, "2acef5700c9db216", "high")
}

// TLS 1.3 のスイートは、アプリの設定（ssl-default-bind-ciphersuites、bind の ciphersuites）があれば、システムの設定より優先される。
func TestHAProxyEffectiveTLS13(t *testing.T) {
	_, inv := collect(t, "rhel9", haproxyRHEL9(t, map[string]string{haproxyCfg: "global\n    ssl-default-bind-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256\n" + haproxyBase +
		"frontend fe_inherit\n    bind 127.0.0.1:8443 ssl " + haproxyCrt + "\n" +
		"frontend fe_override\n    bind 127.0.0.1:8444 ssl " + haproxyCrt + " ciphersuites TLS_AES_128_GCM_SHA256\n"}))
	e := eff(t, inv, "svc:haproxy", "tls.ciphersuites-tls13", "frontend fe_inherit bind 127.0.0.1:8443")
	if e.Status != "resolved" || strings.Join(e.Values, ",") != "TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256" || e.Steps[0].Layer != "app-config" || e.Steps[0].Setting == "" {
		t.Errorf("inherited TLS 1.3 suites = %+v", e)
	}
	o := eff(t, inv, "svc:haproxy", "tls.ciphersuites-tls13", "frontend fe_override bind 127.0.0.1:8444")
	if strings.Join(o.Values, ",") != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("overridden TLS 1.3 suites = %+v", o)
	}
	// TLS 1.2 以下のスイートは、この指定の影響を受けない
	checkSuites(t, eff(t, inv, "svc:haproxy", "tls.ciphers", "frontend fe_inherit bind 127.0.0.1:8443"), 22, "2acef5700c9db216", "high")
}

// RHEL 系のユニットは、主の設定ファイルに加えて /etc/haproxy/conf.d も読ませる。ユニットがそう指定している場合だけ読む。
func TestHAProxyConfigDirectoryFromUnit(t *testing.T) {
	files := map[string]string{
		haproxyCfg:                     "global\n    maxconn 100\n" + haproxyBase,
		"/etc/haproxy/conf.d/50.cfg":   "frontend fe_extra\n    bind 127.0.0.1:8443 ssl " + haproxyCrt + "\n",
		"/etc/haproxy/conf.d/note.txt": "frontend fe_ignored\n    bind 127.0.0.1:9443 ssl " + haproxyCrt + "\n",
	}
	_, inv := collect(t, "rhel9", haproxyRHEL9(t, files))
	for _, x := range inv.EffectiveValues {
		if x.Service == "svc:haproxy" {
			t.Errorf("conf.d must not be read without a unit that names it: %+v", x)
		}
	}
	files["/usr/lib/systemd/system/haproxy.service"] = "[Service]\nEnvironmentFile=-/etc/sysconfig/haproxy\nEnvironment=\"CONFIG=/etc/haproxy/haproxy.cfg\" \"PIDFILE=/run/haproxy.pid\" \"CFGDIR=/etc/haproxy/conf.d\"\nExecStart=/usr/sbin/haproxy -Ws -f $CONFIG -f $CFGDIR -p $PIDFILE $OPTIONS\n"
	_, inv = collect(t, "rhel9", haproxyRHEL9(t, files))
	checkSuites(t, eff(t, inv, "svc:haproxy", "tls.ciphers", "frontend fe_extra bind 127.0.0.1:8443"), 22, "2acef5700c9db216", "high")
	for _, x := range inv.EffectiveValues {
		if x.Service == "svc:haproxy" && strings.Contains(x.Scope, "fe_ignored") {
			t.Errorf("only *.cfg files in the directory are read: %+v", x)
		}
	}
}

// Ubuntu 24.04: システムの openssl.cnf に暗号の指定がなければ、ライブラリの既定（DEFAULT）になる。
func TestHAProxyEffectiveCiphersUbuntu2404(t *testing.T) {
	prepare := func(version, sslPkg, sslVersion, conf string) func(p string, b *inventory.Builder) {
		return func(p string, b *inventory.Builder) {
			b.AddPackage(model.Package{Manager: "dpkg", Name: "haproxy", Version: version, Role: "tls-server"})
			b.AddPackage(model.Package{Manager: "dpkg", Name: sslPkg, Version: sslVersion, Role: "crypto-library"})
			writeCert(t, p+"/etc/lab/rsa.crt", "rsa")
			writeCert(t, p+"/etc/lab/ec.crt", "ec")
			os.MkdirAll(filepath.Dir(p+haproxyCfg), 0o755)
			os.WriteFile(p+haproxyCfg, []byte(conf), 0o644)
		}
	}
	conf := "global\n    maxconn 100\n" + haproxyBase + "frontend fe_default\n    bind 127.0.0.1:8443 ssl " + haproxyCrt + "\n"
	scope := "frontend fe_default bind 127.0.0.1:8443"
	_, inv := collect(t, "", prepare("2.8.30-0ubuntu0.24.04.2", "libssl3t64", "3.0.13-0ubuntu3.16", conf))
	e := eff(t, inv, "svc:haproxy", "tls.ciphers", scope)
	checkSuites(t, e, 20, "2a06ff1e94ff51a2", "high")
	if !strings.HasPrefix(layers(e), "app-default/default library/default library/expand") {
		t.Errorf("steps = %s", layers(e))
	}
	// 古い HAProxy（1.6）は、同じ名前の証明書を複数指定しても最初の1つしか使わない（ECDSA のスイートは使えない）。組み込みの DH パラメータを持つ
	_, inv = collect(t, "", prepare("1.6.3-1ubuntu0.3", "libssl1.0.0", "1.0.2g-1ubuntu4.20", conf))
	e = eff(t, inv, "svc:haproxy", "tls.ciphers", scope)
	checkSuites(t, e, 30, "0034b8492620755c", "high")
	// 証明書をディレクトリで指定している場合は、どの証明書が使われるかを追わず、種類による絞り込みをしない（確度は一段下）
	_, inv = collect(t, "", prepare("2.8.30-0ubuntu0.24.04.2", "libssl3t64", "3.0.13-0ubuntu3.16",
		"global\n"+haproxyBase+"frontend fe_default\n    bind 127.0.0.1:8443 ssl crt /etc/lab/\n"))
	e = eff(t, inv, "svc:haproxy", "tls.ciphers", scope)
	if e.Status != "resolved" || e.Confidence != "medium" || !strings.Contains(strings.Join(e.Notes, " "), "certificate") {
		t.Errorf("certificate directory: %+v", e)
	}
	// 既定の表にない版 → 暗号の指定がない bind は求めない。指定がある bind は求められるが、DHE の可否が分からないので確度は一段下
	_, inv = collect(t, "", prepare("9.9.9-1ubuntu1", "libssl3t64", "3.0.13-0ubuntu3.16",
		"global\n"+haproxyBase+"frontend fe_default\n    bind 127.0.0.1:8443 ssl "+haproxyCrt+"\nfrontend fe_set\n    bind 127.0.0.1:8444 ssl "+haproxyCrt+" ciphers "+haproxyAlt+"\n"))
	if e := eff(t, inv, "svc:haproxy", "tls.ciphers", scope); e.Status != "unresolved" || !strings.Contains(e.Reason, "haproxy 9.9.9-1ubuntu1") {
		t.Errorf("unknown haproxy version: %+v", e)
	}
	if e := eff(t, inv, "svc:haproxy", "tls.ciphers", "frontend fe_set bind 127.0.0.1:8444"); e.Status != "resolved" || e.Confidence != "medium" || len(e.Values) != 7 {
		t.Errorf("unknown haproxy version, explicit ciphers: %+v", e)
	}
}
