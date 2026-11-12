//go:build unix

package apps

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"kagiya/internal/inventory"
	"kagiya/internal/model"
)

// 以下のテストの期待値（スイートの数と集合のハッシュ）は、検証ラボで実際に nginx / Apache httpd を起動し、
// ハンドシェイクで受け入れるスイートを数え上げた結果（RHEL 9.9: openssl-libs 3.5.9-1.el9_9、nginx-core 1.20.1-32.el9_9.1、
// httpd-core 2.4.62-13.el9_8.9。Ubuntu 24.04.5: libssl3t64 3.0.13-0ubuntu3.16、apache2-bin 2.4.58-1ubuntu8.18）。
// 設定ファイルも、そのときに使ったものと同じ内容。

func setDigest(names []string) string {
	s := append([]string{}, names...)
	sort.Strings(s)
	h := sha256.Sum256([]byte(strings.Join(s, ":")))
	return hex.EncodeToString(h[:])[:16]
}

func sortedJoin(names []string) string {
	s := append([]string{}, names...)
	sort.Strings(s)
	return strings.Join(s, ",")
}

// writeCert は、テスト用の自己署名証明書を PEM で書く（kind は "rsa" か "ec"）。
func writeCert(t *testing.T, path, kind string) {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "lab.test"},
		NotBefore: time.Unix(1700000000, 0), NotAfter: time.Unix(1800000000, 0)}
	var der []byte
	var err error
	if kind == "rsa" {
		k, e := rsa.GenerateKey(rand.Reader, 2048)
		if e != nil {
			t.Fatal(e)
		}
		der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	} else {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	}
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}

const (
	rhel9Policy      = "@SECLEVEL=2:kEECDH:kRSA:kEDH:kPSK:kDHEPSK:kECDHEPSK:kRSAPSK:-aDSS:-3DES:!DES:!RC4:!RC2:!IDEA:-SEED:!eNULL:!aNULL:!MD5:-SHA384:-CAMELLIA:-ARIA:-AESCCM8"
	rhel9PolicyTLS13 = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_SHA256"
	rhel9TLS13       = "TLS_AES_128_CCM_SHA256,TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256"
	ubuntuTLS13      = "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256"
	nginxCerts       = "ssl_certificate /etc/lab/rsa.crt; ssl_certificate_key /etc/lab/rsa.key; ssl_certificate /etc/lab/ec.crt; ssl_certificate_key /etc/lab/ec.key;"
	apacheCerts      = "    SSLCertificateFile /etc/lab/rsa.crt\n    SSLCertificateKeyFile /etc/lab/rsa.key\n    SSLCertificateFile /etc/lab/ec.crt\n    SSLCertificateKeyFile /etc/lab/ec.key\n"
)

// rhel9Web は、RHEL 9.9 に nginx と httpd を導入した状態を作る。opensslRelease で OpenSSL のリリースを変えられる。
func rhel9Web(t *testing.T, opensslVersion, opensslRelease string, files map[string]string) func(p string, b *inventory.Builder) {
	return func(p string, b *inventory.Builder) {
		b.AddPackage(model.Package{Manager: "rpm", Name: "nginx-core", Epoch: 2, Version: "1.20.1", Release: "32.el9_9.1", Role: "tls-server"})
		b.AddPackage(model.Package{Manager: "rpm", Name: "httpd-core", Version: "2.4.62", Release: "13.el9_8.9", Role: "tls-server"})
		if opensslVersion != "" {
			b.AddPackage(model.Package{Manager: "rpm", Name: "openssl-libs", Epoch: 1, Version: opensslVersion, Release: opensslRelease, Role: "crypto-library"})
		}
		// システムの openssl.cnf が取り込む暗号ポリシー（OS 設定のコレクタが読んだ結果）
		b.AddOSSetting(model.OSSetting{ID: "openssl.system_default.CipherString", Value: rhel9Policy, Path: "/etc/crypto-policies/back-ends/opensslcnf.config", Line: 1})
		b.AddOSSetting(model.OSSetting{ID: "openssl.system_default.Ciphersuites", Value: rhel9PolicyTLS13, Path: "/etc/crypto-policies/back-ends/opensslcnf.config", Line: 2})
		os.MkdirAll(p+"/etc/crypto-policies/back-ends", 0o755)
		os.WriteFile(p+"/etc/crypto-policies/back-ends/opensslcnf.config", []byte("CipherString = "+rhel9Policy+"\nCiphersuites = "+rhel9PolicyTLS13+"\nTLS.MinProtocol = TLSv1.2\n"), 0o644)
		writeCert(t, p+"/etc/lab/rsa.crt", "rsa")
		writeCert(t, p+"/etc/lab/ec.crt", "ec")
		os.WriteFile(p+"/etc/lab/dh.pem", []byte("-----BEGIN DH PARAMETERS-----\n"), 0o644)
		for name, content := range files {
			os.MkdirAll(filepath.Dir(p+name), 0o755)
			os.WriteFile(p+name, []byte(content), 0o644)
		}
	}
}

func eff(t *testing.T, inv *model.Inventory, svc, param, scope string) model.EffectiveValue {
	t.Helper()
	for _, e := range inv.EffectiveValues {
		if e.Service == svc && e.Parameter == param && e.Scope == scope {
			return e
		}
	}
	var have []string
	for _, e := range inv.EffectiveValues {
		have = append(have, e.Service+" "+e.Parameter+" ["+e.Scope+"]")
	}
	t.Fatalf("no effective value for %s %s [%s]; have %v", svc, param, scope, have)
	return model.EffectiveValue{}
}

func checkSuites(t *testing.T, e model.EffectiveValue, count int, digest, confidence string) {
	t.Helper()
	if e.Status != "resolved" || len(e.Values) != count || setDigest(e.Values) != digest || e.Confidence != confidence {
		t.Errorf("%s [%s]: status=%s confidence=%s reason=%q notes=%v: got %d suites (%s), want %d (%s)",
			e.Parameter, e.Scope, e.Status, e.Confidence, e.Reason, e.Notes, len(e.Values), setDigest(e.Values), count, digest)
	}
}

const nginxConf = "/etc/nginx/conf.d/lab-tls.conf"

// nginx: 暗号の記載がない server は、アプリの既定の暗号文字列を、導入されている OpenSSL で展開したものになる。
func TestNginxEffectiveCiphersDefault(t *testing.T) {
	_, inv := collect(t, "rhel9", rhel9Web(t, "3.5.9", "1.el9_9", map[string]string{
		nginxConf: "server { listen 127.0.0.1:8443 ssl; server_name default.lab.test; " + nginxCerts + " }\n"}))
	e := eff(t, inv, "svc:nginx", "tls.ciphers", "server default.lab.test")
	checkSuites(t, e, 38, "8eb6eb3b8003ea16", "high")
	if e.Direction != "inbound" || e.Values[0] != "ECDHE-ECDSA-AES256-GCM-SHA384" {
		t.Errorf("direction=%s first=%s", e.Direction, e.Values[0])
	}
	// どう求めたか: アプリの既定 → ライブラリでの展開 → システムの設定によるセキュリティレベル → 証明書と DH パラメータによる絞り込み
	var layers []string
	for _, s := range e.Steps {
		layers = append(layers, s.Layer+"/"+s.Op)
	}
	if strings.Join(layers, " ") != "app-default/default library/expand os-policy/security-level app-config/filter-certificates app-default/filter-dh-parameters" {
		t.Errorf("steps = %v", layers)
	}
	if s := e.Steps[0].Source; s == nil || s.Package != "nginx-core" || s.Version != "1.20.1-32.el9_9.1" || !strings.HasPrefix(s.Image, "redhat/ubi9@sha256:") {
		t.Errorf("app default source = %+v", e.Steps[0].Source)
	}
	if s := e.Steps[1].Source; s == nil || s.Package != "openssl-libs" || s.Version != "3.5.9-1.el9_9" {
		t.Errorf("library source = %+v", e.Steps[1].Source)
	}
	// TLS 1.3 のスイートは別の項目。RHEL では暗号ポリシー（システムの openssl.cnf）が決めている。
	e13 := eff(t, inv, "svc:nginx", "tls.ciphersuites-tls13", "server default.lab.test")
	if e13.Status != "resolved" || sortedJoin(e13.Values) != rhel9TLS13 || e13.Values[0] != "TLS_AES_256_GCM_SHA384" {
		t.Errorf("TLS 1.3 = %+v", e13)
	}
	if len(e13.Steps) == 0 || e13.Steps[0].Layer != "os-policy" {
		t.Errorf("TLS 1.3 steps = %+v", e13.Steps)
	}
	// 暗号スイートの実効値は、TLS を待ち受ける server にだけ出す（パッケージ既定の、ポート 80 だけの server には出さない）
	for _, x := range inv.EffectiveValues {
		if x.Service == "svc:nginx" && x.Scope != "server default.lab.test" {
			t.Errorf("unexpected effective value for scope %q", x.Scope)
		}
	}
}

// nginx: http 全体に書いた値は server に引き継がれ、server に書けばそちらが効く。ssl_dhparam があれば DHE も使える。
func TestNginxEffectiveCiphersInheritAndOverride(t *testing.T) {
	_, inv := collect(t, "rhel9", rhel9Web(t, "3.5.9", "1.el9_9", map[string]string{nginxConf: `ssl_ciphers HIGH:!aNULL:!MD5:!kRSA;
ssl_protocols TLSv1.2;
server { listen 127.0.0.1:8443 ssl; server_name inherit.lab.test; ` + nginxCerts + ` }
server { listen 127.0.0.1:8444 ssl; server_name override.lab.test; ` + nginxCerts + `
    ssl_ciphers ECDHE+AESGCM:DHE+AESGCM:AES128-SHA;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_dhparam /etc/lab/dh.pem;
}
`}))
	e := eff(t, inv, "svc:nginx", "tls.ciphers", "server inherit.lab.test")
	checkSuites(t, e, 24, "f369e3d2fa271458", "high")
	if e.Steps[0].Layer != "app-config" || e.Steps[0].Op != "override" || e.Steps[0].Setting == "" {
		t.Errorf("steps[0] = %+v", e.Steps[0])
	}
	var set model.Setting
	for _, s := range inv.Settings {
		if s.ID == e.Steps[0].Setting {
			set = s
		}
	}
	if set.Parameter != "tls.ciphers" || set.Scope != "http" || set.Location.Line != 1 {
		t.Errorf("the inherited value must point at the http-level setting, got %+v", set)
	}
	o := eff(t, inv, "svc:nginx", "tls.ciphers", "server override.lab.test")
	checkSuites(t, o, 7, "17da0592b5fe6045", "high")
	if strings.Join(o.Values, " ") != "ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-GCM-SHA256 DHE-RSA-AES256-GCM-SHA384 DHE-RSA-AES128-GCM-SHA256 AES128-SHA" {
		t.Errorf("override = %v", o.Values)
	}
}

// nginx: PROFILE=SYSTEM は、暗号ポリシーのファイルの内容に置き換えて展開する。
func TestNginxEffectiveCiphersProfile(t *testing.T) {
	_, inv := collect(t, "rhel9", rhel9Web(t, "3.5.9", "1.el9_9", map[string]string{
		nginxConf: "server { listen 127.0.0.1:8443 ssl; server_name profile.lab.test; " + nginxCerts + " ssl_ciphers PROFILE=SYSTEM; }\n"}))
	e := eff(t, inv, "svc:nginx", "tls.ciphers", "server profile.lab.test")
	checkSuites(t, e, 22, "2acef5700c9db216", "high")
	found := false
	for _, s := range e.Steps {
		found = found || (s.Layer == "os-policy" && s.Op == "profile")
	}
	if !found {
		t.Errorf("steps must show that the system policy was used: %+v", e.Steps)
	}
}

// 求められない場合と、確度が下がる場合。推測では埋めない。
func TestNginxEffectiveCiphersLimits(t *testing.T) {
	plain := map[string]string{nginxConf: "server { listen 127.0.0.1:8443 ssl; server_name default.lab.test; " + nginxCerts + " }\n"}
	scope := "server default.lab.test"

	// 補間: OpenSSL のリリースだけが実測した版と違う → 実測した表で求め、確度を一段下げて、その旨を残す
	_, inv := collect(t, "rhel9", rhel9Web(t, "3.5.9", "2.el9_9", plain))
	e := eff(t, inv, "svc:nginx", "tls.ciphers", scope)
	checkSuites(t, e, 38, "8eb6eb3b8003ea16", "medium")
	if len(e.Notes) == 0 || !strings.Contains(strings.Join(e.Notes, " "), "3.5.9-1.el9_9") {
		t.Errorf("notes must name the measured version that was used instead: %v", e.Notes)
	}

	// 対応表のない版の OpenSSL → 求めない
	_, inv = collect(t, "rhel9", rhel9Web(t, "9.9.9", "1.el9", plain))
	if e := eff(t, inv, "svc:nginx", "tls.ciphers", scope); e.Status != "unresolved" || len(e.Values) != 0 || !strings.Contains(e.Reason, "openssl-libs 9.9.9-1.el9") {
		t.Errorf("unknown OpenSSL version: %+v", e)
	}
	// OpenSSL のパッケージ情報がない → 求めない
	_, inv = collect(t, "rhel9", rhel9Web(t, "", "", plain))
	if e := eff(t, inv, "svc:nginx", "tls.ciphers", scope); e.Status != "unresolved" || e.Reason == "" {
		t.Errorf("no OpenSSL package: %+v", e)
	}
	// ssl_conf_command（OpenSSL の設定を直接いじる書き方）があると、暗号文字列だけでは決まらない → 求めない
	_, inv = collect(t, "rhel9", rhel9Web(t, "3.5.9", "1.el9_9", map[string]string{
		nginxConf: "server { listen 127.0.0.1:8443 ssl; server_name default.lab.test; " + nginxCerts + " ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384; }\n"}))
	if e := eff(t, inv, "svc:nginx", "tls.ciphers", scope); e.Status != "unresolved" || !strings.Contains(e.Reason, "ssl_conf_command") {
		t.Errorf("ssl_conf_command: %+v", e)
	}
	// 証明書を読めない → 証明書の種類による絞り込みをせずに求め、確度を下げて、その旨を残す
	_, inv = collect(t, "rhel9", rhel9Web(t, "3.5.9", "1.el9_9", map[string]string{
		nginxConf: "server { listen 127.0.0.1:8443 ssl; server_name default.lab.test; ssl_certificate /etc/lab/missing.crt; ssl_certificate_key /etc/lab/missing.key; }\n"}))
	e = eff(t, inv, "svc:nginx", "tls.ciphers", scope)
	// （この構成では、証明書の種類で落ちるはずの DSA 認証のスイートはすべて DHE で、DH パラメータがないために既に落ちている。数は変わらない）
	if e.Status != "resolved" || e.Confidence != "medium" || len(e.Values) < 38 || !strings.Contains(strings.Join(e.Notes, " "), "certificate") {
		t.Errorf("unreadable certificate: %d suites, %+v", len(e.Values), e)
	}
	// RSA の証明書だけ → ECDSA で認証するスイートは使えない
	_, inv = collect(t, "rhel9", rhel9Web(t, "3.5.9", "1.el9_9", map[string]string{
		nginxConf: "server { listen 127.0.0.1:8443 ssl; server_name default.lab.test; ssl_certificate /etc/lab/rsa.crt; ssl_certificate_key /etc/lab/rsa.key; }\n"}))
	e = eff(t, inv, "svc:nginx", "tls.ciphers", scope)
	if e.Status != "resolved" || e.Confidence != "high" || len(e.Values) == 0 || len(e.Values) >= 38 {
		t.Errorf("RSA only: %d suites, %+v", len(e.Values), e)
	}
	for _, s := range e.Values {
		if strings.Contains(s, "ECDSA") {
			t.Errorf("RSA only: unexpected suite %s", s)
		}
	}
	// 暗号文字列が OpenSSL に拒否される内容（1つも残らない）→ 求めない
	_, inv = collect(t, "rhel9", rhel9Web(t, "3.5.9", "1.el9_9", map[string]string{
		nginxConf: "server { listen 127.0.0.1:8443 ssl; server_name default.lab.test; " + nginxCerts + " ssl_ciphers NOSUCHWORD; }\n"}))
	if e := eff(t, inv, "svc:nginx", "tls.ciphers", scope); e.Status != "unresolved" || !strings.Contains(e.Reason, "no cipher match") {
		t.Errorf("rejected cipher string: %+v", e)
	}
}

const apacheConf = "/etc/httpd/conf.d/lab-tls.conf"

// Apache: 暗号の記載がない VirtualHost は、mod_ssl の既定の暗号文字列になる。組み込みの DH パラメータがあるので DHE も使える。
func TestApacheEffectiveCiphersRHEL9(t *testing.T) {
	vh := "VirtualHost 127.0.0.1:8443"
	_, inv := collect(t, "rhel9", rhel9Web(t, "3.5.9", "1.el9_9", map[string]string{apacheConf: "Listen 127.0.0.1:8443\n<VirtualHost 127.0.0.1:8443>\n    ServerName default.lab.test\n    SSLEngine on\n" + apacheCerts + "</VirtualHost>\n"}))
	e := eff(t, inv, "svc:httpd", "tls.ciphers", vh)
	checkSuites(t, e, 27, "e08c4d6580e60588", "high")
	if s := e.Steps[0]; s.Layer != "app-default" || s.Source == nil || s.Source.Package != "httpd-core" {
		t.Errorf("steps[0] = %+v", s)
	}
	if e13 := eff(t, inv, "svc:httpd", "tls.ciphersuites-tls13", vh); sortedJoin(e13.Values) != rhel9TLS13 {
		t.Errorf("TLS 1.3 = %+v", e13)
	}

	// 全体に書いた値は VirtualHost に引き継がれ、VirtualHost に書けばそちらが効く
	_, inv = collect(t, "rhel9", rhel9Web(t, "3.5.9", "1.el9_9", map[string]string{apacheConf: `SSLCipherSuite HIGH:!aNULL:!MD5:!kRSA
SSLProtocol -all +TLSv1.2
Listen 127.0.0.1:8443
Listen 127.0.0.1:8444
<VirtualHost 127.0.0.1:8443>
    ServerName inherit.lab.test
    SSLEngine on
` + apacheCerts + `</VirtualHost>
<VirtualHost 127.0.0.1:8444>
    ServerName override.lab.test
    SSLEngine on
` + apacheCerts + `    SSLCipherSuite ECDHE+AESGCM:DHE+AESGCM:AES128-SHA
    SSLProtocol all -SSLv3
</VirtualHost>
`}))
	checkSuites(t, eff(t, inv, "svc:httpd", "tls.ciphers", vh), 39, "c08400076f551c06", "high")
	checkSuites(t, eff(t, inv, "svc:httpd", "tls.ciphers", "VirtualHost 127.0.0.1:8444"), 7, "17da0592b5fe6045", "high")

	// PROFILE=SYSTEM
	_, inv = collect(t, "rhel9", rhel9Web(t, "3.5.9", "1.el9_9", map[string]string{apacheConf: "Listen 127.0.0.1:8443\n<VirtualHost 127.0.0.1:8443>\n    ServerName profile.lab.test\n    SSLEngine on\n" + apacheCerts + "    SSLCipherSuite PROFILE=SYSTEM\n</VirtualHost>\n"}))
	checkSuites(t, eff(t, inv, "svc:httpd", "tls.ciphers", vh), 31, "5cf20341674624f8", "high")

	// パッケージ既定の VirtualHost（_default_:443）は、証明書がまだ作られていないので、種類による絞り込みなしで求まる（確度は一段下）
	d := eff(t, inv, "svc:httpd", "tls.ciphers", "VirtualHost _default_:443")
	if d.Status != "resolved" || d.Confidence != "medium" || len(d.Values) < 31 {
		t.Errorf("packaged default vhost: %+v", d)
	}

	// SSLOpenSSLConfCmd があると、暗号文字列だけでは決まらない → 求めない
	_, inv = collect(t, "rhel9", rhel9Web(t, "3.5.9", "1.el9_9", map[string]string{apacheConf: "Listen 127.0.0.1:8443\n<VirtualHost 127.0.0.1:8443>\n    SSLEngine on\n" + apacheCerts + "    SSLOpenSSLConfCmd Ciphersuites TLS_AES_256_GCM_SHA384\n</VirtualHost>\n"}))
	if e := eff(t, inv, "svc:httpd", "tls.ciphers", vh); e.Status != "unresolved" || !strings.Contains(e.Reason, "SSLOpenSSLConfCmd") {
		t.Errorf("SSLOpenSSLConfCmd: %+v", e)
	}
	// TLS 1.3 のスイートをアプリの設定で指定している場合（SSLCipherSuite TLSv1.3 ...）は、TLS 1.3 の側だけ求めない
	_, inv = collect(t, "rhel9", rhel9Web(t, "3.5.9", "1.el9_9", map[string]string{apacheConf: "Listen 127.0.0.1:8443\n<VirtualHost 127.0.0.1:8443>\n    SSLEngine on\n" + apacheCerts + "    SSLCipherSuite TLSv1.3 TLS_AES_256_GCM_SHA384\n</VirtualHost>\n"}))
	checkSuites(t, eff(t, inv, "svc:httpd", "tls.ciphers", vh), 27, "e08c4d6580e60588", "high")
	if e := eff(t, inv, "svc:httpd", "tls.ciphersuites-tls13", vh); e.Status != "unresolved" {
		t.Errorf("TLS 1.3 suites set by the application: %+v", e)
	}
}

// Apache（Ubuntu 24.04）: パッケージの設定（mods-enabled/ssl.conf）が全体に SSLCipherSuite HIGH:!aNULL を書いている。
func TestApacheEffectiveCiphersUbuntu2404(t *testing.T) {
	site := "/etc/apache2/sites-enabled/lab-tls.conf"
	prepare := func(conf string) func(p string, b *inventory.Builder) {
		return func(p string, b *inventory.Builder) {
			b.AddPackage(model.Package{Manager: "dpkg", Name: "apache2-bin", Version: "2.4.58-1ubuntu8.18", Role: "tls-server"})
			b.AddPackage(model.Package{Manager: "dpkg", Name: "libssl3t64", Version: "3.0.13-0ubuntu3.16", Role: "crypto-library"})
			b.AddPackage(model.Package{Manager: "dpkg", Name: "libssl-dev", Version: "3.0.13-0ubuntu3.16", Role: "crypto-library"})
			link(t, p, "../mods-available/ssl.load", "/etc/apache2/mods-enabled/ssl.load")
			link(t, p, "../mods-available/ssl.conf", "/etc/apache2/mods-enabled/ssl.conf")
			writeCert(t, p+"/etc/lab/rsa.crt", "rsa")
			writeCert(t, p+"/etc/lab/ec.crt", "ec")
			os.MkdirAll(filepath.Dir(p+site), 0o755)
			os.WriteFile(p+site, []byte(conf), 0o644)
		}
	}
	vh := "VirtualHost 127.0.0.1:8443"
	_, inv := collect(t, "ubuntu2404", prepare("Listen 127.0.0.1:8443\n<VirtualHost 127.0.0.1:8443>\n    ServerName default.lab.test\n    SSLEngine on\n"+apacheCerts+"</VirtualHost>\n"))
	e := eff(t, inv, "svc:httpd", "tls.ciphers", vh)
	checkSuites(t, e, 59, "00df38bc54882866", "high")
	if e.Steps[0].Layer != "app-config" || e.Steps[0].Setting == "" {
		t.Errorf("steps[0] = %+v", e.Steps[0])
	}
	// システムの openssl.cnf に TLS 1.3 の指定がなければ、ライブラリの既定
	e13 := eff(t, inv, "svc:httpd", "tls.ciphersuites-tls13", vh)
	if sortedJoin(e13.Values) != ubuntuTLS13 || len(e13.Steps) == 0 || e13.Steps[0].Layer != "library" {
		t.Errorf("TLS 1.3 = %+v", e13)
	}
	// TLS のモジュールが読み込まれていなければ、実効値は出さない
	_, inv = collect(t, "ubuntu2404", func(p string, b *inventory.Builder) {
		b.AddPackage(model.Package{Manager: "dpkg", Name: "libssl3t64", Version: "3.0.13-0ubuntu3.16", Role: "crypto-library"})
	})
	for _, x := range inv.EffectiveValues {
		if x.Service == "svc:httpd" {
			t.Errorf("unexpected effective value without ssl_module: %+v", x)
		}
	}
}
