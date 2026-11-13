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

// 以下の期待値（スイートの数と要約値、グループ）は、検証ラボで実際に Postfix を起動し、同じコンテナ内からのハンドシェイク
// （openssl s_client -starttls smtp）で受け入れるスイートとグループを数え上げた結果
// （RHEL 9.9 の postfix 3.5.25-3.el9_8、Debian 13 の 3.10.13-0+deb13u1、Ubuntu 20.04 の 3.4.13-0ubuntu1.4）。
// 設定は、そのときと同じ意味のものを最小限に書いている。

const (
	postfixMain   = "/etc/postfix/main.cf"
	postfixMaster = "/etc/postfix/master.cf"
	// 証明書（RSA と ECDSA）と、STARTTLS を任意で受け付ける設定
	postfixBase = "myhostname = lab.test\nsmtpd_tls_cert_file = /etc/lab/rsa.crt\nsmtpd_tls_key_file = /etc/lab/rsa.key\n" +
		"smtpd_tls_eccert_file = /etc/lab/ec.crt\nsmtpd_tls_eckey_file = /etc/lab/ec.key\nsmtpd_tls_security_level = may\n"
	postfixSMTP = "127.0.0.1:8025 inet n - n - - smtpd\npickup    unix  n       -       n       60      1       pickup\n"
	smtpScope   = "service 127.0.0.1:8025 inet"
)

func postfixFiles(main, master string) map[string]string {
	return map[string]string{postfixMain: main, postfixMaster: master}
}

func postfixRHEL9(t *testing.T, files map[string]string) func(p string, b *inventory.Builder) {
	prepare := rhel9Web(t, "3.5.9", "1.el9_9", files)
	return func(p string, b *inventory.Builder) {
		b.AddPackage(model.Package{Manager: "rpm", Name: "postfix", Epoch: 2, Version: "3.5.25", Release: "3.el9_8", Role: "mail-server"})
		prepare(p, b)
	}
}

// postfixDeb は、Debian 系に postfix を導入した状態を作る（システムの openssl.cnf に暗号の指定はない）。
func postfixDeb(t *testing.T, postfix, libssl, libsslVersion string, files map[string]string) func(p string, b *inventory.Builder) {
	return func(p string, b *inventory.Builder) {
		b.AddPackage(model.Package{Manager: "dpkg", Name: "postfix", Version: postfix, Role: "mail-server"})
		b.AddPackage(model.Package{Manager: "dpkg", Name: libssl, Version: libsslVersion, Role: "crypto-library"})
		writeCert(t, p+"/etc/lab/rsa.crt", "rsa")
		writeCert(t, p+"/etc/lab/ec.crt", "ec")
		for name, content := range files {
			os.MkdirAll(filepath.Dir(p+name), 0o755)
			os.WriteFile(p+name, []byte(content), 0o644)
		}
	}
}

func contains(values []string, name string) bool {
	for _, v := range values {
		if v == name {
			return true
		}
	}
	return false
}

// 暗号の指定がなければ、等級 medium の暗号文字列になる。Postfix はセキュリティレベルを 0 にするので、
// RHEL の暗号ポリシー（レベル 2）は効かず、認証なし（匿名）のスイートも受け入れる。
func TestPostfixEffectiveCiphersDefault(t *testing.T) {
	_, inv := collect(t, "rhel9", postfixRHEL9(t, postfixFiles(postfixBase, postfixSMTP)))
	e := eff(t, inv, "svc:postfix", "tls.ciphers", smtpScope)
	checkSuites(t, e, 71, "0ff7fe49b63a24a1", "high")
	if e.Direction != "inbound" || !contains(e.Values, "ADH-AES256-GCM-SHA384") || !contains(e.Values, "AES256-SHA") {
		t.Errorf("direction=%s values=%v", e.Direction, e.Values)
	}
	// どう求めたか: アプリの既定 → ライブラリでの展開 → アプリが決めるセキュリティレベル（システムの設定ではない）
	if l := layers(e); !strings.HasPrefix(l, "app-default/default library/expand app-default/security-level") || strings.Contains(l, "os-policy") {
		t.Errorf("steps = %s", l)
	}
	if s := e.Steps[0].Source; s == nil || s.Package != "postfix" || s.Version != "3.5.25-3.el9_8" {
		t.Errorf("app default source = %+v", e.Steps[0].Source)
	}
	// TLS 1.3 のスイートは Postfix が設定しないので、システムの暗号ポリシーの 4 個
	if e13 := eff(t, inv, "svc:postfix", "tls.ciphersuites-tls13", smtpScope); e13.Status != "resolved" || sortedJoin(e13.Values) != rhel9TLS13 {
		t.Errorf("tls13 = %+v", e13)
	}
	// 鍵交換のグループは Postfix 自身の既定。システムの設定にもライブラリの既定にも従わない（耐量子のハイブリッドを受け入れない）
	g := groupsOf(t, withSystemGroups(t, postfixFiles(postfixBase, postfixSMTP)), "svc:postfix", smtpScope)
	if strings.Join(g.Values, " ") != "X25519 X448 P-256 P-521 P-384" || g.Steps[0].Layer != "app-default" || g.Steps[0].Source == nil || g.Confidence != "high" {
		t.Errorf("groups = %+v", g)
	}

	// Ubuntu 20.04（OpenSSL 1.1.1f）と Debian 13（OpenSSL 3.5.7。等級の暗号文字列が違う）
	_, inv = collect(t, "", postfixDeb(t, "3.4.13-0ubuntu1.4", "libssl1.1", "1.1.1f-1ubuntu2.24", postfixFiles(postfixBase, postfixSMTP)))
	checkSuites(t, eff(t, inv, "svc:postfix", "tls.ciphers", smtpScope), 74, "547c6db55b763f88", "high")
	if e13 := eff(t, inv, "svc:postfix", "tls.ciphersuites-tls13", smtpScope); sortedJoin(e13.Values) != ubuntuTLS13 {
		t.Errorf("ubuntu tls13 = %+v", e13)
	}
	_, inv = collect(t, "", postfixDeb(t, "3.10.13-0+deb13u1", "libssl3t64", "3.5.7-1~deb13u3", postfixFiles(postfixBase, postfixSMTP)))
	checkSuites(t, eff(t, inv, "svc:postfix", "tls.ciphers", smtpScope), 71, "0ff7fe49b63a24a1", "high")
	// Postfix 3.10 は、有限体 DH のグループも自分で決める。OpenSSL 3.5 の既定（X25519MLKEM768 を含む）にはならない
	if g := groupsOf(t, inv, "svc:postfix", smtpScope); strings.Join(g.Values, " ") != "X25519 X448 P-256 P-384 P-521 ffdhe2048 ffdhe3072" {
		t.Errorf("debian groups = %v", g.Values)
	}
}

// withSystemGroups は、RHEL 9.9 の暗号ポリシーの Groups がある状態で、Postfix の設定を読む。
func withSystemGroups(t *testing.T, files map[string]string) *model.Inventory {
	t.Helper()
	_, inv := collect(t, "rhel9", withGroups(rhel9PolicyGroups, postfixRHEL9(t, files)))
	return inv
}

// 等級、除外の指定、等級に対応する暗号文字列の書き換え、証明書の種類。
func TestPostfixEffectiveCiphersGradesAndExclusions(t *testing.T) {
	for _, c := range []struct {
		name, extra string
		count       int
		digest      string
	}{
		{"high", "smtpd_tls_ciphers = high\n", 65, "69613f6aa913dc4f"},
		{"exclude", "smtpd_tls_exclude_ciphers = aNULL, MD5, DES, 3DES\n", 59, "00df38bc54882866"},
		{"cipherlist", "tls_medium_cipherlist = HIGH:!aNULL:!kRSA:@STRENGTH\n", 39, "c08400076f551c06"},
		// ほかの項目の値を参照する書き方（$名前）
		{"reference", "smtpd_tls_mandatory_ciphers = high\nsmtpd_tls_ciphers = ${smtpd_tls_mandatory_ciphers}\n", 65, "69613f6aa913dc4f"},
	} {
		_, inv := collect(t, "rhel9", postfixRHEL9(t, postfixFiles(postfixBase+c.extra, postfixSMTP)))
		e := eff(t, inv, "svc:postfix", "tls.ciphers", smtpScope)
		checkSuites(t, e, c.count, c.digest, "high")
		if e.Steps[0].Layer != "app-config" || e.Steps[0].Setting == "" {
			t.Errorf("%s: steps = %+v", c.name, e.Steps)
		}
	}
	// 証明書が RSA だけなら、ECDSA のスイートは使えない（匿名のスイートは残る）
	rsaOnly := "myhostname = lab.test\nsmtpd_tls_cert_file = /etc/lab/rsa.crt\nsmtpd_tls_key_file = /etc/lab/rsa.key\nsmtpd_tls_security_level = may\n"
	_, inv := collect(t, "rhel9", postfixRHEL9(t, postfixFiles(rsaOnly, postfixSMTP)))
	checkSuites(t, eff(t, inv, "svc:postfix", "tls.ciphers", smtpScope), 56, "429d1a7d2aa73683", "high")
	// 証明書なし（none）: 匿名のスイートだけになり、TLS 1.3 は使えない
	_, inv = collect(t, "rhel9", postfixRHEL9(t, postfixFiles("smtpd_tls_cert_file = none\nsmtpd_tls_security_level = may\n", postfixSMTP)))
	e := eff(t, inv, "svc:postfix", "tls.ciphers", smtpScope)
	checkSuites(t, e, 12, "4c94c71dd2c4d570", "high")
	for _, v := range e.Values {
		if !strings.HasPrefix(v, "ADH-") && !strings.HasPrefix(v, "AECDH-") {
			t.Errorf("a suite that needs a certificate: %s", v)
		}
	}
	if e13 := eff(t, inv, "svc:postfix", "tls.ciphersuites-tls13", smtpScope); len(e13.Values) != 0 {
		t.Errorf("tls13 without a certificate = %+v", e13)
	}
}

// master.cf のサービスごとの上書き（-o）。STARTTLS が必須のサービスと、最初から TLS のサービスは、「必須」のときの等級と除外を使う。
func TestPostfixServicesAndOverrides(t *testing.T) {
	main := postfixBase + "smtpd_tls_exclude_ciphers = aNULL, MD5, DES, 3DES\nsmtpd_tls_mandatory_exclude_ciphers = kRSA\n"
	master := postfixSMTP + "127.0.0.1:8587 inet n - n - - smtpd\n  -o smtpd_tls_security_level=encrypt\n" +
		"127.0.0.1:8465 inet n - n - - smtpd\n  -o smtpd_tls_wrappermode=yes\n  -o smtpd_tls_security_level=encrypt\n  -o smtpd_tls_mandatory_ciphers=high\n" +
		"lab-unix unix n - n - - smtpd\n[::1]:8525 inet n - n - 1 postscreen\n"
	_, inv := collect(t, "rhel9", postfixRHEL9(t, postfixFiles(main, master)))
	checkSuites(t, eff(t, inv, "svc:postfix", "tls.ciphers", smtpScope), 59, "00df38bc54882866", "high")
	checkSuites(t, eff(t, inv, "svc:postfix", "tls.ciphers", "service 127.0.0.1:8587 inet"), 43, "17754a2af349e17e", "high")
	checkSuites(t, eff(t, inv, "svc:postfix", "tls.ciphers", "service 127.0.0.1:8465 inet"), 39, "c08400076f551c06", "high")
	// 待ち受けるのは、種類が inet で、プログラムが smtpd のサービスだけ
	n := 0
	for _, e := range inv.EffectiveValues {
		if e.Service == "svc:postfix" && e.Parameter == "tls.ciphers" {
			n++
		}
	}
	if n != 3 {
		t.Errorf("%d scopes have tls.ciphers, want 3", n)
	}

	// 最初から TLS の待ち受け（wrappermode）は、STARTTLS が任意の設定のままでも、「必須」のときの等級（既定の medium）を使う
	master = postfixSMTP + "127.0.0.1:8465 inet n - n - - smtpd\n  -o smtpd_tls_wrappermode=yes\n"
	_, inv = collect(t, "rhel9", postfixRHEL9(t, postfixFiles(postfixBase+"smtpd_tls_ciphers = high\n", master)))
	checkSuites(t, eff(t, inv, "svc:postfix", "tls.ciphers", smtpScope), 65, "69613f6aa913dc4f", "high")
	checkSuites(t, eff(t, inv, "svc:postfix", "tls.ciphers", "service 127.0.0.1:8465 inet"), 71, "0ff7fe49b63a24a1", "high")
}

// 鍵交換のグループの指定。古い書き方（等級）が効くかどうかは、版による。
func TestPostfixGroups(t *testing.T) {
	main := postfixBase + "tls_eecdh_auto_curves = secp384r1 X25519\n"
	master := postfixSMTP + "127.0.0.1:8587 inet n - n - - smtpd\n  -o smtpd_tls_eecdh_grade=ultra\n"
	_, inv := collect(t, "rhel9", postfixRHEL9(t, postfixFiles(main, master)))
	g := groupsOf(t, inv, "svc:postfix", smtpScope)
	if strings.Join(g.Values, " ") != "P-384 X25519" || g.Steps[0].Layer != "app-config" || g.Steps[0].Setting == "" {
		t.Errorf("custom groups = %+v", g)
	}
	// Postfix 3.5: 等級 ultra の指定が効き、その曲線（secp384r1）だけになる
	if g := groupsOf(t, inv, "svc:postfix", "service 127.0.0.1:8587 inet"); strings.Join(g.Values, " ") != "P-384" {
		t.Errorf("3.5 ultra = %v", g.Values)
	}
	// Postfix 3.10: 等級の指定は効かない。有限体 DH のグループは、既定のまま加わる
	_, inv = collect(t, "", postfixDeb(t, "3.10.13-0+deb13u1", "libssl3t64", "3.5.7-1~deb13u3", postfixFiles(main, master)))
	for _, scope := range []string{smtpScope, "service 127.0.0.1:8587 inet"} {
		if g := groupsOf(t, inv, "svc:postfix", scope); strings.Join(g.Values, " ") != "P-384 X25519 ffdhe2048 ffdhe3072" {
			t.Errorf("3.10 [%s] = %v", scope, g.Values)
		}
	}
}

// TLS を使わない設定では、実効値を作らない。古い書き方（smtpd_use_tls = yes）は、STARTTLS が任意の設定と同じ。
func TestPostfixTLSDisabledAndLegacySwitch(t *testing.T) {
	noTLS := "myhostname = lab.test\nsmtpd_tls_cert_file = /etc/lab/rsa.crt\nsmtpd_tls_key_file = /etc/lab/rsa.key\n"
	_, inv := collect(t, "rhel9", postfixRHEL9(t, postfixFiles(noTLS, postfixSMTP)))
	service(t, inv, "postfix")
	for _, e := range inv.EffectiveValues {
		if e.Service == "svc:postfix" {
			t.Errorf("TLS is off, but an effective value was produced: %+v", e)
		}
	}
	// 設定に書かれた値は記録する
	if len(byParam(inv, "svc:postfix")["inbound:tls.certificate"]) == 0 {
		t.Errorf("settings = %+v", byParam(inv, "svc:postfix"))
	}
	_, inv = collect(t, "rhel9", postfixRHEL9(t, postfixFiles(noTLS+"smtpd_use_tls = yes\n", postfixSMTP)))
	checkSuites(t, eff(t, inv, "svc:postfix", "tls.ciphers", smtpScope), 56, "429d1a7d2aa73683", "high")
	// サービスごとの上書きで TLS を切っている場合
	_, inv = collect(t, "rhel9", postfixRHEL9(t, postfixFiles(postfixBase, "127.0.0.1:8025 inet n - n - - smtpd -o smtpd_tls_security_level=none\n")))
	for _, e := range inv.EffectiveValues {
		if e.Service == "svc:postfix" {
			t.Errorf("TLS is off for this service: %+v", e)
		}
	}
}

// 求められない場合と、確度が下がる場合。
func TestPostfixLimits(t *testing.T) {
	unresolved := func(main, want string) {
		t.Helper()
		_, inv := collect(t, "rhel9", postfixRHEL9(t, postfixFiles(main, postfixSMTP)))
		if e := eff(t, inv, "svc:postfix", "tls.ciphers", smtpScope); e.Status != "unresolved" || !strings.Contains(e.Reason, want) {
			t.Errorf("want unresolved (%s): %+v", want, e)
		}
	}
	// 値の分からない項目への参照、条件つきの書き方、循環する参照、知らない等級
	unresolved(postfixBase+"smtpd_tls_ciphers = $my_own_grade\n", "my_own_grade")
	unresolved(postfixBase+"smtpd_tls_ciphers = ${smtpd_tls_ask_ccert?high}\n", "smtpd_tls_ciphers")
	unresolved(postfixBase+"smtpd_tls_ciphers = $smtpd_tls_mandatory_ciphers\nsmtpd_tls_mandatory_ciphers = $smtpd_tls_ciphers\n", "smtpd_tls_ciphers")
	unresolved(postfixBase+"smtpd_tls_ciphers = strongest\n", "grade")
	// 既定値を測っていない版 → 求めない
	_, inv := collect(t, "", postfixDeb(t, "9.9.9-1", "libssl3t64", "3.5.7-1~deb13u3", postfixFiles(postfixBase, postfixSMTP)))
	if e := eff(t, inv, "svc:postfix", "tls.ciphers", smtpScope); e.Status != "unresolved" || !strings.Contains(e.Reason, "postfix 9.9.9-1") {
		t.Errorf("unknown version: %+v", e)
	}
	// 証明書の指定を追えない書き方（鍵と証明書をまとめたファイルの並び）→ 証明書による絞り込みをせず、確度を下げる
	_, inv = collect(t, "rhel9", postfixRHEL9(t, postfixFiles("smtpd_tls_chain_files = /etc/lab/all.pem\nsmtpd_tls_security_level = may\n", postfixSMTP)))
	if e := eff(t, inv, "svc:postfix", "tls.ciphers", smtpScope); e.Status != "resolved" || e.Confidence != "medium" {
		t.Errorf("chain files: %+v", e)
	}
	// 補間（リリースだけが違う）→ 確度を一段下げ、実測した版を注記に残す
	_, inv = collect(t, "rhel9", func(p string, b *inventory.Builder) {
		b.AddPackage(model.Package{Manager: "rpm", Name: "postfix", Epoch: 2, Version: "3.5.25", Release: "4.el9_9", Role: "mail-server"})
		rhel9Web(t, "3.5.9", "1.el9_9", postfixFiles(postfixBase, postfixSMTP))(p, b)
	})
	if e := eff(t, inv, "svc:postfix", "tls.ciphers", smtpScope); e.Confidence != "medium" || !strings.Contains(strings.Join(e.Notes, " "), "3.5.25-3.el9_8") {
		t.Errorf("interpolated: %+v", e)
	}
}

// 証明書を持たないサービスでは TLS 1.3 を使えないので、TLS 1.3 でだけ使われるグループ（有限体 DH）は受け入れない
// （Debian 13 の postfix 3.10.13 で、認証なしの ECDH のスイートを使って実測）。
func TestPostfixGroupsWithoutCertificate(t *testing.T) {
	_, inv := collect(t, "", postfixDeb(t, "3.10.13-0+deb13u1", "libssl3t64", "3.5.7-1~deb13u3",
		postfixFiles("smtpd_tls_cert_file = none\nsmtpd_tls_security_level = may\n", postfixSMTP)))
	g := groupsOf(t, inv, "svc:postfix", smtpScope)
	if strings.Join(g.Values, " ") != "X25519 X448 P-256 P-384 P-521" || g.Confidence != "high" {
		t.Errorf("groups without a certificate = %+v", g)
	}
}
