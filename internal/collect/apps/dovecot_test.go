//go:build unix

package apps

import (
	"strings"
	"testing"

	"kagiya/internal/inventory"
	"kagiya/internal/model"
)

// 以下の期待値（スイートの数と要約値、グループ）は、検証ラボで実際に Dovecot を起動し、同じコンテナ内からのハンドシェイク
// （openssl s_client。imaps と pop3s）で数え上げた結果（AlmaLinux 9.8 の dovecot 2.3.16-18.el9_8.8 と openssl-libs 3.5.8-2.el9_8、
// Debian 13 の dovecot-core 1:2.4.1+dfsg1-6+deb13u7）。RHEL 系は、UBI にパッケージがないため AlmaLinux で測った。

const (
	dovecotConf = "/etc/dovecot/dovecot.conf"
	dovecotSSL  = "/etc/dovecot/conf.d/10-ssl.conf"
	dovecotLab  = "/etc/dovecot/conf.d/zz-lab.conf"
	dovecotMain = "protocols = imap pop3\n!include conf.d/*.conf\n"
	// RHEL 系が配る設定（暗号に関わる行）
	dovecotRHELSSL = "ssl = required\nssl_cert = </etc/lab/rsa.crt\nssl_key = </etc/lab/rsa.key\nssl_cipher_list = PROFILE=SYSTEM\n"
	dovecotRSA     = "ssl = yes\nssl_cert = </etc/lab/rsa.crt\nssl_key = </etc/lab/rsa.key\n"
	dovecotRSA24   = "ssl = yes\nssl_server_cert_file = /etc/lab/rsa.crt\nssl_server_key_file = /etc/lab/rsa.key\n"
	alma9Groups    = "X25519 P-256 X448 P-521 P-384 ffdhe2048 ffdhe3072 ffdhe4096 ffdhe6144 ffdhe8192"
)

func dovecotAlma9(t *testing.T, lab string) func(p string, b *inventory.Builder) {
	prepare := rhel9Web(t, "3.5.8", "2.el9_8", map[string]string{dovecotConf: dovecotMain, dovecotSSL: dovecotRHELSSL, dovecotLab: lab})
	return withGroups(rhel9PolicyGroups, func(p string, b *inventory.Builder) {
		b.AddPackage(model.Package{Manager: "rpm", Name: "dovecot", Epoch: 1, Version: "2.3.16", Release: "18.el9_8.8", Role: "mail-server"})
		prepare(p, b)
	})
}

func dovecotDebian13(t *testing.T, lab string) func(p string, b *inventory.Builder) {
	prepare := postfixDeb(t, "3.10.13-0+deb13u1", "libssl3t64", "3.5.7-1~deb13u3", map[string]string{dovecotConf: "dovecot_config_version = 2.4.0\n" + dovecotMain, dovecotLab: lab})
	return func(p string, b *inventory.Builder) {
		b.AddPackage(model.Package{Manager: "dpkg", Name: "dovecot-core", Version: "1:2.4.1+dfsg1-6+deb13u7", Role: "mail-server"})
		prepare(p, b)
	}
}

func dvEff(t *testing.T, inv *model.Inventory, param, scope string) model.EffectiveValue {
	t.Helper()
	return eff(t, inv, "svc:dovecot", param, scope)
}

// RHEL 系が配る設定は、暗号文字列に PROFILE=SYSTEM（暗号ポリシー）を指定している。しかし、接続を受けるプロセスは chroot の中で動き、
// 暗号ポリシーのファイルを読めないので、実際にはライブラリの既定（DEFAULT）になる。chroot を外した設定では、暗号ポリシーどおりになる。
func TestDovecotProfileSystemInChroot(t *testing.T) {
	_, inv := collect(t, "rhel9", dovecotAlma9(t, ""))
	e := dvEff(t, inv, "tls.ciphers", "")
	checkSuites(t, e, 13, "6521c40a0f41163b", "high")
	if !strings.Contains(strings.Join(e.Notes, " "), "chroot") || e.Steps[0].Layer != "app-config" {
		t.Errorf("the effect of the chroot must be explained: %+v", e)
	}
	// TLS 1.3 のスイートとグループは、システムの設定に従う（Dovecot 自身の既定はない）
	if e13 := dvEff(t, inv, "tls.ciphersuites-tls13", ""); sortedJoin(e13.Values) != rhel9TLS13 {
		t.Errorf("tls13 = %+v", e13)
	}
	if g := groupsOf(t, inv, "svc:dovecot", ""); strings.Join(g.Values, " ") != alma9Groups || !strings.HasPrefix(layers(g), "os-policy/override") {
		t.Errorf("groups = %+v", g)
	}
	// 続きを書いた場合（PROFILE=SYSTEM:!kRSA）も、先頭がライブラリの既定に置き換わる
	_, inv = collect(t, "rhel9", dovecotAlma9(t, "ssl_cipher_list = PROFILE=SYSTEM:!kRSA\n"))
	checkSuites(t, dvEff(t, inv, "tls.ciphers", ""), 7, "568d80fb3f9207f9", "high")
	// chroot を外すと、暗号ポリシーどおり
	_, inv = collect(t, "rhel9", dovecotAlma9(t, "service imap-login {\n  chroot =\n}\n"))
	e = dvEff(t, inv, "tls.ciphers", "protocol imap")
	checkSuites(t, e, 14, "e0b9c520bf39d246", "high")
	if strings.Contains(strings.Join(e.Notes, " "), "chroot") {
		t.Errorf("notes = %v", e.Notes)
	}
	// 同じ設定でも、chroot を外していないプロトコル（pop3 など）は、ライブラリの既定のまま
	checkSuites(t, dvEff(t, inv, "tls.ciphers", ""), 13, "6521c40a0f41163b", "high")
}

// 設定の記載: 証明書（2 つまで）、暗号文字列、DH パラメータ、曲線、TLS 1.3 のスイート、プロトコルごとの上書き。
func TestDovecotConfigured(t *testing.T) {
	for _, c := range []struct {
		name, lab string
		count     int
		digest    string
	}{
		{"ec", "ssl_cert = </etc/lab/ec.crt\nssl_key = </etc/lab/ec.key\n", 7, "fae0cc14515bb2c5"},
		{"both", "ssl_alt_cert = </etc/lab/ec.crt\nssl_alt_key = </etc/lab/ec.key\n", 20, "2a06ff1e94ff51a2"},
		{"ciphers", "ssl_cipher_list = ECDHE+AESGCM:DHE+AESGCM:AES128-SHA\n", 3, "ab9f4f5b40e78756"},
		// DHE は、DH パラメータのファイルを指定したときだけ使える
		{"dhparams", "ssl_dh = </etc/lab/dh.pem\nssl_cipher_list = DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-SHA:AES256-SHA\n", 3, "f6cfcb7ed6912e5f"},
		{"nodh", "ssl_cipher_list = DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-SHA:AES256-SHA\n", 1, "4672e179193d567e"},
	} {
		_, inv := collect(t, "rhel9", dovecotAlma9(t, c.lab))
		checkSuites(t, dvEff(t, inv, "tls.ciphers", ""), c.count, c.digest, "high")
	}
	_, inv := collect(t, "rhel9", dovecotAlma9(t, "ssl_curve_list = secp384r1:X25519\nssl_cipher_suites = TLS_AES_256_GCM_SHA384\n"))
	if g := groupsOf(t, inv, "svc:dovecot", ""); strings.Join(g.Values, " ") != "P-384 X25519" || g.Steps[0].Layer != "app-config" || g.Steps[0].Setting == "" {
		t.Errorf("curves = %+v", g)
	}
	if e13 := dvEff(t, inv, "tls.ciphersuites-tls13", ""); strings.Join(e13.Values, ",") != "TLS_AES_256_GCM_SHA384" || e13.Steps[0].Layer != "app-config" {
		t.Errorf("tls13 = %+v", e13)
	}
	// プロトコルごとの上書き: imap だけ暗号を変える。ほかのプロトコルは、全体の記載のまま
	_, inv = collect(t, "rhel9", dovecotAlma9(t, "ssl_cipher_list = HIGH:!aNULL:!kRSA\nprotocol imap {\n  ssl_cipher_list = ECDHE+AESGCM\n}\n"))
	checkSuites(t, dvEff(t, inv, "tls.ciphers", "protocol imap"), 2, "ca92f21dfad7d0c6", "high")
	checkSuites(t, dvEff(t, inv, "tls.ciphers", ""), 11, "75004e607f9fce0b", "high")
}

// Debian 13（Dovecot 2.4。証明書などの項目の名前が違う）。暗号の指定がなければ Dovecot の既定の暗号文字列。
// グループは OpenSSL 3.5 の既定に従うので、何も設定しなくても耐量子のハイブリッド（X25519MLKEM768）を受け入れる。
func TestDovecotDebian13(t *testing.T) {
	_, inv := collect(t, "", dovecotDebian13(t, dovecotRSA24))
	e := dvEff(t, inv, "tls.ciphers", "")
	checkSuites(t, e, 11, "75004e607f9fce0b", "high")
	if e.Steps[0].Layer != "app-default" || e.Steps[0].Source == nil || e.Steps[0].Source.Package != "dovecot-core" {
		t.Errorf("steps = %+v", e.Steps)
	}
	if g := groupsOf(t, inv, "svc:dovecot", ""); strings.Join(g.Values, " ") != "X25519MLKEM768 X25519 P-256 X448 P-384 P-521 ffdhe2048 ffdhe3072" || !strings.HasPrefix(layers(g), "library/default") {
		t.Errorf("groups = %+v", g)
	}
	_, inv = collect(t, "", dovecotDebian13(t, dovecotRSA24+"ssl_server_alt_cert_file = /etc/lab/ec.crt\nssl_server_alt_key_file = /etc/lab/ec.key\n"))
	checkSuites(t, dvEff(t, inv, "tls.ciphers", ""), 24, "f369e3d2fa271458", "high")
	_, inv = collect(t, "", dovecotDebian13(t, dovecotRSA24+"ssl_server_dh_file = /etc/lab/dh.pem\nssl_cipher_list = DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-SHA:AES256-SHA\n"))
	checkSuites(t, dvEff(t, inv, "tls.ciphers", ""), 3, "f6cfcb7ed6912e5f", "high")
}

// TLS を使わない設定では、実効値を作らない。追えない書き方は、求めない。
func TestDovecotDisabledAndLimits(t *testing.T) {
	_, inv := collect(t, "rhel9", dovecotAlma9(t, "ssl = no\n"))
	service(t, inv, "dovecot")
	for _, e := range inv.EffectiveValues {
		if e.Service == "svc:dovecot" {
			t.Errorf("ssl is off, but an effective value was produced: %+v", e)
		}
	}
	// 接続先の名前や接続元ごとの設定（local_name、local、remote）の中の TLS の指定は追わない
	_, inv = collect(t, "rhel9", dovecotAlma9(t, "local_name mail.example.jp {\n  ssl_cipher_list = HIGH\n}\n"))
	if e := dvEff(t, inv, "tls.ciphers", ""); e.Status != "unresolved" || !strings.Contains(e.Reason, "local_name") {
		t.Errorf("local_name: %+v", e)
	}
	// 既定値を測っていない版
	_, inv = collect(t, "rhel9", func(p string, b *inventory.Builder) {
		b.AddPackage(model.Package{Manager: "rpm", Name: "dovecot", Epoch: 1, Version: "9.9.9", Release: "1.el9", Role: "mail-server"})
		rhel9Web(t, "3.5.8", "2.el9_8", map[string]string{dovecotConf: dovecotMain, dovecotLab: dovecotRSA})(p, b)
	})
	if e := dvEff(t, inv, "tls.ciphers", ""); e.Status != "unresolved" || !strings.Contains(e.Reason, "dovecot 9.9.9-1.el9") {
		t.Errorf("unknown version: %+v", e)
	}
}
