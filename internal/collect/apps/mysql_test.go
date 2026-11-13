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

// 以下の期待値（スイートの数と要約値、グループ）は、検証ラボで実際に MariaDB / MySQL を起動し、同じコンテナ内からの
// ハンドシェイクで数え上げた結果（AlmaLinux 9.8 の mariadb-server 10.5.29-3.el9_7.alma.1 と mysql-server 8.0.46-1.el9_8、
// Debian 13 の mariadb-server 1:11.8.6-0+deb13u1）。RHEL 系は、UBI にパッケージがないため AlmaLinux で測った。

const (
	myCnf  = "/etc/my.cnf"
	myLab  = "/etc/my.cnf.d/zz-lab.cnf"
	myMain = "[client-server]\n!includedir /etc/my.cnf.d\n"
	myRSA  = "[mysqld]\nbind-address = 127.0.0.1\nssl_cert = /etc/lab/rsa.crt\nssl_key = /etc/lab/rsa.key\n"
	myEC   = "[mysqld]\nssl_cert = /etc/lab/ec.crt\nssl_key = /etc/lab/ec.key\n"
)

func dbAlma9(t *testing.T, pkg, version, release, lab string) func(p string, b *inventory.Builder) {
	prepare := rhel9Web(t, "3.5.8", "2.el9_8", map[string]string{myCnf: myMain, myLab: lab})
	return withGroups(rhel9PolicyGroups, func(p string, b *inventory.Builder) {
		b.AddPackage(model.Package{Manager: "rpm", Name: pkg, Epoch: 3, Version: version, Release: release, Role: "database"})
		prepare(p, b)
	})
}

func mariadbAlma9(t *testing.T, lab string) func(p string, b *inventory.Builder) {
	return dbAlma9(t, "mariadb-server", "10.5.29", "3.el9_7.alma.1", lab)
}

func mysqlAlma9(t *testing.T, lab string) func(p string, b *inventory.Builder) {
	return dbAlma9(t, "mysql-server", "8.0.46", "1.el9_8", lab)
}

// MariaDB: 暗号の指定がなければ、MariaDB は何も設定せず、OpenSSL のシステム既定（RHEL 系では暗号ポリシー）になる。
// 鍵交換のグループと TLS 1.3 のスイートも、システムの設定に従う。証明書の指定がなければ、TLS は無効（10.5）。
func TestMariaDBEffective(t *testing.T) {
	_, inv := collect(t, "rhel9", mariadbAlma9(t, myRSA))
	e := eff(t, inv, "svc:mariadb", "tls.ciphers", "")
	checkSuites(t, e, 23, "1aae0270f9f74ce1", "high")
	if l := layers(e); !strings.HasPrefix(l, "app-default/default os-policy/override library/expand os-policy/security-level") {
		t.Errorf("steps = %s", l)
	}
	if g := groupsOf(t, inv, "svc:mariadb", ""); strings.Join(g.Values, " ") != alma9Groups {
		t.Errorf("groups = %v", g.Values)
	}
	// MySQL の設定としては読まない（MariaDB だけが導入されている）
	for _, s := range inv.Services {
		if s.App == "mysql" {
			t.Errorf("a MySQL service was reported on a MariaDB host: %+v", s)
		}
	}
	_, inv = collect(t, "rhel9", mariadbAlma9(t, myEC))
	checkSuites(t, eff(t, inv, "svc:mariadb", "tls.ciphers", ""), 8, "9fc1d4987559029c", "high")
	_, inv = collect(t, "rhel9", mariadbAlma9(t, myRSA+"ssl_cipher = ECDHE+AESGCM:DHE+AESGCM:AES128-SHA\n"))
	checkSuites(t, eff(t, inv, "svc:mariadb", "tls.ciphers", ""), 5, "c912afa74ee150e6", "high")
	// 項目名の「-」と「_」、後勝ち、別のグループ（[server]）の記載、読まれないグループ（[mysqldump]）
	_, inv = collect(t, "rhel9", mariadbAlma9(t, myRSA+"ssl-cipher = HIGH:!aNULL\nssl_cipher = \"HIGH:!aNULL:!kRSA\"   # later wins\n[mysqldump]\nssl_cipher = IGNORED\n[server]\nssl-cert=/etc/lab/ec.crt\nssl-key = /etc/lab/ec.key\n"))
	e = eff(t, inv, "svc:mariadb", "tls.ciphers", "")
	checkSuites(t, e, 13, "3b18ae1431c420e7", "high")
	if e.Steps[0].Layer != "app-config" || e.Steps[0].Setting == "" {
		t.Errorf("steps = %+v", e.Steps)
	}
	// 証明書の指定がない: 10.5 は TLS が無効
	_, inv = collect(t, "rhel9", mariadbAlma9(t, "[mysqld]\nbind-address = 127.0.0.1\n"))
	service(t, inv, "mariadb")
	for _, e := range inv.EffectiveValues {
		if e.Service == "svc:mariadb" {
			t.Errorf("TLS is off without a certificate in 10.5: %+v", e)
		}
	}
}

// MariaDB 11.8（Debian 13）: 証明書の指定がなくても、自分で用意した証明書（RSA）で TLS が有効。
// グループは OpenSSL 3.5 の既定に従うので、何も設定しなくても耐量子のハイブリッド（X25519MLKEM768）を受け入れる。
func TestMariaDBDebian13(t *testing.T) {
	deb := func(conf string) func(p string, b *inventory.Builder) {
		prepare := postfixDeb(t, "3.10.13-0+deb13u1", "libssl3t64", "3.5.7-1~deb13u3", map[string]string{"/etc/mysql/my.cnf": "!includedir /etc/mysql/mariadb.conf.d/\n", "/etc/mysql/mariadb.conf.d/50-server.cnf": conf})
		return func(p string, b *inventory.Builder) {
			b.AddPackage(model.Package{Manager: "dpkg", Name: "mariadb-server", Version: "1:11.8.6-0+deb13u1", Role: "database"})
			prepare(p, b)
		}
	}
	_, inv := collect(t, "", deb("[mysqld]\nbind-address = 127.0.0.1\n"))
	e := eff(t, inv, "svc:mariadb", "tls.ciphers", "")
	checkSuites(t, e, 20, "5d7b3a7e73aa210c", "high")
	if g := groupsOf(t, inv, "svc:mariadb", ""); strings.Join(g.Values, " ") != "X25519MLKEM768 X25519 P-256 X448 P-384 P-521 ffdhe2048 ffdhe3072" {
		t.Errorf("groups = %v", g.Values)
	}
	_, inv = collect(t, "", deb(myEC))
	checkSuites(t, eff(t, inv, "svc:mariadb", "tls.ciphers", ""), 7, "fae0cc14515bb2c5", "high")
}

// MySQL: 暗号の指定がなければ、MySQL が内蔵する既定の並び。設定に書いた暗号文字列には、拒否する暗号の並びが後ろに足される。
// 鍵交換のグループは MySQL が自分で決め（P-256、P-384、P-521）、X25519 も耐量子のハイブリッドも受け入れない。
// 証明書の指定がなくても、データディレクトリに自分で用意した証明書（RSA）で TLS が有効。
func TestMySQLEffective(t *testing.T) {
	_, inv := collect(t, "rhel9", mysqlAlma9(t, myRSA))
	e := eff(t, inv, "svc:mysql", "tls.ciphers", "")
	checkSuites(t, e, 20, "3c3c5b556371eddf", "high")
	if e.Steps[0].Layer != "app-default" || e.Steps[0].Source == nil || e.Steps[0].Source.Package != "mysql-server" {
		t.Errorf("steps = %+v", e.Steps)
	}
	g := groupsOf(t, inv, "svc:mysql", "")
	if strings.Join(g.Values, " ") != "P-256 P-384 P-521" || g.Steps[0].Layer != "app-default" {
		t.Errorf("groups = %+v", g)
	}
	if e13 := eff(t, inv, "svc:mysql", "tls.ciphersuites-tls13", ""); sortedJoin(e13.Values) != rhel9TLS13 {
		t.Errorf("tls13 = %+v", e13)
	}
	for _, s := range inv.Services {
		if s.App == "mariadb" {
			t.Errorf("a MariaDB service was reported on a MySQL host: %+v", s)
		}
	}
	_, inv = collect(t, "rhel9", mysqlAlma9(t, myEC))
	checkSuites(t, eff(t, inv, "svc:mysql", "tls.ciphers", ""), 6, "9ce46948c3293377", "high")
	_, inv = collect(t, "rhel9", mysqlAlma9(t, myRSA+"ssl_cipher = ECDHE+AESGCM:DHE+AESGCM:AES128-SHA\ntls_ciphersuites = TLS_AES_256_GCM_SHA384\n"))
	checkSuites(t, eff(t, inv, "svc:mysql", "tls.ciphers", ""), 5, "c912afa74ee150e6", "high")
	if e13 := eff(t, inv, "svc:mysql", "tls.ciphersuites-tls13", ""); strings.Join(e13.Values, ",") != "TLS_AES_256_GCM_SHA384" {
		t.Errorf("configured tls13 = %+v", e13)
	}
	_, inv = collect(t, "rhel9", mysqlAlma9(t, myRSA+"ssl_cipher = HIGH:!aNULL:!kRSA\n[server]\nssl-cert=/etc/lab/ec.crt\nssl-key = /etc/lab/ec.key\n"))
	checkSuites(t, eff(t, inv, "svc:mysql", "tls.ciphers", ""), 13, "3b18ae1431c420e7", "high")
	// 証明書の指定がない: データディレクトリの server-cert.pem（自動で作られる）が使われる
	_, inv = collect(t, "rhel9", func(p string, b *inventory.Builder) {
		mysqlAlma9(t, "[mysqld]\ndatadir=/var/lib/mysql\n")(p, b)
		os.MkdirAll(p+"/var/lib/mysql", 0o755)
		data, _ := os.ReadFile(filepath.Join(p, "etc/lab/rsa.crt"))
		os.WriteFile(p+"/var/lib/mysql/server-cert.pem", data, 0o644)
	})
	checkSuites(t, eff(t, inv, "svc:mysql", "tls.ciphers", ""), 20, "3c3c5b556371eddf", "high")
	// TLS を切っている設定
	_, inv = collect(t, "rhel9", mysqlAlma9(t, "[mysqld]\nskip-ssl\n"))
	for _, e := range inv.EffectiveValues {
		if e.Service == "svc:mysql" {
			t.Errorf("TLS is off: %+v", e)
		}
	}
}
