//go:build unix

package apps

import (
	"strings"
	"testing"

	"kagiya/internal/inventory"
	"kagiya/internal/model"
)

// 以下の期待値（スイートの数と要約値、グループ）は、検証ラボで実際に PostgreSQL を起動し、同じコンテナ内からのハンドシェイク
// （openssl s_client -starttls postgres）で数え上げた結果（AlmaLinux 9.8 の postgresql-server 13.23-6.el9_8 と
// openssl-libs 3.5.8-2.el9_8、Debian 13 の postgresql-17 17.12-0+deb13u1）。RHEL 系は、UBI にサーバーのパッケージがないため AlmaLinux で測った。

const (
	pgRHELConf = "/var/lib/pgsql/data/postgresql.conf"
	pgRHELAuto = "/var/lib/pgsql/data/postgresql.auto.conf"
	pgDebConf  = "/etc/postgresql/17/main/postgresql.conf"
	pgBase     = "listen_addresses = '127.0.0.1'\nport = 5432\nssl = on\nssl_cert_file = '/etc/lab/rsa.crt'\nssl_key_file = '/etc/lab/rsa.key'\n"
	pgBaseEC   = "ssl = on\nssl_cert_file = '/etc/lab/ec.crt'\nssl_key_file = '/etc/lab/ec.key'\n"
)

// pgAlma9 は、AlmaLinux 9.8 に postgresql-server を導入した状態を作る。
func pgAlma9(t *testing.T, files map[string]string) func(p string, b *inventory.Builder) {
	prepare := rhel9Web(t, "3.5.8", "2.el9_8", files)
	return func(p string, b *inventory.Builder) {
		b.AddPackage(model.Package{Manager: "rpm", Name: "postgresql-server", Version: "13.23", Release: "6.el9_8", Role: "database"})
		prepare(p, b)
	}
}

func pgDebian13(t *testing.T, files map[string]string) func(p string, b *inventory.Builder) {
	prepare := postfixDeb(t, "3.10.13-0+deb13u1", "libssl3t64", "3.5.7-1~deb13u3", files)
	return func(p string, b *inventory.Builder) {
		b.AddPackage(model.Package{Manager: "dpkg", Name: "postgresql-17", Version: "17.12-0+deb13u1", Role: "database"})
		b.AddPackage(model.Package{Manager: "dpkg", Name: "postgresql-client-17", Version: "17.12-0+deb13u1", Role: "database"})
		prepare(p, b)
	}
}

func pgEff(t *testing.T, inv *model.Inventory, param string) model.EffectiveValue {
	t.Helper()
	return eff(t, inv, "svc:postgresql", param, "")
}

// 暗号の指定がなければ、PostgreSQL の既定の暗号文字列。セキュリティレベルと TLS 1.3 のスイートは、システムの設定に従う。
// 鍵交換のグループは、既定では P-256 の 1 つだけで、TLS 1.3 でも同じ（耐量子のハイブリッドを受け入れない）。
func TestPostgreSQLEffectiveDefaults(t *testing.T) {
	_, inv := collect(t, "rhel9", withGroups(rhel9PolicyGroups, pgAlma9(t, map[string]string{pgRHELConf: pgBase})))
	e := pgEff(t, inv, "tls.ciphers")
	checkSuites(t, e, 40, "c351065849c073d2", "high")
	if l := layers(e); !strings.HasPrefix(l, "app-default/default library/expand os-policy/security-level") {
		t.Errorf("steps = %s", l)
	}
	if s := e.Steps[0].Source; s == nil || s.Package != "postgresql-server" || s.Version != "13.23-6.el9_8" || !strings.HasPrefix(s.Image, "almalinux@sha256:") {
		t.Errorf("source = %+v", e.Steps[0].Source)
	}
	if e13 := pgEff(t, inv, "tls.ciphersuites-tls13"); sortedJoin(e13.Values) != rhel9TLS13 {
		t.Errorf("tls13 = %+v", e13)
	}
	g := groupsOf(t, inv, "svc:postgresql", "")
	if strings.Join(g.Values, " ") != "P-256" || g.Steps[0].Layer != "app-default" || g.Confidence != "high" {
		t.Errorf("groups = %+v", g)
	}
	// 証明書が ECDSA
	_, inv = collect(t, "rhel9", pgAlma9(t, map[string]string{pgRHELConf: pgBaseEC}))
	checkSuites(t, pgEff(t, inv, "tls.ciphers"), 13, "3b18ae1431c420e7", "high")

	// Debian 13: 設定は /etc/postgresql/<版>/<クラスタ>/ にある。OpenSSL 3.5 の既定（X25519MLKEM768 を含む）にはならない
	_, inv = collect(t, "", pgDebian13(t, map[string]string{pgDebConf: "data_directory = '/var/lib/postgresql/17/main'\n" + pgBase}))
	checkSuites(t, pgEff(t, inv, "tls.ciphers"), 40, "c351065849c073d2", "high")
	if e13 := pgEff(t, inv, "tls.ciphersuites-tls13"); sortedJoin(e13.Values) != ubuntuTLS13 {
		t.Errorf("debian tls13 = %+v", e13)
	}
	if g := groupsOf(t, inv, "svc:postgresql", ""); strings.Join(g.Values, " ") != "P-256" {
		t.Errorf("debian groups = %v", g.Values)
	}
}

// 設定の記載: 暗号文字列、曲線、DH パラメータ。同じ項目の書き直し、include、ALTER SYSTEM（postgresql.auto.conf）。
func TestPostgreSQLConfigured(t *testing.T) {
	_, inv := collect(t, "rhel9", pgAlma9(t, map[string]string{pgRHELConf: pgBase + "ssl_ciphers = 'ECDHE+AESGCM:DHE+AESGCM:AES128-SHA'\nssl_ecdh_curve = 'secp384r1'\n"}))
	e := pgEff(t, inv, "tls.ciphers")
	checkSuites(t, e, 5, "c912afa74ee150e6", "high")
	if e.Steps[0].Layer != "app-config" || e.Steps[0].Setting == "" {
		t.Errorf("steps = %+v", e.Steps)
	}
	if g := groupsOf(t, inv, "svc:postgresql", ""); strings.Join(g.Values, " ") != "P-384" || g.Steps[0].Layer != "app-config" || g.Steps[0].Setting == "" {
		t.Errorf("groups = %+v", g)
	}
	// DH パラメータの指定がなくても、組み込みのパラメータで DHE を使える
	_, inv = collect(t, "rhel9", pgAlma9(t, map[string]string{pgRHELConf: pgBase + "ssl_ciphers = 'DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-SHA:AES256-SHA'\n"}))
	checkSuites(t, pgEff(t, inv, "tls.ciphers"), 3, "f6cfcb7ed6912e5f", "high")

	// 後に書かれたものが効く。include した先も、その位置で読まれる。include_dir は名前の順
	dir := "/var/lib/pgsql/data/"
	_, inv = collect(t, "rhel9", pgAlma9(t, map[string]string{
		pgRHELConf:             pgBase + "ssl_ciphers = 'HIGH:!aNULL'\nssl_ciphers = 'HIGH:!aNULL:!kRSA' # later wins\ninclude 'lab-extra.conf'\ninclude_dir 'lab.d'\n",
		dir + "lab-extra.conf": "ssl_prefer_server_ciphers = off\n", dir + "lab.d/10-curve.conf": "ssl_ecdh_curve = 'secp521r1'\n", dir + "lab.d/20-curve.conf": "ssl_ecdh_curve = 'secp384r1'\n"}))
	checkSuites(t, pgEff(t, inv, "tls.ciphers"), 26, "02de241f6306d23f", "high")
	if g := groupsOf(t, inv, "svc:postgresql", ""); strings.Join(g.Values, " ") != "P-384" {
		t.Errorf("include_dir groups = %v", g.Values)
	}
	// ALTER SYSTEM で書かれた値（データディレクトリの postgresql.auto.conf）は、postgresql.conf より優先される
	_, inv = collect(t, "rhel9", pgAlma9(t, map[string]string{pgRHELConf: pgBase + "ssl_ciphers = 'HIGH:!aNULL'\n",
		pgRHELAuto: "# Do not edit this file manually!\nssl_ciphers = 'ECDHE+AESGCM'\n"}))
	e = pgEff(t, inv, "tls.ciphers")
	checkSuites(t, e, 2, "ca92f21dfad7d0c6", "high")
	// Debian 系では、データディレクトリは設定の data_directory が指す
	_, inv = collect(t, "", pgDebian13(t, map[string]string{pgDebConf: "data_directory = '/var/lib/postgresql/17/main'\n" + pgBase + "ssl_ciphers = 'HIGH:!aNULL'\n",
		"/var/lib/postgresql/17/main/postgresql.auto.conf": "ssl_ciphers = 'ECDHE+AESGCM'\n"}))
	checkSuites(t, pgEff(t, inv, "tls.ciphers"), 2, "ca92f21dfad7d0c6", "high")
}

// TLS を使わない設定（既定は ssl = off）では、実効値を作らない。求められない場合は、理由を残す。
func TestPostgreSQLDisabledAndLimits(t *testing.T) {
	_, inv := collect(t, "rhel9", pgAlma9(t, map[string]string{pgRHELConf: "listen_addresses = 'localhost'\n#ssl = on\nssl_ciphers = 'HIGH'\n"}))
	service(t, inv, "postgresql")
	for _, e := range inv.EffectiveValues {
		if e.Service == "svc:postgresql" {
			t.Errorf("ssl is off, but an effective value was produced: %+v", e)
		}
	}
	if len(byParam(inv, "svc:postgresql")["inbound:tls.ciphers"]) == 0 {
		t.Errorf("configured values must be recorded: %+v", byParam(inv, "svc:postgresql"))
	}
	// PostgreSQL 18 の新しい項目（ssl_groups、ssl_tls13_ciphers）は実測していないので、求めない
	_, inv = collect(t, "rhel9", pgAlma9(t, map[string]string{pgRHELConf: pgBase + "ssl_groups = 'X25519MLKEM768:secp384r1'\nssl_tls13_ciphers = 'TLS_AES_256_GCM_SHA384'\n"}))
	if e := pgEff(t, inv, "tls.groups"); e.Status != "unresolved" || !strings.Contains(e.Reason, "ssl_groups") {
		t.Errorf("ssl_groups: %+v", e)
	}
	if e := pgEff(t, inv, "tls.ciphersuites-tls13"); e.Status != "unresolved" || !strings.Contains(e.Reason, "ssl_tls13_ciphers") {
		t.Errorf("ssl_tls13_ciphers: %+v", e)
	}
	checkSuites(t, pgEff(t, inv, "tls.ciphers"), 40, "c351065849c073d2", "high")
	// 既定値を測っていない版
	_, inv = collect(t, "rhel9", func(p string, b *inventory.Builder) {
		b.AddPackage(model.Package{Manager: "rpm", Name: "postgresql-server", Version: "99.1", Release: "1.el9", Role: "database"})
		rhel9Web(t, "3.5.8", "2.el9_8", map[string]string{pgRHELConf: pgBase})(p, b)
	})
	if e := pgEff(t, inv, "tls.ciphers"); e.Status != "unresolved" || !strings.Contains(e.Reason, "postgresql-server 99.1-1.el9") {
		t.Errorf("unknown version: %+v", e)
	}
}

// PostgreSQL 18（AlmaLinux 9 のモジュール、18.6）。期待値は、検証ラボで実際に起動して数え上げた結果。
//   - 既定のグループは、X25519 と P-256 の 2 つ（17 までは P-256 の 1 つ）
//   - ssl_groups は、グループの並び。耐量子のハイブリッド（X25519MLKEM768）も指定できる
//   - ssl_ecdh_curve は、同じ項目の古い名前として、18 でも効く
//   - ssl_tls13_ciphers は、TLS 1.3 のスイートの並び
func TestPostgreSQL18(t *testing.T) {
	host := func(conf string) func(p string, b *inventory.Builder) {
		prepare := rhel9Web(t, "3.5.8", "2.el9_8", map[string]string{pgRHELConf: pgBase + conf})
		return func(p string, b *inventory.Builder) {
			b.AddPackage(model.Package{Manager: "rpm", Name: "postgresql-server", Version: "18.6", Release: "1.module_el9.8.0+310+22372bcc", Role: "database"})
			prepare(p, b)
		}
	}
	groups := func(conf string) model.EffectiveValue {
		_, inv := collect(t, "rhel9", host(conf))
		return pgEff(t, inv, "tls.groups")
	}
	if g := groups(""); g.Status != "resolved" || strings.Join(g.Values, " ") != "X25519 P-256" || g.Confidence != "high" || g.Steps[0].Layer != "app-default" {
		t.Errorf("default groups = %+v", g)
	}
	if g := groups("ssl_groups = 'X25519MLKEM768:secp384r1'\n"); g.Status != "resolved" || strings.Join(g.Values, " ") != "X25519MLKEM768 P-384" || g.Confidence != "high" || g.Steps[0].Layer != "app-config" {
		t.Errorf("ssl_groups = %+v", g)
	}
	if g := groups("ssl_ecdh_curve = 'secp384r1'\n"); g.Status != "resolved" || strings.Join(g.Values, " ") != "P-384" {
		t.Errorf("ssl_ecdh_curve on 18 = %+v", g)
	}
	// 2 つの名前の両方が書かれた場合は、測っていないので、求めない
	if g := groups("ssl_ecdh_curve = 'secp384r1'\nssl_groups = 'X25519'\n"); g.Status != "unresolved" || !strings.Contains(g.Reason, "ssl_ecdh_curve") {
		t.Errorf("both names = %+v", g)
	}
	_, inv := collect(t, "rhel9", host("ssl_tls13_ciphers = 'TLS_AES_256_GCM_SHA384'\n"))
	e := pgEff(t, inv, "tls.ciphersuites-tls13")
	if e.Status != "resolved" || strings.Join(e.Values, " ") != "TLS_AES_256_GCM_SHA384" || e.Confidence != "high" || e.Steps[0].Layer != "app-config" || e.Steps[0].Setting == "" {
		t.Errorf("ssl_tls13_ciphers = %+v", e)
	}
	// TLS 1.2 以下のスイートは、既定のまま（実測: 40 個）
	if c := pgEff(t, inv, "tls.ciphers"); c.Status != "resolved" || len(c.Values) != 40 {
		t.Errorf("ciphers with ssl_tls13_ciphers = %d %s", len(c.Values), c.Status)
	}
	// 解釈できない値は、求めない
	_, inv = collect(t, "rhel9", host("ssl_tls13_ciphers = 'TLS_AES_256_GCM_SHA384 $x'\n"))
	if e := pgEff(t, inv, "tls.ciphersuites-tls13"); e.Status != "unresolved" {
		t.Errorf("uninterpretable ssl_tls13_ciphers = %+v", e)
	}
}
