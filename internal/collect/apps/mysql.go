package apps

import (
	"strings"

	"kagiya/internal/model"
	"kagiya/internal/parse/mycnf"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

// このファイルは MariaDB / MySQL の設定の読み取り（設定ファイルの形は同じで、既定と挙動が違う）。
//
// 決まり方（検証ラボで、MariaDB 6 版・MySQL 6 版を実際に起動して確かめたもの）:
//
//   - 設定は my.cnf と、そこから取り込まれるファイル。サーバーが読むグループ（[mysqld]、[server] など）の項目だけが効き、
//     同じ項目は後に読まれたものが効く。
//   - MariaDB: 暗号の指定（ssl_cipher）がなければ何も設定せず、OpenSSL のシステム既定になる。鍵交換のグループと TLS 1.3 のスイートも
//     システムの設定に従う。証明書の指定がなければ、古い版は TLS が無効、新しい版（11.8）は自分で用意した証明書で有効。
//   - MySQL: 暗号の指定がなければ、内蔵の既定の並び。設定に書いた暗号文字列には、拒否する暗号の並びが後ろに足される。
//     鍵交換のグループは MySQL が自分で決める。証明書の指定がなければ、データディレクトリに自分で用意した証明書で有効。

// サーバーが読むグループ（版ごとのグループ [mysqld-8.0] などは読まない）。
var mycnfGroups = map[string]map[string]bool{
	"mariadb": {"mysqld": true, "server": true, "mariadb": true, "mariadbd": true, "client-server": true},
	"mysql":   {"mysqld": true, "server": true},
}

func (c *Collector) mysql(app ruleset.AppRule, svc model.Service, config string) {
	if config == "" {
		return
	}
	opts, problems := mycnf.Parse(config, confFS{c})
	for _, pr := range problems {
		c.Builder.Skip(safefs.Skip{Path: c.Prefix + config, Reason: "config-problem", Detail: pr})
	}
	groups := mycnfGroups[app.ID]
	last := map[string]mycnf.Option{}
	for _, o := range opts {
		if groups[o.Group] {
			last[o.Name] = o
		}
	}
	for _, o := range opts {
		if !groups[o.Group] || last[o.Name] != o || o.Value == "" {
			continue // 効いている記載だけを記録する
		}
		if rule, ok := app.Directive(o.Name); ok {
			c.record(app, svc, rule, o.Value, o.File, o.Line, "", dirOf(config))
		}
	}
	defs, _, _, _ := c.appDefaults(app)

	// TLS を切る指定
	if _, off := last["skip_ssl"]; off {
		return
	}
	if o, ok := last["ssl"]; ok {
		switch strings.ToLower(o.Value) {
		case "0", "off", "false", "no":
			return
		}
	}
	sc := tlsScope{certsOK: true}
	cert := last["ssl_cert"].Value
	switch without := strings.Join(defs["tls.without-certificate"], ","); {
	case cert != "":
		if strings.HasPrefix(cert, "/") && !strings.ContainsAny(cert, "\x00\n*?[") {
			sc.certs = []string{cert}
		} else {
			sc.certsOK = false
		}
	case app.ID == "mysql":
		// データディレクトリに自分で用意した証明書。読めればその種類、読めなければ実測どおり RSA として扱う
		dataDir := "/var/lib/mysql"
		if o, ok := last["datadir"]; ok && strings.HasPrefix(o.Value, "/") && !strings.ContainsAny(o.Value, "\x00\n*?[") {
			dataDir = strings.TrimRight(o.Value, "/")
		}
		if _, err := c.read(dataDir + "/server-cert.pem"); err == nil {
			sc.certs = []string{dataDir + "/server-cert.pem"}
		} else {
			sc.autoRSA = without == "auto-rsa"
			sc.certsOK = sc.autoRSA
		}
	case without == "disabled":
		return // この版は、証明書の指定がなければ TLS が無効
	case without == "auto-rsa":
		sc.autoRSA = true // 起動のたびに自分で用意する証明書（ファイルにはない）
	default:
		sc.certsOK = false
	}
	if o, ok := last["ssl_cipher"]; ok && o.Value != "" {
		sc.cipher, sc.cipherFile, sc.cipherLine = o.Value, o.File, o.Line
		if suffix := strings.Join(defs["tls.cipher-suffix"], ","); suffix != "" {
			sc.cipher += ":" + suffix // MySQL は、拒否する暗号の並びを後ろに足す
		}
		if !validCipherString(sc.cipher) {
			sc.blocker = "the configured cipher string (ssl_cipher) is not interpreted"
		}
	}
	if o, ok := last["tls_ciphersuites"]; ok && o.Value != "" {
		if cipherString.MatchString(o.Value) {
			sc.tls13, sc.tls13File, sc.tls13Line = o.Value, o.File, o.Line
		} else {
			sc.tls13Blocker = "the configured TLS 1.3 suites (tls_ciphersuites) are not interpreted"
		}
	}
	c.opensslServerEffective(app, svc, []tlsScope{sc})
}

// hasPackage は、アプリのパッケージが導入されているかを返す。
func (c *Collector) hasPackage(app ruleset.AppRule) bool {
	for _, p := range c.Builder.Packages() {
		if ruleset.MatchName(app.Packages, p.Name) {
			return true
		}
	}
	return false
}
