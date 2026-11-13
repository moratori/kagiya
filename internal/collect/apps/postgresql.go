package apps

import (
	"strings"

	"kagiya/internal/model"
	"kagiya/internal/parse/pgconf"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

// このファイルは PostgreSQL の設定の読み取り。
//
// PostgreSQL の決まり方（検証ラボで、7 つのディストリの PostgreSQL 10〜17 を実際に起動して確かめたもの）:
//
//   - 設定は postgresql.conf と、そこから取り込まれるファイル。同じ項目は、後に読まれたものが効く。
//     ALTER SYSTEM で書かれた値（データディレクトリの postgresql.auto.conf）は、postgresql.conf より優先される。
//   - TLS を使うのは ssl = on のとき（既定は off）。サーバー全体で 1 つの設定で、証明書も 1 つ。
//   - 暗号文字列（ssl_ciphers）は、そのまま OpenSSL に渡る。セキュリティレベルと TLS 1.3 のスイートは、システムの設定に従う。
//   - 鍵交換のグループは ssl_ecdh_curve の 1 つだけ（既定は prime256v1）。TLS 1.3 でも、このグループだけになる。
//   - DH パラメータの指定（ssl_dh_params_file）がなくても、組み込みのパラメータで DHE を使える。

var pgBool = map[string]bool{"on": true, "true": true, "yes": true, "1": true, "off": false, "false": false, "no": false, "0": false}

func (c *Collector) postgresql(app ruleset.AppRule, svc model.Service, config string) {
	if config == "" {
		return
	}
	settings, problems := pgconf.Parse(config, confFS{c})
	for _, pr := range problems {
		c.Builder.Skip(safefs.Skip{Path: c.Prefix + config, Reason: "config-problem", Detail: pr})
	}
	// データディレクトリ: 設定の data_directory、なければ設定ファイルのあるディレクトリ
	dataDir := dirOf(config)
	for _, s := range settings {
		if s.Name == "data_directory" && strings.HasPrefix(s.Value, "/") && !strings.ContainsAny(s.Value, "\x00\n*?[") {
			dataDir = strings.TrimRight(s.Value, "/")
		}
	}
	// ALTER SYSTEM で書かれた値。postgresql.conf より後に読まれる
	auto := dataDir + "/postgresql.auto.conf"
	if _, err := c.read(auto); err == nil {
		more, problems := pgconf.Parse(auto, confFS{c})
		for _, pr := range problems {
			c.Builder.Skip(safefs.Skip{Path: c.Prefix + auto, Reason: "config-problem", Detail: pr})
		}
		settings = append(settings, more...)
	}
	last := map[string]pgconf.Setting{}
	for _, s := range settings {
		last[s.Name] = s
	}
	for _, s := range settings {
		if last[s.Name] != s {
			continue // 効いている記載だけを記録する
		}
		if rule, ok := app.Directive(s.Name); ok && s.Value != "" {
			c.record(app, svc, rule, s.Value, s.File, s.Line, "", dataDir)
		}
	}

	on, known := pgBool[strings.ToLower(last["ssl"].Value)]
	if _, set := last["ssl"]; !set || (known && !on) {
		return // TLS を使わない（既定は off）
	}
	sc := tlsScope{certsOK: true}
	if !known {
		sc.blocker = "the value of ssl is not one of on, off"
		sc.groupsBlocker = sc.blocker
	}
	if s, ok := last["ssl_ciphers"]; ok {
		sc.cipher, sc.cipherFile, sc.cipherLine = s.Value, s.File, s.Line
		if !validCipherString(s.Value) {
			sc.blocker = "the configured cipher string (ssl_ciphers) is not interpreted"
		}
	}
	// 証明書は 1 つ。相対パスは、データディレクトリから（既定は server.crt）
	cert := "server.crt"
	if s, ok := last["ssl_cert_file"]; ok && s.Value != "" {
		cert = s.Value
	}
	if !strings.HasPrefix(cert, "/") {
		cert = dataDir + "/" + cert
	}
	if strings.ContainsAny(cert, "\x00\n*?[") {
		sc.certsOK = false
	} else {
		sc.certs = []string{cert}
	}
	sc.dhParam = last["ssl_dh_params_file"].Value != ""
	if s, ok := last["ssl_ecdh_curve"]; ok && s.Value != "" {
		sc.setGroups(s.Value, s.File, s.Line, "ssl_ecdh_curve")
	}
	// PostgreSQL 18 で加わった項目は、実物で測っていない
	if s, ok := last["ssl_groups"]; ok && s.Value != "" {
		sc.groups, sc.groupsBlocker = "", "ssl_groups (PostgreSQL 18 or later) is set; its effect is not measured yet"
	}
	if s, ok := last["ssl_tls13_ciphers"]; ok && s.Value != "" {
		sc.tls13Blocker = "ssl_tls13_ciphers (PostgreSQL 18 or later) is set; its effect is not measured yet"
	}
	c.opensslServerEffective(app, svc, []tlsScope{sc})
}
