package apps

import (
	"strings"

	"kagiya/internal/model"
	"kagiya/internal/parse/apacheconf"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

// apache は Apache HTTP Server の設定を読む。
//
// TLS のモジュール（ssl_module）が読み込まれていない場合は、その旨をサービスの注記に残す。
// Listen は、TLS を有効にした <VirtualHost> と同じポートのもの（または https の指定があるもの）だけを記録する。
func (c *Collector) apache(app ruleset.AppRule, svc model.Service, config string) {
	if config == "" {
		return
	}
	r := apacheconf.Parse(config, confFS{c})
	for _, pr := range r.Problems {
		c.Builder.Skip(safefs.Skip{Path: c.Prefix + config, Reason: "config-problem", Detail: pr})
	}
	hasSSL := false
	for _, m := range r.Modules {
		hasSSL = hasSSL || m == "ssl_module"
	}
	if !hasSSL {
		c.Builder.ServiceNote(svc.ID, "ssl_module is not loaded by the configuration; TLS directives are not in effect")
	}
	vhost := func(sections []string) string {
		for i := len(sections) - 1; i >= 0; i-- {
			if strings.HasPrefix(strings.ToLower(sections[i]), "virtualhost ") {
				return "VirtualHost " + strings.TrimSpace(sections[i][len("virtualhost "):])
			}
		}
		return ""
	}
	portOf := func(addr string) string {
		addr = strings.Fields(addr + " x")[0]
		if i := strings.LastIndexByte(addr, ':'); i >= 0 {
			return addr[i+1:]
		}
		return addr
	}
	tlsPorts := map[string]bool{}
	for _, d := range r.Directives {
		if d.Name == "sslengine" && strings.EqualFold(unquoteArg(d.Args), "on") {
			if vh := vhost(d.Sections); vh != "" {
				tlsPorts[portOf(strings.TrimPrefix(vh, "VirtualHost "))] = true
			}
		}
	}
	for _, d := range r.Directives {
		rule, ok := app.Directive(d.Name)
		if !ok {
			continue
		}
		args := unquoteArg(d.Args)
		if rule.Type == "listen" {
			f := strings.Fields(args)
			if len(f) == 0 || !(tlsPorts[portOf(f[0])] || (len(f) > 1 && strings.EqualFold(f[1], "https"))) {
				continue
			}
		}
		scope := vhost(d.Sections)
		if scope != "" && !scopeText.MatchString(scope) {
			scope = "VirtualHost"
		}
		c.record(app, svc, rule, args, d.File, d.Line, scope, r.ServerRoot)
	}
	if hasSSL {
		c.opensslServerEffective(app, svc, apacheScopes(r, vhost))
	}
}

// apacheScopes は、TLS を有効にした VirtualHost ごとに、暗号スイートの解決に必要な記載をまとめる。
//
// mod_ssl の規則: VirtualHost に書かれていない項目は、全体（VirtualHost の外）に書かれた値を引き継ぐ。
// 同じ範囲に同じ項目が複数あれば、後に書かれたものが効く。SSLCertificateFile は複数書けて、
// VirtualHost に1つでも書けば全体のものは引き継がない。
func apacheScopes(r *apacheconf.Result, vhost func([]string) string) []tlsScope {
	// ディレクトリ単位の設定（<Directory>、<Location> など）の中の記載は、接続の暗号スイートには効かない
	perDir := func(sections []string) bool {
		for _, s := range sections {
			l := strings.ToLower(s)
			for _, p := range []string{"directory", "location", "files", "proxy", "if ", "elseif ", "else"} {
				if strings.HasPrefix(l, p) {
					return true
				}
			}
		}
		return false
	}
	var order []string
	seen := map[string]bool{}
	for _, d := range r.Directives {
		if vh := vhost(d.Sections); vh != "" && !seen[vh] {
			seen[vh] = true
			order = append(order, vh)
		}
	}
	// lookup は、VirtualHost の中の記載を返す。なければ全体の記載を返す。
	lookup := func(vh, name string) []apacheconf.Directive {
		var own, global []apacheconf.Directive
		for _, d := range r.Directives {
			if d.Name != name || perDir(d.Sections) {
				continue
			}
			switch vhost(d.Sections) {
			case vh:
				own = append(own, d)
			case "":
				global = append(global, d)
			}
		}
		if len(own) > 0 {
			return own
		}
		return global
	}
	if len(order) == 0 {
		order = []string{""} // VirtualHost のない構成（全体が1つのサーバー）
	}
	var scopes []tlsScope
	for _, vh := range order {
		engine := lookup(vh, "sslengine")
		if len(engine) == 0 || !strings.EqualFold(unquoteArg(engine[len(engine)-1].Args), "on") {
			continue
		}
		sc := tlsScope{name: vh, certsOK: true}
		if vh != "" && !scopeText.MatchString(vh) {
			sc.name = "VirtualHost"
		}
		// SSLCipherSuite [SSL|TLSv1.3] 暗号文字列。TLSv1.3 を付けたものは TLS 1.3 のスイートの指定で、別扱い。
		for _, d := range lookup(vh, "sslciphersuite") {
			f := strings.Fields(unquoteArg(d.Args))
			for i := range f {
				f[i] = unquoteArg(f[i])
			}
			switch {
			case len(f) == 2 && strings.EqualFold(f[0], "TLSv1.3"):
				sc.tls13Blocker = "the TLS 1.3 suites are set by the application (SSLCipherSuite TLSv1.3 ...); this form is not resolved yet"
				continue
			case len(f) == 2 && strings.EqualFold(f[0], "SSL"):
				f = f[1:]
			}
			if len(f) != 1 || !validCipherString(f[0]) {
				sc.blocker = "the configured cipher string (SSLCipherSuite) is not interpreted"
				continue
			}
			sc.blocker = ""
			sc.cipher, sc.cipherFile, sc.cipherLine = f[0], d.File, d.Line // 後に書かれたものが効く
		}
		for _, d := range lookup(vh, "sslcertificatefile") {
			p := unquoteArg(d.Args)
			if p == "" || strings.ContainsAny(p, "$%:") || strings.ContainsAny(p, " \t") {
				sc.certsOK = false // 変数や、ファイル以外の指定（pkcs11: など）
				continue
			}
			if !strings.HasPrefix(p, "/") {
				if r.ServerRoot == "" {
					sc.certsOK = false
					continue
				}
				p = strings.TrimRight(r.ServerRoot, "/") + "/" + p
			}
			sc.certs = append(sc.certs, p)
		}
		if len(lookup(vh, "sslopensslconfcmd")) > 0 {
			sc.blocker = "SSLOpenSSLConfCmd is used; it changes the OpenSSL settings directly, so the cipher string alone does not determine the result"
		}
		scopes = append(scopes, sc)
	}
	return scopes
}

func unquoteArg(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}
