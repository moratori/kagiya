package apps

import (
	"strings"

	"kagiya/internal/model"
	"kagiya/internal/parse/nginxconf"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

// nginx は nginx の設定を読む。
//
// 設定に明記された TLS 関連の値と、それがどの範囲（http 全体、どの server）に書かれているかを記録する。
// そのうえで、TLS を待ち受ける server ごとに、暗号スイートの実効値を求める（nginxEffective）。
func (c *Collector) nginx(app ruleset.AppRule, svc model.Service, config string) {
	if config == "" {
		return
	}
	ds, problems := nginxconf.Parse(config, confFS{c})
	for _, pr := range problems {
		c.Builder.Skip(safefs.Skip{Path: c.Prefix + config, Reason: "config-problem", Detail: pr})
	}
	// server ブロックごとの名前（最初の server_name）
	serverOf := func(ctx string) string {
		for _, seg := range strings.Split(ctx, "/") {
			if strings.HasPrefix(seg, "server#") {
				return seg
			}
		}
		return ""
	}
	names := map[string]string{}
	for _, d := range ds {
		if d.Name == "server_name" && len(d.Args) > 0 && strings.HasSuffix(d.Context, serverOf(d.Context)) {
			if id := serverOf(d.Context); id != "" && names[id] == "" && wordItem.MatchString(d.Args[0]) {
				names[id] = d.Args[0]
			}
		}
	}
	base := dirOf(config)
	for _, d := range ds {
		rule, ok := app.Directive(d.Name)
		if !ok || len(d.Args) == 0 {
			continue
		}
		if rule.Type == "listen" {
			tls := false
			for _, a := range d.Args[1:] {
				tls = tls || a == "ssl" || a == "quic"
			}
			if !tls {
				continue // TLS を使わない待ち受け
			}
		}
		scope := d.Context
		if id := serverOf(d.Context); id != "" {
			scope = "server " + names[id]
			if names[id] == "" {
				scope = id
			}
		} else if i := strings.IndexByte(scope, '/'); i >= 0 {
			scope = scope[:i]
		}
		c.record(app, svc, rule, strings.Join(d.Args, " "), d.File, d.Line, scope, base)
	}
	c.opensslServerEffective(app, svc, nginxScopes(ds, names, base))
}

// nginxScopes は、TLS を待ち受ける server ブロックごとに、暗号スイートの解決に必要な記載をまとめる。
//
// nginx の規則: server に書かれていない項目は、外側（http）に書かれた値を引き継ぐ。server に書けば、そちらが効く。
// 証明書（ssl_certificate）は複数書けて、server に1つでも書けば外側のものは引き継がない。
func nginxScopes(ds []nginxconf.Directive, names map[string]string, base string) []tlsScope {
	// server ブロックの直下の文脈（例: "http/server#2"）を、現れた順に集める
	var servers []string
	seen := map[string]bool{}
	for _, d := range ds {
		i := strings.LastIndex(d.Context, "server#")
		if i < 0 || strings.Contains(d.Context[i:], "/") || seen[d.Context] {
			continue
		}
		seen[d.Context] = true
		servers = append(servers, d.Context)
	}
	var scopes []tlsScope
	for _, ctx := range servers {
		id := ctx[strings.LastIndex(ctx, "server#"):]
		outer := strings.TrimSuffix(strings.TrimSuffix(ctx, id), "/")
		// lookup は、server の直下の記載を返す。なければ外側の階層の記載を返す。
		lookup := func(name string) []nginxconf.Directive {
			var own, inherited []nginxconf.Directive
			for _, d := range ds {
				if d.Name != name {
					continue
				}
				switch d.Context {
				case ctx:
					own = append(own, d)
				case outer:
					inherited = append(inherited, d)
				}
			}
			if len(own) > 0 {
				return own
			}
			return inherited
		}
		tls := false
		for _, d := range ds {
			if d.Context == ctx && d.Name == "listen" {
				for _, a := range d.Args[min(1, len(d.Args)):] {
					tls = tls || a == "ssl" || a == "quic"
				}
			}
		}
		if !tls {
			continue
		}
		sc := tlsScope{name: "server " + names[id], certsOK: true}
		if names[id] == "" {
			sc.name = id
		}
		if cs := lookup("ssl_ciphers"); len(cs) > 0 {
			v := strings.Join(cs[0].Args, " ")
			if !validCipherString(v) {
				sc.blocker = "the configured cipher string (ssl_ciphers) is not interpreted"
			}
			sc.cipher, sc.cipherFile, sc.cipherLine = v, cs[0].File, cs[0].Line
		}
		for _, d := range lookup("ssl_certificate") {
			if len(d.Args) == 0 || strings.ContainsAny(d.Args[0], "$:") {
				sc.certsOK = false // 変数や、ファイル以外の指定（data: など）
				continue
			}
			p := d.Args[0]
			if !strings.HasPrefix(p, "/") {
				p = strings.TrimRight(base, "/") + "/" + p
			}
			sc.certs = append(sc.certs, p)
		}
		sc.dhParam = len(lookup("ssl_dhparam")) > 0
		if len(lookup("ssl_conf_command")) > 0 {
			sc.blocker = "ssl_conf_command is used; it changes the OpenSSL settings directly, so the cipher string alone does not determine the result"
		}
		scopes = append(scopes, sc)
	}
	return scopes
}
