package apps

import (
	"sort"
	"strings"

	"kagiya/internal/model"
	"kagiya/internal/parse/stunnelconf"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

// stunnel の設定の置き場所。この下の *.conf のそれぞれが、1 つの起動単位の設定になる。
const stunnelConfDir = "/etc/stunnel"

// stunnel は stunnel の設定を読む。
//
// 設定に明記された TLS 関連の値と、それがどの範囲（どの設定ファイルの、どのサービス）に書かれているかを記録し、
// 待ち受ける側（client = yes でない）のサービスごとに、暗号スイートの実効値を求める。
//
// stunnel の規則: サービスの節より前に書かれた値は、そのファイルの全サービスの既定になる。サービスの節に書けば、そちらが効く。
// 同じ範囲に同じ項目が複数あれば、後に書かれたものが効く。
func (c *Collector) stunnel(app ruleset.AppRule, svc model.Service) {
	files, _ := confFS{c}.Glob(stunnelConfDir + "/*.conf")
	sort.Strings(files)
	var scopes []tlsScope
	for _, file := range files {
		data, err := c.read(file)
		if err != nil {
			c.Builder.Skip(safefs.Skip{Path: c.Prefix + file, Reason: "config-problem", Detail: "not readable"})
			continue
		}
		ds, problems := stunnelconf.Parse(file, data)
		for _, pr := range problems {
			c.Builder.Skip(safefs.Skip{Path: c.Prefix + file, Reason: "config-problem", Detail: pr})
		}
		base := file[strings.LastIndexByte(file, '/')+1:]
		if !scopeText.MatchString(base) {
			base = "stunnel"
		}
		// 範囲ごとの、項目 → 最後の記載
		global := map[string]stunnelconf.Directive{}
		services := map[string]map[string]stunnelconf.Directive{}
		var order []string
		for _, d := range ds {
			if d.Service == "" {
				global[d.Key] = d
				continue
			}
			if services[d.Service] == nil {
				services[d.Service] = map[string]stunnelconf.Directive{}
				order = append(order, d.Service)
			}
			services[d.Service][d.Key] = d
		}
		scopeOf := func(service string) string {
			if service == "" {
				return base
			}
			if name := base + " [" + service + "]"; scopeText.MatchString(name) {
				return name
			}
			return base + " [service]"
		}
		client := func(service string) bool {
			d, ok := services[service]["client"]
			if !ok {
				d, ok = global["client"]
			}
			return ok && strings.EqualFold(d.Value, "yes")
		}
		for _, d := range ds {
			rule, ok := app.Directive(d.Key)
			if !ok || d.Value == "" {
				continue
			}
			if d.Service != "" && client(d.Service) {
				rule.Direction = "outbound" // 外向きの接続をするサービスの設定
			}
			value := d.Value
			if rule.Type == "listen" {
				value += " ssl"
			}
			c.record(app, svc, rule, value, d.File, d.Line, scopeOf(d.Service), "")
		}
		for _, name := range order {
			s := services[name]
			if _, ok := s["accept"]; !ok || client(name) {
				continue // 待ち受けないサービス、外向きの接続をするサービス
			}
			// lookup は、サービスの節の記載を返す。なければ全体の記載を返す。
			lookup := func(key string) (stunnelconf.Directive, bool) {
				if d, ok := s[key]; ok {
					return d, true
				}
				d, ok := global[key]
				return d, ok
			}
			sc := tlsScope{name: scopeOf(name)}
			if d, ok := lookup("ciphers"); ok {
				sc.cipher, sc.cipherFile, sc.cipherLine = d.Value, d.File, d.Line
				if !validCipherString(d.Value) {
					sc.blocker = "the configured cipher string (ciphers) is not interpreted"
				}
			}
			if d, ok := lookup("ciphersuites"); ok {
				if cipherString.MatchString(d.Value) {
					sc.tls13, sc.tls13File, sc.tls13Line = d.Value, d.File, d.Line
				} else {
					sc.tls13Blocker = "the configured TLS 1.3 suites are not interpreted"
				}
			}
			if d, ok := lookup("curves"); ok {
				sc.setGroups(d.Value, d.File, d.Line, "curves")
			}
			// 証明書は1つのサービスに1つ。絶対パスで指定されたものだけを読む
			if d, ok := lookup("cert"); ok && strings.HasPrefix(d.Value, "/") && !strings.ContainsAny(d.Value, "$*?[") {
				sc.certs, sc.certsOK = []string{d.Value}, true
			}
			scopes = append(scopes, sc)
		}
	}
	c.opensslServerEffective(app, svc, scopes)
}
