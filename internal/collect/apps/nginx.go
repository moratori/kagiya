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
// 記録するのは、設定に明記された TLS 関連の値と、それがどの範囲（http 全体、どの server）に書かれているか。
// 外側の階層の値が内側に引き継がれる規則や、同じ項目の上書きの解決は行わない。
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
}
