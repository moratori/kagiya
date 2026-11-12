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
}

func unquoteArg(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}
