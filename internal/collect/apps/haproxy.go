package apps

import (
	"sort"
	"strconv"
	"strings"

	"kagiya/internal/model"
	"kagiya/internal/parse/haproxyconf"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

// bind の行の指定のうち、後ろに値を1つ取るもの（ここにないものは、値を取らない指定として読み飛ばす）。
// 値を取る指定を取りこぼすと、その値を別の指定と取り違えるので、TLS に関係しないものも含めて挙げている。
var haproxyBindValue = map[string]bool{
	"crt": true, "crt-list": true, "ciphers": true, "ciphersuites": true, "curves": true, "ecdhe": true, "sigalgs": true, "client-sigalgs": true,
	"ssl-min-ver": true, "ssl-max-ver": true, "ca-file": true, "ca-verify-file": true, "ca-sign-file": true, "ca-sign-pass": true, "crl-file": true,
	"verify": true, "alpn": true, "npn": true, "crt-ignore-err": true, "ca-ignore-err": true, "ssl-f-use": true,
	"accept-netscaler-cip": true, "backlog": true, "gid": true, "group": true, "id": true, "interface": true, "level": true, "severity-output": true,
	"maxconn": true, "mode": true, "mss": true, "name": true, "namespace": true, "nice": true, "process": true, "proto": true, "shards": true,
	"tcp-ut": true, "thread": true, "uid": true, "user": true, "expose-fd": true, "quic-cc-algo": true, "quic-socket": true,
}

// haproxy は HAProxy の設定を読む。
//
// 設定に明記された TLS 関連の値と、それがどの範囲（全体、どの frontend / listen）に書かれているかを記録し、
// TLS を待ち受ける bind ごとに、暗号スイートの実効値を求める。
//
// HAProxy の規則: bind の行に書かれていない項目は、全体（global）の ssl-default-bind-* の値を引き継ぐ。
// bind の行に書けば、そちらが効く。
func (c *Collector) haproxy(app ruleset.AppRule, svc model.Service, config string, units []unitInfo) {
	if config == "" {
		return
	}
	var ds []haproxyconf.Directive
	for _, file := range c.haproxyFiles(config, units) {
		data, err := c.read(file)
		if err != nil {
			c.Builder.Skip(safefs.Skip{Path: c.Prefix + file, Reason: "config-problem", Detail: "not readable"})
			continue
		}
		d, problems := haproxyconf.Parse(file, data)
		for _, pr := range problems {
			c.Builder.Skip(safefs.Skip{Path: c.Prefix + file, Reason: "config-problem", Detail: pr})
		}
		ds = append(ds, d...)
	}

	// 全体の設定（同じ項目が複数あれば、後に書かれたものが効く）
	global := map[string]haproxyconf.Directive{}
	for _, d := range ds {
		if d.Section == "global" && len(d.Args) > 0 {
			global[d.Keyword] = d
		}
	}
	crtBase := ""
	if d, ok := global["crt-base"]; ok && !d.HasVariable && strings.HasPrefix(d.Args[0], "/") {
		crtBase = d.Args[0]
	}
	for _, d := range ds {
		if d.Section != "global" || len(d.Args) == 0 || d.HasVariable {
			continue
		}
		if rule, ok := app.Directive(d.Keyword); ok && rule.Type != "listen" {
			c.record(app, svc, rule, strings.Join(d.Args, " "), d.File, d.Line, "global", crtBase)
		}
	}

	var scopes []tlsScope
	binds := map[string]int{}
	for _, d := range ds {
		if d.Keyword != "bind" || len(d.Args) == 0 || (d.Section != "frontend" && d.Section != "listen") {
			continue
		}
		opts := haproxyBindOptions(d.Args[1:])
		if _, tls := opts["ssl"]; !tls {
			continue // TLS を使わない待ち受け
		}
		// 範囲の名前。節の名前や待ち受けの指定に、結果に出せない文字が含まれる場合は、種類と番号で表す
		section := d.Section + " " + d.Name
		if !scopeText.MatchString(section) {
			section = d.Section
		}
		binds[section]++
		name := section + " bind " + d.Args[0]
		if d.HasVariable || !scopeText.MatchString(name) {
			name = section + " bind#" + strconv.Itoa(binds[section])
		}
		if rule, ok := app.Directive("bind"); ok && !d.HasVariable {
			c.record(app, svc, rule, d.Args[0]+" ssl", d.File, d.Line, section, "")
		}
		for opt, values := range opts {
			rule, ok := app.Directive("bind." + opt)
			if !ok || d.HasVariable {
				continue
			}
			for _, v := range values {
				c.record(app, svc, rule, v, d.File, d.Line, section, crtBase)
			}
		}

		sc := tlsScope{name: name, certsOK: !d.HasVariable}
		// 暗号文字列: bind の行の ciphers、なければ全体の ssl-default-bind-ciphers、どちらもなければアプリの既定
		if v := opts["ciphers"]; len(v) > 0 {
			sc.cipher, sc.cipherFile, sc.cipherLine = v[len(v)-1], d.File, d.Line
		} else if g, ok := global["ssl-default-bind-ciphers"]; ok {
			sc.cipher, sc.cipherFile, sc.cipherLine = g.Args[0], g.File, g.Line
			if g.HasVariable {
				sc.blocker = "the configured cipher string (ssl-default-bind-ciphers) contains a variable and is not interpreted"
			}
		}
		if sc.cipher != "" && (len(sc.cipher) > 8192 || !cipherString.MatchString(sc.cipher)) {
			sc.blocker = "the configured cipher string is not interpreted"
		}
		// TLS 1.3 のスイート: bind の行の ciphersuites、なければ全体の ssl-default-bind-ciphersuites
		if v := opts["ciphersuites"]; len(v) > 0 {
			sc.tls13, sc.tls13File, sc.tls13Line = v[len(v)-1], d.File, d.Line
		} else if g, ok := global["ssl-default-bind-ciphersuites"]; ok && !g.HasVariable {
			sc.tls13, sc.tls13File, sc.tls13Line = g.Args[0], g.File, g.Line
		}
		if sc.tls13 != "" && !cipherString.MatchString(sc.tls13) {
			sc.tls13, sc.tls13Blocker = "", "the configured TLS 1.3 suites are not interpreted"
		}
		// 証明書: crt に指定されたファイル。ディレクトリや一覧ファイル（crt-list）は、どの証明書が使われるかを追わない
		if len(opts["crt"]) == 0 || len(opts["crt-list"]) > 0 {
			sc.certsOK = false
		}
		for _, p := range opts["crt"] {
			if !strings.HasPrefix(p, "/") {
				if crtBase == "" {
					sc.certsOK = false
					continue
				}
				p = strings.TrimRight(crtBase, "/") + "/" + p
			}
			if strings.HasSuffix(p, "/") || strings.ContainsAny(p, "$*?[") {
				sc.certsOK = false
				continue
			}
			sc.certs = append(sc.certs, p)
		}
		// DH パラメータ: 全体の設定で長さかファイルが指定されていれば、DHE を使える
		_, size := global["tune.ssl.default-dh-param"]
		_, file := global["ssl-dh-param-file"]
		sc.dhParam = size || file
		scopes = append(scopes, sc)
	}
	c.opensslServerEffective(app, svc, scopes)
}

// haproxyBindOptions は、bind の行の指定を「名前 → 値の並び」にする。値を取らない指定は、空の並びで登録する。
func haproxyBindOptions(args []string) map[string][]string {
	opts := map[string][]string{}
	for i := 0; i < len(args); i++ {
		name := args[i]
		if haproxyBindValue[name] && i+1 < len(args) {
			i++
			opts[name] = append(opts[name], args[i])
			continue
		}
		if _, ok := opts[name]; !ok {
			opts[name] = nil
		}
	}
	return opts
}

// haproxyFiles は、HAProxy が読む設定ファイルの一覧を返す。
//
// ユニットの起動コマンドに -f の指定があれば、それに従う（RHEL 系は、主の設定ファイルに加えて /etc/haproxy/conf.d を読ませる）。
// ディレクトリが指定された場合は、その直下の *.cfg を名前の順に読む。ユニットがなければ、主の設定ファイルだけを読む。
func (c *Collector) haproxyFiles(config string, units []unitInfo) []string {
	var named []string
	for _, u := range units {
		args := c.unitArgs(u)
		for i := 1; i+1 < len(args); i++ {
			if args[i].text == "-f" {
				i++
				if strings.HasPrefix(args[i].text, "/") {
					named = append(named, args[i].text)
				}
			}
		}
		if len(named) > 0 {
			break
		}
	}
	if len(named) == 0 {
		return []string{config}
	}
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, p := range named {
		if _, err := c.read(p); err == nil {
			add(p)
			continue
		}
		files, _ := confFS{c}.Glob(strings.TrimRight(p, "/") + "/*.cfg")
		sort.Strings(files)
		for _, f := range files {
			add(f)
		}
	}
	if len(out) == 0 {
		return []string{config}
	}
	return out
}
