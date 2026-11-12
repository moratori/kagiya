// Package apps は、サーバーアプリケーションの設定を読むコレクタ。
//
// 設定ファイルに明記された暗号関連の値を、どこに書かれていたかとともに記録する。
// あわせて、サービスが起動するよう設定されているか（利用の確からしさ）を、systemd の定義から読む。
// アプリのコマンド（sshd -T など）や systemctl は実行しない。
//
// ここで記録するのは「設定に書かれている値」まで。記載のない項目の既定値の解決は別の段階で行う。
package apps

import (
	"path"
	"regexp"
	"strings"

	"kagiya/internal/inventory"
	"kagiya/internal/model"
	"kagiya/internal/parse/apacheconf"
	"kagiya/internal/parse/nginxconf"
	"kagiya/internal/parse/sshdconf"
	"kagiya/internal/parse/unitfile"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

const maxConfigSize = 1 << 20

// systemd のユニットファイルの置き場所（優先順）。出典: 設計書 13章（RHEL 8.10 / 9.9、Ubuntu 16.04 / 24.04 で確認）。
var unitDirs = []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"}

const systemdAdminDir = "/etc/systemd/system" // 有効化のリンク（*.wants/）とマスクが置かれる

var (
	algorithmList = regexp.MustCompile(`^[A-Za-z0-9@._*?-]+(,[A-Za-z0-9@._*?-]+)*$`)
	intValue      = regexp.MustCompile(`^[0-9]{1,9}$`)
	intList       = regexp.MustCompile(`^[0-9]{1,9}(,[0-9]{1,9})*$`)
	listItem      = regexp.MustCompile(`^[A-Za-z0-9@._*-]{1,128}$`)
	wordItem      = regexp.MustCompile(`^[A-Za-z0-9._:+=@!,*/\[\]-]{1,256}$`)
	cipherString  = regexp.MustCompile(`^[A-Za-z0-9_:+!@=. -]+$`)
	scopeText     = regexp.MustCompile(`^[A-Za-z0-9 ._:*\[\]-]{1,256}$`)
)

type Collector struct {
	Prefix  string // テスト用。通常は空
	Opener  *safefs.Opener
	Builder *inventory.Builder
	Rules   *ruleset.RuleSet
}

func (c *Collector) Collect() {
	for _, app := range c.Rules.Apps {
		if app.Grammar == "" {
			continue
		}
		c.application(app)
	}
}

func (c *Collector) read(path string) ([]byte, error) {
	return c.Opener.ReadFile(c.Prefix+path, maxConfigSize)
}

// confFS は、設定ファイルの中に書かれたパス（接頭辞なし）を、安全なファイルアクセスを通して読む。
type confFS struct{ c *Collector }

func (f confFS) ReadFile(p string) ([]byte, error) { return f.c.read(p) }

func (f confFS) Glob(pattern string) ([]string, error) {
	files, err := f.c.Opener.Glob(f.c.Prefix + pattern)
	for i := range files {
		files[i] = strings.TrimPrefix(files[i], f.c.Prefix)
	}
	return files, err
}

type unitInfo struct {
	name string
	path string // 接頭辞なし
	unit *unitfile.Unit
}

func (c *Collector) application(app ruleset.AppRule) {
	config := ""
	for _, p := range app.ConfigFiles {
		if _, err := c.read(p); err == nil {
			config = p
			break
		}
	}
	comp, hasComp := c.Builder.FindComponent("app:" + app.ID + ":")
	units := c.units(app)
	if config == "" && !hasComp && len(units) == 0 {
		return
	}
	svc := model.Service{ID: "svc:" + app.ID, App: app.ID}
	if hasComp {
		svc.Component = comp.ID
	}
	if config != "" {
		svc.ConfigFiles = []string{c.Prefix + config}
	}
	svc.Activity = c.activity(app, units, hasComp, comp)
	c.Builder.AddService(svc)

	switch app.Grammar {
	case "sshd":
		c.sshd(app, svc, config, units)
	case "nginx":
		c.nginx(app, svc, config)
	case "apache":
		c.apache(app, svc, config)
	}
}

// units は、アプリのユニットファイルのうち実在するものを読む。
func (c *Collector) units(app ruleset.AppRule) []unitInfo {
	var out []unitInfo
	for _, name := range app.Units {
		for _, dir := range unitDirs {
			path := dir + "/" + name
			if t, ok := c.Opener.LinkTarget(c.Prefix + path); ok && t == "/dev/null" {
				continue // マスク（起動しない設定）。定義としては読まない
			}
			data, err := c.read(path)
			if err != nil {
				continue
			}
			out = append(out, unitInfo{name: name, path: path, unit: unitfile.Parse(data)})
			break
		}
	}
	return out
}

// activity は、サービスの「利用の確からしさ」を決める。
// systemd は、*.wants / *.requires ディレクトリにユニットへのリンクがあると、起動時にそのユニットを立ち上げる。
func (c *Collector) activity(app ruleset.AppRule, units []unitInfo, hasComp bool, comp model.Component) model.Activity {
	var enabled, masked []model.Evidence
	isMasked := map[string]bool{}
	for _, name := range app.Units {
		p := c.Prefix + systemdAdminDir + "/" + name
		if t, ok := c.Opener.LinkTarget(p); ok && t == "/dev/null" {
			isMasked[name] = true
			masked = append(masked, model.Evidence{Kind: "unit-masked", Path: p, Detail: name})
		}
	}
	admin, err := c.Opener.Resolve(c.Prefix + systemdAdminDir)
	if err == nil {
		dirs, _ := c.Opener.ListNames(admin)
		for _, d := range dirs {
			if !d.IsDir || !(strings.HasSuffix(d.Name, ".wants") || strings.HasSuffix(d.Name, ".requires")) {
				continue
			}
			ents, _ := c.Opener.ListNames(admin + "/" + d.Name)
			for _, e := range ents {
				for _, name := range app.Units {
					if e.Name == name && !isMasked[name] {
						enabled = append(enabled, model.Evidence{Kind: "unit-enabled", Path: admin + "/" + d.Name + "/" + e.Name, Detail: name})
					}
				}
			}
		}
	}
	switch {
	case len(enabled) > 0:
		return model.Activity{Level: "enabled", Evidence: enabled}
	case len(masked) > 0:
		return model.Activity{Level: "installed", Evidence: masked}
	case len(units) > 0:
		return model.Activity{Level: "installed", Evidence: []model.Evidence{{Kind: "unit-present", Path: c.Prefix + units[0].path, Detail: units[0].name}}}
	case hasComp:
		return model.Activity{Level: "installed", Evidence: []model.Evidence{{Kind: "binary-present", Path: comp.Path}}}
	}
	return model.Activity{Level: "unknown"}
}

// directive は、設定の1項目（出どころ付き）。
type directive struct {
	keyword, args string
	file          string // 接頭辞なし
	line          int
	match         string
	source        string // command-line | config-file
}

// sshd は OpenSSH サーバーの設定を読む。
//
// sshd は「同じ項目は最初に得た値を使う」。起動引数の -o は設定ファイルより先に処理されるため、
// 起動引数で渡された値は設定ファイルの記載より優先される（RHEL 8 系は、システム全体の暗号ポリシーをこの方法で渡す）。
func (c *Collector) sshd(app ruleset.AppRule, svc model.Service, config string, units []unitInfo) {
	var ds []directive
	for _, u := range units {
		if !strings.HasSuffix(u.name, ".service") {
			continue
		}
		ds = append(ds, c.sshdCommandLine(u)...)
		break
	}
	if config != "" {
		parsed, problems := sshdconf.Parse(config, confFS{c})
		for _, pr := range problems {
			c.Builder.Skip(safefs.Skip{Path: c.Prefix + config, Reason: "config-problem", Detail: pr})
		}
		for _, d := range parsed {
			ds = append(ds, directive{d.Keyword, d.Args, d.File, d.Line, d.Match, "config-file"})
		}
	}

	seen := map[string]bool{} // 全体の設定として既に値を得た項目
	configured := map[string]bool{}
	for _, d := range ds {
		rule, ok := app.Directive(d.keyword)
		if !ok {
			continue
		}
		s := model.Setting{
			Service: svc.ID, Parameter: rule.Parameter, Direction: app.Direction, Basis: "configured",
			Layer: "app-config", Source: d.source,
			Location: model.SettingLocation{Path: c.Prefix + d.file, Line: d.line},
		}
		if strings.HasPrefix(d.file, "/etc/crypto-policies/") {
			s.Layer = "os-policy" // システム全体の暗号ポリシーが生成した設定
		}
		if d.match != "" {
			s.Scope = "Match " + d.match
		}
		if c.fill(&s, rule, d.args, "") != valueOK {
			c.Builder.Skip(safefs.Skip{Path: c.Prefix + d.file, Reason: "invalid-value", Detail: rule.Parameter})
			continue
		}
		if d.match == "" {
			s.Effective = rule.Multi || !seen[rule.Parameter]
			seen[rule.Parameter] = true
			configured[rule.Parameter] = true
		}
		c.Builder.AddSetting(s)
	}

	c.sshdEffective(app, svc)

	// 記載がない項目のうち、ファイルを指すもの（ホスト鍵）は、アプリの既定の場所を参照先として記録する。
	for _, ref := range app.DefaultReferences {
		if configured[ref.Parameter] {
			continue
		}
		for _, p := range ref.Paths {
			c.Builder.AddSetting(model.Setting{
				Service: svc.ID, Parameter: ref.Parameter, Direction: app.Direction, Basis: "default",
				Layer: "app-default", Source: "default", Values: []string{p}, Effective: true,
				ReferencedPaths: []string{c.Prefix + p},
			})
		}
	}
}

type valueStatus int

const (
	valueOK             valueStatus = iota
	valueInvalid                    // 設定値として妥当でない（記録しない。問題として報告する）
	valueNotInterpreted             // 変数を含むなど、値を確定できない（記録しない。問題としては数えない）
)

// fill は、値を種類ごとに検証して設定に入れる。検証を通らない値は記録しない（設定ファイルに紛れた秘密が出力に写るのを防ぐ）。
// baseDir は、相対パスの基準になるディレクトリ（接頭辞なし。空なら相対パスは受け付けない）。
func (c *Collector) fill(s *model.Setting, rule ruleset.DirectiveRule, args, baseDir string) valueStatus {
	if len(args) == 0 || len(args) > 8192 {
		return valueInvalid
	}
	each := func(items []string, re *regexp.Regexp) bool {
		if len(items) == 0 || len(items) > 256 {
			return false
		}
		for _, it := range items {
			if !re.MatchString(it) {
				return false
			}
		}
		return true
	}
	switch rule.Type {
	case "algorithm-list":
		if strings.ContainsAny(args[:1], "+-^") {
			s.Modifier, args = args[:1], args[1:]
		}
		if !algorithmList.MatchString(args) {
			return valueInvalid
		}
		s.Values = strings.Split(args, ",")
	case "colon-list":
		items := strings.Split(args, ":")
		if !each(items, listItem) {
			return valueInvalid
		}
		s.Values = items
	case "cipher-string":
		if !cipherString.MatchString(args) {
			return valueInvalid
		}
		s.Values = strings.Split(args, ":")
	case "words", "listen":
		items := strings.Fields(args)
		if !each(items, wordItem) {
			return valueInvalid
		}
		s.Values = items
	case "flag":
		v := strings.ToLower(args)
		if v != "on" && v != "off" {
			return valueInvalid
		}
		s.Values = []string{v}
	case "path":
		if strings.ContainsAny(args, "$%") {
			return valueNotInterpreted // 変数を含む。どのファイルかを確定できない
		}
		if strings.ContainsAny(args, "\x00\n\r*?[~") || len(args) > 1024 {
			return valueInvalid
		}
		full := args
		if !strings.HasPrefix(full, "/") {
			if baseDir == "" {
				return valueInvalid
			}
			full = strings.TrimRight(baseDir, "/") + "/" + full
		}
		for _, seg := range strings.Split(full, "/") {
			if seg == ".." {
				return valueInvalid
			}
		}
		s.Values = []string{args}
		s.ReferencedPaths = []string{c.Prefix + full}
	case "int":
		if !intValue.MatchString(args) {
			return valueInvalid
		}
		s.Values = []string{args}
	case "int-list":
		if !intList.MatchString(args) {
			return valueInvalid
		}
		s.Values = strings.Split(args, ",")
	default:
		return valueInvalid
	}
	return valueOK
}

// record は、設定の1項目を検証して記録する。
func (c *Collector) record(app ruleset.AppRule, svc model.Service, rule ruleset.DirectiveRule, args, file string, line int, scope, baseDir string) {
	s := model.Setting{
		Service: svc.ID, Parameter: rule.Parameter, Direction: app.Direction, Scope: scope, Basis: "configured",
		Layer: "app-config", Source: "config-file", Effective: true,
		Location: model.SettingLocation{Path: c.Prefix + file, Line: line},
	}
	if rule.Direction != "" {
		s.Direction = rule.Direction
	}
	switch c.fill(&s, rule, args, baseDir) {
	case valueOK:
		c.Builder.AddSetting(s)
	case valueNotInterpreted:
		c.Builder.Skip(safefs.Skip{Path: c.Prefix + file, Reason: "not-interpreted", Detail: rule.Parameter})
	default:
		c.Builder.Skip(safefs.Skip{Path: c.Prefix + file, Reason: "invalid-value", Detail: rule.Parameter})
	}
}

func dirOf(path string) string {
	if i := strings.LastIndexByte(path, '/'); i > 0 {
		return path[:i]
	}
	return "/"
}

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

// sshdCommandLine は、ユニットファイルの ExecStart と環境ファイルから、sshd に渡される -o オプションを読む。
func (c *Collector) sshdCommandLine(u unitInfo) []directive {
	type envVal struct {
		value string
		file  string
		line  int
	}
	env := map[string]envVal{}
	for _, ef := range u.unit.Values("Service", "EnvironmentFile") {
		ef = strings.TrimPrefix(ef, "-") // 先頭の - は「なくてもよい」の意味
		if !strings.HasPrefix(ef, "/") {
			continue
		}
		data, err := c.read(ef)
		if err != nil {
			continue
		}
		for _, e := range unitfile.ParseEnv(data) {
			env[e.Key] = envVal{e.Value, ef, e.Line} // 後から読んだファイルの値が有効
		}
	}
	execs := u.unit.Values("Service", "ExecStart")
	if len(execs) == 0 {
		return nil
	}
	type arg struct {
		text string
		file string
		line int
	}
	var args []arg
	for _, w := range unitfile.Words(strings.TrimLeft(execs[0], "-@:+!")) {
		switch {
		case w.Variable == "":
			args = append(args, arg{w.Text, u.path, 0})
		case w.Braced:
			if v, ok := env[w.Variable]; ok && v.value != "" {
				args = append(args, arg{v.value, v.file, v.line})
			}
		default:
			v := env[w.Variable]
			for _, f := range strings.Fields(v.value) {
				args = append(args, arg{f, v.file, v.line})
			}
		}
	}
	var out []directive
	for i := 1; i < len(args); i++ {
		opt := ""
		switch {
		case args[i].text == "-o" && i+1 < len(args):
			i++
			opt = args[i].text
		case strings.HasPrefix(args[i].text, "-o") && len(args[i].text) > 2:
			opt = args[i].text[2:]
		default:
			continue
		}
		k, v, ok := strings.Cut(opt, "=")
		if !ok {
			k, v, _ = strings.Cut(opt, " ")
		}
		out = append(out, directive{strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v), args[i].file, args[i].line, "", "command-line"})
	}
	return out
}

// sshdEffective は、sshd の各項目の実効値を求める。
//
//   - 一覧が明記されていれば、それが実効値（既定値を置き換える）。
//   - 「+追加」「-削除」「^先頭へ」の書き方なら、既定の一覧を加工する。
//   - 記載がなければ、既定の一覧がそのまま実効値。
//
// 既定の一覧は、導入されているパッケージ版と完全に一致する既定値表から得る。
// 一致する表がなければ「不明」とし、理由を残す（近い版の値で代用しない）。
func (c *Collector) sshdEffective(app ruleset.AppRule, svc model.Service) {
	var defs map[string][]string
	var prov *model.Provenance
	noDefaults := "no package information for this application; the default values are unknown"
	for _, pat := range app.Packages {
		found := false
		for _, p := range c.Builder.Packages() {
			if !ruleset.MatchName([]string{pat}, p.Name) {
				continue
			}
			found = true
			version := p.Version
			if p.Release != "" {
				version += "-" + p.Release
			}
			if d, src, ok := c.Rules.AppDefaults(app.ID, p.Name, version); ok {
				defs = d
				prov = &model.Provenance{Image: src.Image, OS: src.OS, Package: p.Name, Version: version}
			} else {
				noDefaults = "no default values are recorded for " + p.Name + " " + version
			}
			break
		}
		if found {
			break
		}
	}

	configured := map[string]*model.Setting{}
	settings := c.Builder.Settings()
	for i := range settings {
		s := &settings[i]
		if s.Service == svc.ID && s.Basis == "configured" && s.Effective && s.Scope == "" && configured[s.Parameter] == nil {
			configured[s.Parameter] = s
		}
	}
	done := map[string]bool{}
	for _, rule := range app.Directives {
		if done[rule.Parameter] || rule.Multi || (rule.Type != "algorithm-list" && rule.Type != "int" && rule.Type != "int-list") {
			continue
		}
		done[rule.Parameter] = true
		conf, def := configured[rule.Parameter], defs[rule.Parameter]
		e := model.EffectiveValue{Service: svc.ID, Parameter: rule.Parameter, Direction: app.Direction, Status: "resolved", Confidence: "high"}
		unresolved := func(reason string) {
			e.Status, e.Confidence, e.Values, e.Reason = "unresolved", "", nil, reason
		}
		defaultStep := model.ResolutionStep{Layer: "app-default", Op: "default", Source: prov}
		switch {
		case conf == nil && def == nil:
			if defs != nil {
				continue // この版には存在しない項目
			}
			unresolved(noDefaults)
		case conf == nil:
			e.Values, e.Steps = def, []model.ResolutionStep{defaultStep}
		case conf.Modifier == "":
			if hasWildcard(conf.Values) {
				unresolved("a list with wildcards needs the full list of algorithms supported by this version")
				break
			}
			e.Values = conf.Values
			e.Steps = []model.ResolutionStep{{Layer: conf.Layer, Op: "override", Setting: conf.ID}}
		case def == nil:
			unresolved(noDefaults + "; the configuration modifies the default list")
		default:
			values, op, ok := modifyList(def, conf.Modifier, conf.Values)
			if !ok {
				unresolved("a list with wildcards needs the full list of algorithms supported by this version")
				break
			}
			e.Values = values
			e.Steps = []model.ResolutionStep{defaultStep, {Layer: conf.Layer, Op: op, Setting: conf.ID}}
		}
		c.Builder.AddEffective(e)
	}
}

func hasWildcard(items []string) bool {
	for _, it := range items {
		if strings.ContainsAny(it, "*?") {
			return true
		}
	}
	return false
}

// modifyList は、既定の一覧に OpenSSH の加工の書き方を適用する。
//   - : 一覧にないものを末尾に追加   - : パターンに合うものを削除   ^ : 指定したものを先頭に置く
//
// 追加と先頭指定でワイルドカードが使われている場合は、その版が対応する全アルゴリズムの一覧が要るため、解決しない。
func modifyList(def []string, modifier string, items []string) (out []string, op string, ok bool) {
	in := func(list []string, s string) bool {
		for _, x := range list {
			if x == s {
				return true
			}
		}
		return false
	}
	switch modifier {
	case "+":
		if hasWildcard(items) {
			return nil, "", false
		}
		out = append(out, def...)
		for _, it := range items {
			if !in(out, it) {
				out = append(out, it)
			}
		}
		return out, "append", true
	case "^":
		if hasWildcard(items) {
			return nil, "", false
		}
		for _, it := range items {
			if !in(out, it) {
				out = append(out, it)
			}
		}
		for _, d := range def {
			if !in(out, d) {
				out = append(out, d)
			}
		}
		return out, "prepend", true
	case "-":
		for _, d := range def {
			removed := false
			for _, pat := range items {
				if m, err := path.Match(pat, d); err == nil && m {
					removed = true
					break
				}
			}
			if !removed {
				out = append(out, d)
			}
		}
		return out, "remove", true
	}
	return nil, "", false
}
