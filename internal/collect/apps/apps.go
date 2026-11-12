// Package apps は、サーバーアプリケーションの設定を読むコレクタ。
//
// 設定ファイルに明記された暗号関連の値を、どこに書かれていたかとともに記録する。
// あわせて、サービスが起動するよう設定されているか（利用の確からしさ）を、systemd の定義から読む。
// アプリのコマンド（sshd -T など）や systemctl は実行しない。
//
// ここで記録するのは「設定に書かれている値」まで。記載のない項目の既定値の解決は別の段階で行う。
package apps

import (
	"regexp"
	"strings"

	"kagiya/internal/inventory"
	"kagiya/internal/model"
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

	if app.Grammar == "sshd" {
		c.sshd(app, svc, config, units)
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
		if !c.fill(&s, rule, d.args) {
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

// fill は、値を種類ごとに検証して設定に入れる。検証を通らない値は記録しない（設定ファイルに紛れた秘密が出力に写るのを防ぐ）。
func (c *Collector) fill(s *model.Setting, rule ruleset.DirectiveRule, args string) bool {
	if len(args) == 0 || len(args) > 8192 {
		return false
	}
	switch rule.Type {
	case "algorithm-list":
		if strings.ContainsAny(args[:1], "+-^") {
			s.Modifier, args = args[:1], args[1:]
		}
		if !algorithmList.MatchString(args) {
			return false
		}
		s.Values = strings.Split(args, ",")
	case "path":
		if !strings.HasPrefix(args, "/") || strings.ContainsAny(args, "\x00\n\r*?[$%~") || strings.Contains(args, "/../") || len(args) > 1024 {
			return false
		}
		s.Values = []string{args}
		s.ReferencedPaths = []string{c.Prefix + args}
	case "int":
		if !intValue.MatchString(args) {
			return false
		}
		s.Values = []string{args}
	case "int-list":
		if !intList.MatchString(args) {
			return false
		}
		s.Values = strings.Split(args, ",")
	default:
		return false
	}
	return true
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
