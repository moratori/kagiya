// Package apps は、サーバーアプリケーションの設定を読むコレクタ。
//
// 設定ファイルに明記された暗号関連の値を、どこに書かれていたかとともに記録する。
// あわせて、サービスが起動するよう設定されているか（利用の確からしさ）を、systemd の定義から読む。
// アプリのコマンド（sshd -T など）や systemctl は実行しない。
//
// このファイルは、どのアプリにも共通の部分（アプリの発見、起動定義と有効化状態、設定値の検証と記録）。
// アプリごとの設定の意味（どの記載が効くか、引き継ぎ、実効値の解決）は、アプリ別のファイルに分けている
// （sshd.go、nginx.go、apache.go）。版やディストリで変わる値は、コードではなくルール（rules/）に持つ。
package apps

import (
	"regexp"
	"strings"

	"kagiya/internal/inventory"
	"kagiya/internal/model"
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
