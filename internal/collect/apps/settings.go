// このファイルは、設定値の検証と記録。どのアプリにも共通（検証を通らない値は記録しない）。

package apps

import (
	"regexp"
	"strings"

	"kagiya/internal/model"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
	"kagiya/internal/tlsciphers"
)

var (
	algorithmList = regexp.MustCompile(`^[A-Za-z0-9@._*?-]+(,[A-Za-z0-9@._*?-]+)*$`)
	intValue      = regexp.MustCompile(`^[0-9]{1,9}$`)
	intList       = regexp.MustCompile(`^[0-9]{1,9}(,[0-9]{1,9})*$`)
	listItem      = regexp.MustCompile(`^[A-Za-z0-9@._*-]{1,128}$`)
	wordItem      = regexp.MustCompile(`^[A-Za-z0-9._:+=@!,*/\[\]-]{1,256}$`)
	cipherString  = regexp.MustCompile(`^[A-Za-z0-9_:+!@=. -]+$`)
	scopeText     = regexp.MustCompile(`^[A-Za-z0-9 ._:*\[\]-]{1,256}$`)
)

type valueStatus int

const (
	valueOK             valueStatus = iota
	valueInvalid                    // 設定値として妥当でない（記録しない。問題として報告する）
	valueNotInterpreted             // 変数を含むなど、値を確定できない（記録しない。問題としては数えない）
)

// fill は、値を種類ごとに検証して設定に入れる。検証を通らない値は記録しない（設定ファイルに紛れた秘密が出力に写るのを防ぐ）。
// baseDir は、相対パスの基準になるディレクトリ（接頭辞なし。空なら相対パスは受け付けない）。
func (c *Collector) fill(s *model.Setting, rule ruleset.DirectiveRule, args, baseDir string) valueStatus {
	if len(args) == 0 || len(args) > maxSettingValue {
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

// validCipherString は、設定に書かれた暗号文字列が、展開の対象にできる形（長さと使われている文字）かを返す。
func validCipherString(s string) bool {
	return s != "" && len(s) <= tlsciphers.MaxRuleLen && cipherString.MatchString(s)
}
