package apps

import (
	"regexp"
	"strings"

	"kagiya/internal/model"
	"kagiya/internal/ruleset"
	"kagiya/internal/tlsgroups"
)

// このファイルは、OpenSSL を使う TLS サーバーに共通の「受け入れる鍵交換のグループ」の解決。
//
// グループの指定は、アプリの設定 > アプリ自身の既定（持つアプリだけ）> システムの openssl.cnf の Groups > ライブラリの既定
// の順で決まる。指定の解釈、知っている名前、既定は、パッケージ版ごとに実測した対応表（rules/groups）から引く。

// groupResolver は、1つのサービスの範囲に共通の、グループの解決に必要な情報。
type groupResolver struct {
	c       *Collector
	app     ruleset.AppRule
	svc     model.Service
	table   *ruleset.GroupTable
	prov    *model.Provenance // 対応表を実測した版
	note    string            // 補間した場合の注記
	noTable string            // 対応表がない理由
	system  string            // システムの openssl.cnf の Groups（古い書き方の Curves も同じ意味）
	appProv *model.Provenance
	appNote string
	defs    map[string][]string
}

func (c *Collector) newGroupResolver(app ruleset.AppRule, svc model.Service, appProv *model.Provenance, appNote string, defs map[string][]string) *groupResolver {
	g := &groupResolver{c: c, app: app, svc: svc, appProv: appProv, appNote: appNote, defs: defs}
	key, prov, note, reason := c.libraryTable("openssl", "group table", func(pkg, version string) (any, ruleset.CipherBuild, bool, bool) {
		tb, build, exact, ok := c.Rules.GroupTableFor("openssl", pkg, version)
		return tb, build, exact, ok
	})
	if key != nil {
		g.table, g.prov, g.note = key.(*ruleset.GroupTable), prov, note
	} else {
		g.noTable = reason
	}
	curves := ""
	for _, s := range c.Builder.OSSettings() {
		switch s.ID {
		case "openssl.system_default.Groups":
			g.system = s.Value
		case "openssl.system_default.Curves":
			curves = s.Value
		}
	}
	if g.system == "" {
		g.system = curves
	}
	return g
}

// resolve は、範囲1つについて、受け入れる鍵交換のグループを求めて記録する。
// level は、その範囲に適用されるセキュリティレベル（なければ負）。levelStep は、そのレベルがどこから来たかを表す段。
func (g *groupResolver) resolve(sc tlsScope, level int, levelStep model.ResolutionStep) {
	e := model.EffectiveValue{Service: g.svc.ID, Parameter: model.ParamTLSGroups, Direction: g.app.Direction, Scope: sc.name,
		Status: model.StatusResolved, Confidence: model.ConfidenceHigh}
	fail := func(reason string) {
		e.Status, e.Confidence, e.Reason = model.StatusUnresolved, "", reason
		g.c.Builder.AddEffective(e)
	}
	switch {
	case g.table == nil:
		fail(g.noTable)
		return
	case sc.groupsBlocker != "":
		fail(sc.groupsBlocker)
		return
	}
	var notes []string
	spec := ""
	appDefault := strings.Join(g.defs[model.ParamTLSGroups], ",")
	switch {
	case sc.groups != "":
		param := sc.groupsParam
		if param == "" {
			param = model.ParamTLSGroups
		}
		spec = sc.groups
		e.Steps = []model.ResolutionStep{{Layer: "app-config", Op: "override", Setting: g.c.settingAt(g.svc, param, sc.groupsFile, sc.groupsLine)}}
	case appDefault != "":
		// アプリ自身が既定のグループを持つ（システムの設定やライブラリの既定には従わない）
		spec = appDefault
		e.Steps = []model.ResolutionStep{{Layer: "app-default", Op: "default", Source: g.appProv}}
		if g.appNote != "" {
			notes = append(notes, g.appNote)
		}
	case g.system != "":
		spec = g.system
		e.Steps = []model.ResolutionStep{{Layer: "os-policy", Op: "override"}}
	default:
		e.Steps = []model.ResolutionStep{{Layer: "library", Op: "default", Source: g.prov}}
	}
	r, err := tlsgroups.Resolve(g.table, spec)
	if err != nil {
		fail("the group list is rejected by this OpenSSL version (unknown name, duplicate, or a form this version does not support)")
		return
	}
	if spec != "" {
		e.Steps = append(e.Steps, model.ResolutionStep{Layer: "library", Op: "expand", Source: g.prov})
	}
	values := r.Groups
	if level >= 0 {
		if usable, ok := tlsgroups.Usable(g.table, r.Groups, level); ok {
			values = usable
			if levelStep.Layer != "" {
				e.Steps = append(e.Steps, levelStep)
			}
		} else {
			notes = append(notes, "the effect of this security level on groups is not measured for this OpenSSL version, so groups are not narrowed down by it")
		}
	}
	if g.note != "" {
		notes = append(notes, g.note)
	}
	if len(values) == 0 {
		notes = append(notes, "no group is usable with this configuration")
	}
	e.Values, e.Notes = values, notes
	if len(notes) > 0 {
		e.Confidence = model.ConfidenceMedium
	}
	g.c.Builder.AddEffective(e)
}

// groupList は、解釈の対象にするグループの指定の形（名前、区切り、OpenSSL 3.5 の接頭辞）。
var groupList = regexp.MustCompile(`^[A-Za-z0-9_.:/?*-]+$`)

// setGroups は、アプリの設定に書かれたグループの指定を、範囲に載せる。what は、理由の文に入れる設定項目の名前。
func (sc *tlsScope) setGroups(value, file string, line int, what string) {
	if len(value) > 1024 || !groupList.MatchString(value) {
		sc.groups, sc.groupsBlocker = "", "the configured group list ("+what+") is not interpreted"
		return
	}
	sc.groups, sc.groupsFile, sc.groupsLine, sc.groupsBlocker = value, file, line, ""
}
