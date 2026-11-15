package apps

import (
	"kagiya/internal/confidence"
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

// decidesOwnGroups は、設定に記載がないときの鍵交換のグループを、自分で決めるアプリ（システムの openssl.cnf やライブラリの既定には従わない）。
// これらのアプリでは、その版の既定のグループ（ルールの tls.groups）が分からなければ、結果を「不明」にする。
// システムの設定やライブラリの既定で代用すると、実物と食い違う（検証ラボの AlmaLinux 9.4 の Postfix 3.5.9 で確かめた）。
var decidesOwnGroups = map[string]bool{"postfix": true, "stunnel": true, "mysql": true}

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
	// システムの Groups / Curves が書かれているが、値を読めていない
	systemUnread bool
	// システムの暗号文字列を読めておらず、セキュリティレベルが分からない
	levelUnknown bool
	appProv      *model.Provenance
	appNote      string
	defs         map[string][]string
	defRule      defaultsRule    // アプリの既定値表の項目を使ったときの、確度の材料
	rule         confidence.Rule // 鍵交換のグループの対応表の、確度の材料
}

func (c *Collector) newGroupResolver(app ruleset.AppRule, svc model.Service, appProv *model.Provenance, appNote string, defs map[string][]string, defRule defaultsRule) *groupResolver {
	g := &groupResolver{c: c, app: app, svc: svc, appProv: appProv, appNote: appNote, defs: defs, defRule: defRule}
	key, prov, note, reason, rule := c.libraryTable("openssl", "group table", func(pkg, version string) (any, ruleset.CipherBuild, bool, bool) {
		tb, build, exact, ok := c.Rules.GroupTableFor("openssl", pkg, version)
		return tb, build, exact, ok
	})
	if key != nil {
		g.table, g.prov, g.note, g.rule = key.(*ruleset.GroupTable), prov, note, rule
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
		case model.OSSettingOpenSSLUnread:
			g.systemUnread = g.systemUnread || s.Value == "Groups" || s.Value == "Curves"
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
		Status: model.StatusResolved}
	fail := func(reason string) {
		e.Status, e.Reason = model.StatusUnresolved, reason
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
	// 確度の材料: 鍵交換のグループの対応表と、使ったアプリの既定値表の項目
	rules := []confidence.Rule{g.rule}
	use := func(item string) {
		if g.defRule != nil {
			rules = append(rules, g.defRule(item))
		}
	}
	for _, item := range sc.usedDefaults {
		use(item)
	}
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
		use(model.ParamTLSGroups)
		e.Steps = []model.ResolutionStep{{Layer: "app-default", Op: "default", Source: g.appProv}}
		if g.appNote != "" {
			notes = append(notes, g.appNote)
		}
	case decidesOwnGroups[g.app.ID]:
		// グループを自分で決めるアプリなのに、その版の既定のグループがルールにない。システムの設定やライブラリの既定で代用しない
		fail("the default groups of this version of the application are not recorded")
		return
	case g.systemUnread:
		fail("the Groups setting in the system OpenSSL configuration could not be read")
		return
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
			// セキュリティレベルがグループに及ぼす効果は、起動して確かめないと分からない。その版の表にこの項目がなければ、求めない
			fail("the effect of this security level on groups is not measured for this OpenSSL version")
			return
		}
	}
	if sc.noCert || sc.tls13Off {
		// 証明書がない、または設定で TLS 1.3 が有効でなければ TLS 1.3 を使えないので、TLS 1.2 以下の鍵交換で使えるグループだけが残る
		in12 := map[string]bool{}
		for _, n := range r.TLS12 {
			in12[n] = true
		}
		var kept []string
		for _, n := range values {
			if in12[n] {
				kept = append(kept, n)
			}
		}
		values = kept
	}
	if g.levelUnknown {
		fail("the security level is not known (the system cipher string could not be read), so the groups it allows cannot be determined")
		return
	}
	if g.note != "" {
		notes = append(notes, g.note)
	}
	if len(values) == 0 {
		notes = append(notes, "no group is usable with this configuration")
		e.Qualifiers = append(e.Qualifiers, model.QualifierNothingAccepted)
	}
	e.Values, e.Notes = values, notes
	g.c.Builder.AddEffective(e, rules...)
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
