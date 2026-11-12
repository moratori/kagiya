package apps

import (
	"path"
	"strings"

	"kagiya/internal/model"
	"kagiya/internal/parse/sshdconf"
	"kagiya/internal/parse/unitfile"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

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
// 既定の一覧は、導入されているパッケージ版の既定値表から得る。実測した版そのものの表がなければ、
// パッケージ名・上流の版・ディストリの系列が同じ実測版の表で補間し、確度を一段下げて、その旨を注記に残す。
// それもなければ「不明」とし、理由を残す（上流の版やディストリが違う表では代用しない）。
func (c *Collector) sshdEffective(app ruleset.AppRule, svc model.Service) {
	defs, prov, defNote, noDefaults := c.appDefaults(app)

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
		// 補間した既定値を使った項目は、確度を一段下げる（一覧が明記されている項目は既定値を使わないので下げない）
		if defNote != "" && e.Status == "resolved" {
			for _, st := range e.Steps {
				if st.Layer == "app-default" {
					e.Confidence, e.Notes = "medium", []string{defNote}
					break
				}
			}
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
