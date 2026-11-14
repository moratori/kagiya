// このファイルは、サービスの設定（範囲ごとの、受け入れる方式の一覧と判定、設定の記載）の組み立て。

package report

import (
	"sort"
	"strings"

	"kagiya/internal/assess"
	"kagiya/internal/model"
)

// values は、名前の一覧を判定つきの行にする。
func (b *builder) values(parameter string, names []string) (rows []valueRow, reasons []string) {
	scheme := assess.SchemeFor(parameter)
	seen := map[string]bool{}
	for _, n := range names {
		row := valueRow{Name: n}
		if scheme != "" {
			vd, ok := b.ev.Value(scheme, n)
			if scheme == assess.SchemeTLSSuite {
				if s, found := b.rs.SuiteAttributes(n); found {
					row.Kx, row.Au, row.Enc = s.Kx, s.Au, s.Enc
				}
			}
			if ok || scheme != assess.SchemeTLSProtocol { // プロトコルの欄には版の名前でない語（all など）も入るので、当たらないものは判定を出さない
				row.HasVerdict, row.Verdict = true, vd
				row.Quantum, row.Classical = quantumBadge[vd.Quantum], classicalBadge[vd.Classical]
				if scheme == assess.SchemeTLSProtocol {
					// プロトコルの版は、現在の計算機に対する評価だけを持つ
					row.Quantum, row.Verdict.Quantum = badge{}, ""
				}
				for _, id := range vd.Rules {
					b.used[id] = true
					if !seen[id] {
						seen[id] = true
						reasons = append(reasons, id)
					}
					if r, found := b.rules[id]; found && r.Quantum == model.QuantumVulnerable {
						if r.Role == model.RoleKeyEstablishment {
							row.VulnKex = true
						} else {
							row.VulnSig = true
						}
					}
				}
			}
		}
		rows = append(rows, row)
	}
	return rows, reasons
}

func (b *builder) reasonViews(ids []string) []ruleView {
	titles := map[string]string{}
	for _, r := range b.ev.Policy().References {
		titles[r.ID] = r.Title
	}
	var out []ruleView
	for _, r := range b.ev.Policy().Rules { // ポリシーに書かれた順に並べる
		for _, id := range ids {
			if r.ID == id {
				out = append(out, b.rule(r, titles))
			}
		}
	}
	return out
}

func (b *builder) services(v *view) {
	svcs := append([]model.Service{}, b.inv.Services...)
	sort.SliceStable(svcs, func(i, j int) bool { return svcs[i].ID < svcs[j].ID })
	components := map[string]model.Component{}
	for _, c := range b.inv.Components {
		components[c.ID] = c
	}
	for _, s := range svcs {
		sv := serviceView{Name: s.App, Activity: activityLabel[s.Activity.Level], ActivityTip: activityTip[s.Activity.Level], Configs: s.ConfigFiles, Notes: s.Notes,
			Active: model.IsActive(s.Activity.Level)}
		if sv.Activity == "" {
			sv.Activity = s.Activity.Level
		}
		for _, e := range s.Activity.Evidence {
			sv.Evidence = append(sv.Evidence, evidenceText(e))
		}
		if c, ok := components[s.Component]; ok {
			sv.Component = c.Path
			if c.Version != nil {
				sv.Component += "（版 " + c.Version.Value + "）"
			}
			if c.Package != nil {
				sv.Component += "、パッケージ " + c.Package.Name + " " + c.Package.FullVersion()
			}
		}

		// 範囲（全体、server、VirtualHost など）ごとにまとめる
		var order []string
		scopes := map[string]*scopeView{}
		scope := func(name string) *scopeView {
			if scopes[name] == nil {
				scopes[name] = &scopeView{Name: name}
				order = append(order, name)
			}
			return scopes[name]
		}
		for _, e := range b.inv.EffectiveValues {
			if e.Service != s.ID {
				continue
			}
			ef := effectiveView{Label: label(e.Parameter), Parameter: e.Parameter, Resolved: e.Status == model.StatusResolved, Reason: e.Reason,
				IsSuite: assess.SchemeFor(e.Parameter) == assess.SchemeTLSSuite}
			switch e.Confidence {
			case "high":
				ef.Confidence = "確度: 高"
			case "medium":
				ef.Confidence = "確度: 中"
			}
			if ef.Resolved {
				var reasons []string
				ef.Rows, reasons = b.values(e.Parameter, e.Values)
				ef.Reasons = b.reasonViews(reasons)
				ef.Fold = len(ef.Rows) > foldRows
				ef.Counts = countText(ef.Rows)
				v.Summary.add(tally(ef.Rows))
			} else {
				v.Summary.Unresolved++
			}
			sc := scope(e.Scope)
			sc.Effective = append(sc.Effective, ef)
		}
		for _, set := range b.inv.Settings {
			if set.Service != s.ID {
				continue
			}
			st := settingView{Label: label(set.Parameter), Values: strings.Join(set.Values, " "), Location: location(set.Location.Path, set.Location.Line), Shadowed: !set.Effective}
			if set.Direction == "outbound" {
				st.Label += "（外向きの接続）"
			}
			if set.Modifier != "" {
				st.Values = set.Modifier + st.Values
			}
			if set.Parameter == model.ParamTLSProtocols {
				rows, _ := b.values(set.Parameter, set.Values)
				for _, r := range rows {
					if r.HasVerdict {
						st.Badges = append(st.Badges, r)
						if r.Verdict.Classical == model.ClassicalWeak {
							v.Summary.Weak++
						}
					}
				}
			}
			sc := scope(set.Scope)
			sc.Settings = append(sc.Settings, st)
		}
		sort.SliceStable(order, func(i, j int) bool { return order[i] < order[j] })
		for _, name := range order {
			sv.Scopes = append(sv.Scopes, *scopes[name])
		}
		v.Summary.Services++
		v.Services = append(v.Services, sv)
	}
	// 起動するよう設定されているサービスを先に並べる（どれも畳んで示す）
	sort.SliceStable(v.Services, func(i, j int) bool { return v.Services[i].Active && !v.Services[j].Active })
}
