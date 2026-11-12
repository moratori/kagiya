// Package report は、スキャン結果から人が読むための HTML レポートを作る。
//
// 出力は単一の HTML ファイルで、外部の資源（スクリプト、スタイルシート、画像、フォント）を一切読まない。
// スクリプトは使わず、畳み込みは HTML の標準の要素（details）で行う。
// 結果に含まれる文字列（証明書の Subject、ファイルのパスなど）は攻撃者が決められるので、html/template の
// 文脈に応じたエスケープを通してだけ書き出す。
//
// 評価（量子計算機に弱いか、危殆化しているか）は、結果ファイルの中の判定を使わず、レポートを作る時点の
// 評価ポリシーでやり直す。
package report

import (
	_ "embed"
	"errors"
	"html/template"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"kagiya/internal/assess"
	"kagiya/internal/model"
	"kagiya/internal/ruleset"
)

//go:embed report.tmpl
var templateText string

var tmpl = template.Must(template.New("report").Parse(templateText))

// 値の一覧がこの数を超えたら、畳んで件数だけを見せる。
const foldRows = 12

// 期限が近いとみなす日数。
const expiringDays = 30

type builder struct {
	inv      *model.Inventory
	ev       *assess.Evaluator
	a        *model.Assessment
	rs       *ruleset.RuleSet
	scanTime time.Time
	settings map[string]model.Setting
	assets   map[string]model.Asset
	used     map[string]bool
	rules    map[string]ruleset.PolicyRule // 評価ポリシーの規則（ID から引く）
}

// Render は、1 ホスト分の結果からレポートを書き出す。
func Render(w io.Writer, inv *model.Inventory, rs *ruleset.RuleSet, policy string) error {
	return RenderAll(w, []*model.Inventory{inv}, rs, policy)
}

// RenderAll は、1 つ以上のホストの結果からレポートを書き出す。
// 複数のホストの場合は、全体の集計の画面と、ホストごとの詳細（1 ホストのときと同じ内容）を 1 つのファイルに入れる。
func RenderAll(w io.Writer, invs []*model.Inventory, rs *ruleset.RuleSet, policy string) error {
	if len(invs) == 0 {
		return errors.New("no result to report")
	}
	ev, err := assess.New(rs, policy)
	if err != nil {
		return err
	}
	// ホスト名の順（同じ名前ならスキャンの順）に並べる
	sorted := append([]*model.Inventory{}, invs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i].Meta, sorted[j].Meta
		if a.Host.Hostname != b.Host.Hostname {
			return a.Host.Hostname < b.Host.Hostname
		}
		return a.StartedAt < b.StartedAt
	})
	p := ev.Policy()
	pg := &page{Multi: len(sorted) > 1, PolicyTitle: p.Title, PolicyVersion: p.Version, ExpiringDays: expiringDays,
		Tips: map[string]string{
			"quantum": quantumBadge["vulnerable"].Tip, "reduced": quantumBadge["reduced"].Tip, "hybrid": quantumBadge["hybrid"].Tip,
			"weak": classicalBadge["weak"].Tip, "legacy": classicalBadge["legacy"].Tip, "unknown": quantumBadge["unknown"].Tip,
			"kex":         "通信の暗号鍵を相手と決める手順。ここが量子計算機に弱いと、いま記録された通信が将来解読され得ます（harvest now, decrypt later）",
			"sig":         "相手が本物であることを確かめる手順（証明書の署名、ホスト鍵など）。その時点で量子計算機が存在しなければ破られません",
			"unresolved":  "設定の書き方や、導入されている版の情報が足りず、受け入れる方式の一覧を求められなかった項目",
			"unconfirmed": "このツールが読んだ設定（対応しているサービスの設定）からは参照が見つからなかった秘密鍵。使われていないことを示すものではありません",
			"confidence":  "確度「高」は、導入されている版そのもので実測した表から求めた値。「中」は、近い版の実測を当てはめたか、証明書などを読めずに絞り込みの一部をしていない値",
		}}
	used := map[string]bool{}
	byID := make(map[string]ruleset.PolicyRule, len(p.Rules))
	for _, r := range p.Rules {
		byID[r.ID] = r
	}
	for i, inv := range sorted {
		b := &builder{inv: inv, ev: ev, a: ev.Assess(inv), rs: rs, settings: map[string]model.Setting{}, assets: map[string]model.Asset{}, used: used, rules: byID}
		for _, s := range inv.Settings {
			b.settings[s.ID] = s
		}
		for _, as := range inv.Assets {
			b.assets[as.ID] = as
		}
		for _, ts := range []string{inv.Meta.FinishedAt, inv.Meta.StartedAt} {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				b.scanTime = t
				break
			}
		}
		v := b.build(i + 1)
		v.Tips = pg.Tips
		pg.Hosts = append(pg.Hosts, v)
		pg.Total.add(v.Summary)
	}
	pg.TotalView = &view{Summary: pg.Total, Tips: pg.Tips, ExpiringDays: expiringDays}
	// 判定の理由として挙げた規則と、出典
	titles := map[string]string{}
	for _, r := range p.References {
		titles[r.ID] = r.Title
		pg.Refs = append(pg.Refs, refView{ID: r.ID, Title: r.Title, URL: r.URL, Note: r.Note})
	}
	for _, r := range p.Rules {
		if used[r.ID] {
			rv := ruleView{ID: r.ID, Summary: r.Summary}
			for _, id := range r.Refs {
				rv.Refs = append(rv.Refs, titles[id])
			}
			pg.Rules = append(pg.Rules, rv)
		}
	}
	return tmpl.Execute(w, pg)
}

func (b *builder) build(n int) *view {
	m := b.inv.Meta
	v := &view{N: n, H: "h" + strconv.Itoa(n), ViewID: "host-" + strconv.Itoa(n),
		Host: m.Host.Hostname, OSArch: m.Host.OS + " / " + m.Host.Arch, Started: m.StartedAt, Finished: m.FinishedAt,
		ToolVersion: m.Tool.Version, RulesVersion: m.Rules.Version, RulesSource: m.Rules.Source,
		Incomplete: !m.Completed, IncompleteReason: m.Incomplete, Elevated: m.Privilege.Elevated, Warnings: m.Warnings,
		ExpiringDays: expiringDays, Coverage: b.inv.Coverage, Roots: strings.Join(m.Invocation.Roots, "、")}
	if m.Host.Distribution != nil {
		v.Distribution = m.Host.Distribution.Name
	}
	for k, val := range m.Labels {
		v.Labels = append(v.Labels, k+"="+val)
	}
	sort.Strings(v.Labels)
	b.services(v)
	b.files(v)
	b.misc(v)
	return v
}

func (b *builder) rule(r ruleset.PolicyRule, titles map[string]string) ruleView {
	rv := ruleView{ID: r.ID, Summary: r.Summary}
	for _, id := range r.Refs {
		rv.Refs = append(rv.Refs, titles[id])
	}
	return rv
}
