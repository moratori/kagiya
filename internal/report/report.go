// Package report は、スキャン結果から人が読むための HTML レポートを作る。
//
// 出力は単一の HTML ファイルで、外部の資源（スクリプト、スタイルシート、画像、フォント）を一切読まない。
// スクリプトは使わず、畳み込みは HTML の標準の要素（details）で行う。
// 結果に含まれる文字列（証明書の Subject、ファイルのパスなど）は攻撃者が決められるので、必ずエスケープして書き出す
// （書き出しの規則は render.go）。テンプレートエンジンは使わない。
//
// 評価（量子計算機に弱いか、危殆化しているか）は、結果ファイルの中の判定を使わず、レポートを作る時点の
// 評価ポリシーでやり直す。
package report

import (
	"bytes"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"kagiya/internal/assess"
	"kagiya/internal/convert"
	"kagiya/internal/model"
	"kagiya/internal/ruleset"
)

// 値の一覧がこの数を超えたら、畳んで件数だけを見せる。
const foldRows = 12

// 期限が近いとみなす日数。
const expiringDays = 30

// レポートに埋め込む CBOM の合計の上限（これを超える分のホストには、保存用のリンクを付けない）。
const maxEmbeddedCBOM = 48 << 20

// maxEmbeddedCBOMPerHost は、1 ホスト分の CBOM の上限（1 つのホストが、埋め込みの枠を使い切らないように）。
const maxEmbeddedCBOMPerHost = 8 << 20

// fileSafe は、ファイル名に使える文字（英数字と . _ -）以外を「_」に置き換える。
func fileSafe(s string) string {
	b := []byte(s)
	for i, c := range b {
		if !(c == '.' || c == '_' || c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			b[i] = '_'
		}
	}
	if len(b) == 0 {
		return "host"
	}
	if len(b) > 100 {
		b = b[:100]
	}
	return string(b)
}

type builder struct {
	inv      *model.Inventory
	ev       *assess.Evaluator
	a        *model.Assessment
	rs       *ruleset.RuleSet
	scanTime time.Time
	assets   map[string]model.Asset
	used     map[string]bool
	rules    map[string]ruleset.PolicyRule // 評価ポリシーの規則（ID から引く）
}

// Render は、1 ホスト分の結果からレポートを書き出す。
func Render(w io.Writer, inv *model.Inventory, rs *ruleset.RuleSet, policy string) error {
	return RenderAll(w, []*model.Inventory{inv}, rs, policy)
}

// issueURL は、「測定が要る版」を知らせる先（kagiya のリポジトリの、Issue を書くページ）。
// リンクには、一覧の中身を入れない（利用者が、コピー用の一覧を自分で貼り付ける）。
const issueURL = "https://github.com/moratori/kagiya/issues/new"

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
			"confidence":  "確度は、この値を求めるのに使った事前の測定の表が、このホストにどれだけ合っているかを表します。「高」は、導入されている版そのものの表で、実際の通信（ハンドシェイク）で裏付けたもの。「中」は、近い版の表で補ったか、裏付けのない表を使ったかの、どちらか一方。「低」は、その両方",
		}}
	used := map[string]bool{}
	embedded := 0
	byID := make(map[string]ruleset.PolicyRule, len(p.Rules))
	for _, r := range p.Rules {
		byID[r.ID] = r
	}
	for i, inv := range sorted {
		b := &builder{inv: inv, ev: ev, a: ev.Assess(inv), rs: rs, assets: map[string]model.Asset{}, used: used, rules: byID}
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
		// CBOM を作って埋め込む（保存用のリンクにする）。ホストが多いときは、ファイルが大きくなりすぎないところまで
		var cb bytes.Buffer
		// 判定は、このレポートを作る時点のルールでやり直したものを使う（入力の結果ファイルに書かれた判定は使わない）
		fresh := *inv
		fresh.Assessment = b.a
		if err := convert.WriteCBOMCompact(&fresh, &cb); err == nil && cb.Len() <= maxEmbeddedCBOMPerHost && embedded+cb.Len() <= maxEmbeddedCBOM {
			embedded += cb.Len()
			v.CBOM = cb.Bytes()
		}
		pg.Hosts = append(pg.Hosts, v)
		pg.Total.add(v.Summary)
	}
	pg.Unmeasured = unmeasuredRows(sorted)
	pg.TotalView = &view{Summary: pg.Total, Tips: pg.Tips, ExpiringDays: expiringDays}
	// 全体の集計には、どれかのホストで探索した起点を、重複なく並べる
	seenRoot := map[string]bool{}
	for _, v := range pg.Hosts {
		for _, r := range v.RootList {
			if !seenRoot[r] {
				seenRoot[r] = true
				pg.TotalView.RootList = append(pg.TotalView.RootList, r)
			}
		}
	}
	sort.Strings(pg.TotalView.RootList)
	// 証明書ストアの件数は、ストアごとに、ホストをまたいで足す
	storeTotal := map[string]int{}
	for _, v := range pg.Hosts {
		for _, sc := range v.StoreCounts {
			storeTotal[sc.Name] += sc.Count
		}
	}
	for name, n := range storeTotal {
		pg.TotalView.StoreCounts = append(pg.TotalView.StoreCounts, storeCount{Name: name, Count: n})
	}
	sort.Slice(pg.TotalView.StoreCounts, func(i, j int) bool { return pg.TotalView.StoreCounts[i].Name < pg.TotalView.StoreCounts[j].Name })
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
	return renderPage(w, pg)
}

func (b *builder) build(n int) *view {
	m := b.inv.Meta
	v := &view{N: n, H: "h" + strconv.Itoa(n), ViewID: "host-" + strconv.Itoa(n),
		Host: m.Host.Hostname, ScanID: shortID(m.ScanID), OSArch: m.Host.OS + " / " + m.Host.Arch, Started: m.StartedAt, Finished: m.FinishedAt,
		ToolVersion: m.Tool.Version, RulesVersion: m.Rules.Version, RulesSource: m.Rules.Source,
		Incomplete: !m.Completed, IncompleteReason: m.Incomplete, Elevated: m.Privilege.Elevated, Warnings: m.Warnings,
		ExpiringDays: expiringDays, Coverage: b.inv.Coverage, Roots: strings.Join(m.Invocation.Roots, "、"),
		RootList: m.Invocation.Roots, CBOMName: "kagiya-" + fileSafe(m.Host.Hostname) + ".cdx.json"}
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

// shortID は、スキャン ID の先頭 8 文字（英数字だけ）を返す。ホスト名は自己申告で重なりうるので、見分ける手掛かりとして出す。
func shortID(id string) string {
	out := make([]byte, 0, 8)
	for i := 0; i < len(id) && len(out) < 8; i++ {
		if c := id[i]; (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			out = append(out, c)
		}
	}
	return string(out)
}

// 測定が要る版の、種類の表示名。
var unmeasuredKind = map[string]string{
	"app-defaults": "既定値", "cipher-table": "暗号スイートの表", "group-table": "鍵交換のグループの表", "jdk": "JDK の表",
	"tomcat": "Tomcat の表", "spring-boot": "Spring Boot", "embedded-tomcat": "同梱の Tomcat", "wildfly": "WildFly の表",
}

// unmeasuredRows は、全ホストの「測定が要る版」を、OS・種類・名前・版ごとに 1 行にまとめる。ホスト名や場所は持たない。
func unmeasuredRows(invs []*model.Inventory) []unmeasuredRow {
	seen := map[unmeasuredRow]bool{}
	var out []unmeasuredRow
	for _, inv := range invs {
		os := "unknown"
		if d := inv.Meta.Host.Distribution; d != nil && d.ID != "" {
			os = d.ID + " " + d.VersionID
		}
		for _, u := range inv.Unmeasured {
			r := unmeasuredRow{OS: os, Kind: u.Kind, Name: u.Name, Version: u.Version, Status: u.Status, Measured: u.Measured}
			if !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		x, y := out[i], out[j]
		switch {
		case x.OS != y.OS:
			return x.OS < y.OS
		case x.Kind != y.Kind:
			return x.Kind < y.Kind
		case x.Name != y.Name:
			return x.Name < y.Name
		}
		return x.Version < y.Version
	})
	return out
}

// line は、コピー用の 1 行（タブ区切り）。
func (r unmeasuredRow) line() string {
	return r.OS + "\t" + r.Kind + "\t" + r.Name + "\t" + r.Version + "\t" + r.Status
}
