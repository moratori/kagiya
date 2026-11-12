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

type badge struct {
	Label string
	Class string
	Tip   string // マウスを載せると出る説明
}

var quantumBadge = map[string]badge{
	"vulnerable":   {"量子計算機に弱い", "bad", "現行の公開鍵暗号（RSA、楕円曲線、DH など）。暗号解読に使える水準の量子計算機ができると破られるため、耐量子の方式への移行の対象です"},
	"hybrid":       {"ハイブリッド", "good", "現行の方式と耐量子の方式を組み合わせた鍵交換。どちらか一方が破られても安全性が保たれるように作られています"},
	"resistant":    {"耐量子", "good", "量子計算機でも破れないと考えられている方式（耐量子の公開鍵暗号、または十分な長さの共通鍵暗号・ハッシュ関数）"},
	"reduced":      {"量子計算機で強度が下がる", "warn", "共通鍵暗号・ハッシュ関数のうち、量子計算機で強度が下がり、CRYPTREC の耐量子計算機暗号リストに載っていない長さのもの（AES-128、SHA-256 など）。NIST は置き換えを求めていません"},
	"not-targeted": {"対象外", "none", "参照した文書に、耐量子の観点での記載がない共通鍵暗号・MAC など"},
	"unknown":      {"判定できない", "unk", "この情報だけでは判定できないもの（参照した文書に記載がない方式、または決まり方が別の設定によるもの）"},
}

var classicalBadge = map[string]badge{
	"weak":    {"危殆化", "bad", "現在の計算機でも安全とは言えないもの。すでに解読の恐れがある方式や、必要な強度（112 ビット）に満たない鍵長・方式です"},
	"legacy":  {"非推奨", "warn", "いますぐ危険ではないが、公的な文書で推奨されなくなった方式や、強度が 112 ビットで移行の期限（2030 年）が示されているもの"},
	"ok":      {"指摘なし", "none", "参照した文書に照らして、現在の計算機に対する問題は見つかっていないもの（量子計算機に対する評価は別の列です）"},
	"unknown": {"判定できない", "unk", "参照した文書に記載がなく、判定できないもの"},
}

var activityTip = map[string]string{
	"running":    "プロセスが動いていることを確認できたもの",
	"enabled":    "OS の起動時に立ち上がるよう設定されているサービス（実際に動いているかは確認していません）",
	"referenced": "サービスの設定ファイルから参照されているもの",
	"installed":  "導入されているが、起動するよう設定されていないもの（手動で起動されている可能性はあります）",
	"unknown":    "このツールが読んだ設定からは、使われ方が分からないもの",
}

// 読み飛ばしの理由の表示名。
var skipLabel = map[string]string{
	"permission-denied":    "権限がなく読めなかった",
	"network-fs":           "ネットワーク越しのファイルシステム（読まない）",
	"unknown-fs":           "種別が分からないファイルシステム（読まない）",
	"excluded":             "除外の指定（結果の出力先など）",
	"not-found":            "指定された場所がなかった",
	"invalid-root":         "探索の起点として使えなかった",
	"parse-error":          "形式を解釈できなかった",
	"config-problem":       "設定ファイルの一部を読めなかった",
	"invalid-value":        "設定値として妥当でなかった",
	"not-interpreted":      "値を確定できなかった設定（変数を含むなど）",
	"unrecognized-setting": "記録の対象外の設定項目",
}

var activityLabel = map[string]string{
	"running": "稼働中", "enabled": "有効", "referenced": "参照あり", "installed": "導入のみ", "unknown": "不明",
}

var parameterLabel = map[string]string{
	"tls.ciphers":                       "暗号スイート（TLS 1.2 以下）",
	"tls.ciphersuites-tls13":            "暗号スイート（TLS 1.3）",
	"tls.protocols":                     "プロトコル",
	"tls.listen":                        "待ち受け",
	"tls.enabled":                       "TLS の有効化",
	"tls.groups":                        "鍵交換のグループ",
	"tls.prefer-server-ciphers":         "サーバー側の優先順を使う",
	"tls.certificate":                   "証明書",
	"tls.private-key":                   "秘密鍵",
	"tls.certificate-chain":             "証明書チェーン",
	"tls.dh-params":                     "DH パラメータ",
	"tls.trusted-certificates":          "信頼する証明書",
	"tls.client-ca":                     "クライアント証明書の CA",
	"tls.openssl-conf-cmd":              "OpenSSL の設定を直接変える指定",
	"ssh.kex-algorithms":                "鍵交換",
	"ssh.gssapi-kex-algorithms":         "GSSAPI の鍵交換",
	"ssh.host-key-algorithms":           "ホスト鍵の署名方式",
	"ssh.pubkey-accepted-algorithms":    "公開鍵認証で受け付ける署名方式",
	"ssh.hostbased-accepted-algorithms": "ホストベース認証で受け付ける署名方式",
	"ssh.ca-signature-algorithms":       "証明書の署名で受け付ける方式",
	"ssh.ciphers":                       "暗号",
	"ssh.macs":                          "MAC",
	"ssh.required-rsa-size":             "RSA 鍵長の下限",
	"ssh.protocol":                      "プロトコルの版",
	"ssh.host-key":                      "ホスト鍵",
}

// 実効値の項目 → 評価での名前の種類（assess と同じ対応）。
var valueScheme = map[string]string{
	"tls.ciphers": "tls-suite", "tls.ciphersuites-tls13": "tls-suite",
	"ssh.kex-algorithms": "ssh-kex", "ssh.host-key-algorithms": "ssh-key", "ssh.pubkey-accepted-algorithms": "ssh-key",
	"ssh.hostbased-accepted-algorithms": "ssh-key", "ssh.ca-signature-algorithms": "ssh-key",
	"ssh.ciphers": "ssh-cipher", "ssh.macs": "ssh-mac", "tls.protocols": "tls-protocol",
}

type valueRow struct {
	Name        string
	Kx, Au, Enc string // 暗号スイートの場合だけ
	Quantum     badge
	Classical   badge
	HasVerdict  bool
	VulnKex     bool // 鍵交換が量子計算機に弱い
	VulnSig     bool // 署名・認証が量子計算機に弱い
}

type ruleView struct {
	ID      string
	Summary string
	Refs    []string // 文書の題名
}

type effectiveView struct {
	Label      string
	Parameter  string
	Resolved   bool
	Confidence string
	Reason     string
	Notes      []string
	Steps      []string
	IsSuite    bool
	Rows       []valueRow
	Fold       bool
	Counts     string
	Reasons    []ruleView
}

type settingView struct {
	Label    string
	Values   string
	Location string
	Shadowed bool
	Badges   []valueRow
}

type scopeView struct {
	Name      string
	Effective []effectiveView
	Settings  []settingView
}

type serviceView struct {
	Name        string
	Activity    string
	ActivityTip string
	Active      bool // 起動するよう設定されている（稼働中を含む）
	Evidence    []string
	Component   string
	Configs     []string
	Notes       []string
	Scopes      []scopeView
}

type assetRow struct {
	Kind      string
	Name      string
	Algorithm string
	Expiry    string
	ExpiryTag badge
	Path      string
	Activity  string
	Evidence  []string
	Quantum   badge
	Classical badge
}

type storeGroup struct {
	Signature string
	Count     int
	Quantum   badge
	Classical badge
	Rows      []assetRow
}

type storeView struct {
	Name   string
	Count  int
	Groups []storeGroup
}

type kv struct{ Key, Value, Where string }

type refView struct {
	ID, Title, URL, Note string
}

// summaryView は要点の数。サービスの設定の数は、サービス・範囲ごとに許可されている方式の延べ数。
type summaryView struct {
	Services   int // 見つかったサービス（起動するよう設定されているかどうかによらない）
	Quantum    int // 量子計算機に弱い方式（鍵交換か署名・認証のどちらかが弱いもの）
	Kex        int // うち、鍵交換が弱いもの
	Sig        int // うち、署名・認証が弱いもの
	Reduced    int // 量子計算機で強度が下がる方式
	Hybrid     int
	Weak       int
	Legacy     int
	Unknown    int
	Unresolved int

	FileQuantum int
	FileWeak    int
	FileLegacy  int
	Expired     int
	Expiring    int
	Unconfirmed int // 設定からの参照を確認できなかった秘密鍵

	Files      int
	Dirs       int
	Permission int // 権限がなく読めなかったもの
	OtherSkips int // それ以外の読み飛ばし（除外の指定を除く）
}

func (s *summaryView) add(o summaryView) {
	s.Services += o.Services
	s.Quantum += o.Quantum
	s.Kex += o.Kex
	s.Sig += o.Sig
	s.Reduced += o.Reduced
	s.Hybrid += o.Hybrid
	s.Weak += o.Weak
	s.Legacy += o.Legacy
	s.Unknown += o.Unknown
	s.Unresolved += o.Unresolved
	s.FileQuantum += o.FileQuantum
	s.FileWeak += o.FileWeak
	s.FileLegacy += o.FileLegacy
	s.Expired += o.Expired
	s.Expiring += o.Expiring
	s.Unconfirmed += o.Unconfirmed
	s.Files += o.Files
	s.Dirs += o.Dirs
	s.Permission += o.Permission
	s.OtherSkips += o.OtherSkips
}

// view は 1 ホスト分の表示。
type view struct {
	N      int    // 何番目のホストか（1 始まり）
	H      string // このホストの中の見出しの ID に付ける接頭辞（h1、h2 …）
	ViewID string // このホストの表示のまとまりの ID（host-1 …）

	Host, OSArch, Distribution, Started, Finished string
	ToolVersion, RulesVersion                     string
	RulesSource                                   string
	Labels                                        []string
	Incomplete                                    bool
	IncompleteReason                              string
	Elevated                                      bool
	Warnings                                      []string
	ExpiringDays                                  int
	Roots                                         string

	Summary     summaryView
	Services    []serviceView
	Unconfirmed []assetRow
	Files       []assetRow
	Stores      []storeView
	OSSettings  []kv
	Packages    []kv
	Components  []kv
	Skipped     []kv
	SkippedBy   []kv
	SkippedCut  bool
	Coverage    model.Coverage
	Tips        map[string]string // 用語の説明（マウスを載せると出る）
}

// page はレポート全体。
type page struct {
	Multi                      bool // 複数ホスト（全体の集計の画面を持つ）
	Hosts                      []*view
	Total                      summaryView
	PolicyTitle, PolicyVersion string
	ExpiringDays               int
	Rules                      []ruleView
	Refs                       []refView
	Tips                       map[string]string
	TotalView                  *view // 全体の集計（要点の表示に使う）
}

type builder struct {
	inv      *model.Inventory
	ev       *assess.Evaluator
	a        *model.Assessment
	rs       *ruleset.RuleSet
	scanTime time.Time
	settings map[string]model.Setting
	assets   map[string]model.Asset
	used     map[string]bool
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
	for i, inv := range sorted {
		b := &builder{inv: inv, ev: ev, a: ev.Assess(inv), rs: rs, settings: map[string]model.Setting{}, assets: map[string]model.Asset{}, used: used}
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

func location(path string, line int) string {
	if path == "" {
		return ""
	}
	if line > 0 {
		return path + ":" + strconv.Itoa(line)
	}
	return path
}

func label(parameter string) string {
	if l, ok := parameterLabel[parameter]; ok {
		return l
	}
	return parameter
}

func evidenceText(e model.Evidence) string {
	kind := map[string]string{
		"unit-enabled": "起動するよう設定されている", "unit-masked": "起動しないよう設定されている", "unit-present": "起動の定義がある（有効化はされていない）",
		"binary-present": "プログラムが導入されている", "config-reference": "設定から参照されている",
	}[e.Kind]
	if kind == "" {
		kind = e.Kind
	}
	s := kind
	if e.Detail != "" {
		s += "（" + label(e.Detail) + "）"
	}
	if loc := location(e.Path, e.Line); loc != "" {
		s += " " + loc
	}
	return s
}

// values は、名前の一覧を判定つきの行にする。
func (b *builder) values(parameter string, names []string) (rows []valueRow, reasons []string) {
	scheme := valueScheme[parameter]
	seen := map[string]bool{}
	for _, n := range names {
		row := valueRow{Name: n}
		if scheme != "" {
			var vd model.Verdict
			var ok bool
			if scheme == "tls-suite" {
				vd, ok = b.ev.Suite(n)
				if s, found := b.rs.SuiteAttributes(n); found {
					row.Kx, row.Au, row.Enc = s.Kx, s.Au, s.Enc
				}
			} else {
				vd, ok = b.ev.Name(scheme, n)
			}
			if ok || scheme != "tls-protocol" { // プロトコルの欄には版の名前でない語（all など）も入るので、当たらないものは判定を出さない
				row.HasVerdict = true
				row.Quantum, row.Classical = quantumBadge[vd.Quantum], classicalBadge[vd.Classical]
				if scheme == "tls-protocol" {
					row.Quantum = badge{}
				}
				for _, id := range vd.Rules {
					b.used[id] = true
					if !seen[id] {
						seen[id] = true
						reasons = append(reasons, id)
					}
					if r, found := b.policyRule(id); found && r.Quantum == "vulnerable" {
						if r.Role == "key-establishment" {
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

func (b *builder) policyRule(id string) (ruleset.PolicyRule, bool) {
	for _, r := range b.ev.Policy().Rules {
		if r.ID == id {
			return r, true
		}
	}
	return ruleset.PolicyRule{}, false
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

func (b *builder) step(s model.ResolutionStep) string {
	src := ""
	if s.Source != nil {
		src = "（" + s.Source.Package + " " + s.Source.Version + " で実測）"
	}
	at := ""
	if set, ok := b.settings[s.Setting]; ok {
		at = "（" + location(set.Location.Path, set.Location.Line) + "）"
	}
	level := map[string]string{"app-config": "設定の記載による", "app-default": "アプリの既定による", "os-policy": "システムの設定による", "library": "暗号ライブラリの既定による"}[s.Layer]
	switch s.Op {
	case "override":
		if s.Layer == "os-policy" {
			return "システムの設定の値" + at
		}
		return "設定の記載" + at
	case "default":
		if s.Layer == "library" {
			return "暗号ライブラリの既定" + src
		}
		return "アプリの既定値" + src
	case "append":
		return "既定の一覧に追加" + at
	case "remove":
		return "既定の一覧から削除" + at
	case "prepend":
		return "既定の一覧の先頭に追加" + at
	case "profile":
		return "システムの暗号ポリシーの内容に置き換え"
	case "expand":
		return "暗号ライブラリでの展開" + src
	case "security-level":
		return "セキュリティレベルで絞り込み（" + level + "）"
	case "filter-certificates":
		return "証明書の種類で絞り込み"
	case "filter-dh-parameters":
		return "DH パラメータの有無で絞り込み（" + level + "）" + src
	}
	return s.Layer + " / " + s.Op
}

// tally は、値の一覧を要点の数に数える。
func tally(rows []valueRow) summaryView {
	var t summaryView
	for _, r := range rows {
		if r.VulnKex || r.VulnSig || r.Quantum.Class == "bad" {
			t.Quantum++
		}
		if r.VulnKex {
			t.Kex++
		}
		if r.VulnSig {
			t.Sig++
		}
		if r.Quantum.Label == quantumBadge["reduced"].Label {
			t.Reduced++
		}
		if r.Quantum.Label == quantumBadge["hybrid"].Label {
			t.Hybrid++
		}
		switch r.Classical.Class {
		case "bad":
			t.Weak++
		case "warn":
			t.Legacy++
		}
		if r.HasVerdict && (r.Quantum.Class == "unk" || r.Classical.Class == "unk") {
			t.Unknown++
		}
	}
	return t
}

func countText(rows []valueRow) string {
	t := tally(rows)
	parts := []string{strconv.Itoa(len(rows)) + " 個"}
	add := func(n int, s string) {
		if n > 0 {
			parts = append(parts, s+" "+strconv.Itoa(n))
		}
	}
	add(t.Quantum, "量子計算機に弱い")
	add(t.Reduced, "量子計算機で強度が下がる")
	add(t.Hybrid, "ハイブリッド")
	add(t.Weak, "危殆化")
	add(t.Legacy, "非推奨")
	add(t.Unknown, "判定できない")
	return strings.Join(parts, "、")
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
			Active: s.Activity.Level == "running" || s.Activity.Level == "enabled"}
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
				sv.Component += "、パッケージ " + c.Package.Name + " " + c.Package.Version
				if c.Package.Release != "" {
					sv.Component += "-" + c.Package.Release
				}
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
			ef := effectiveView{Label: label(e.Parameter), Parameter: e.Parameter, Resolved: e.Status == "resolved", Reason: e.Reason, Notes: e.Notes,
				IsSuite: valueScheme[e.Parameter] == "tls-suite"}
			switch e.Confidence {
			case "high":
				ef.Confidence = "確度: 高"
			case "medium":
				ef.Confidence = "確度: 中"
			}
			for _, st := range e.Steps {
				ef.Steps = append(ef.Steps, b.step(st))
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
			if set.Parameter == "tls.protocols" {
				rows, _ := b.values(set.Parameter, set.Values)
				for _, r := range rows {
					if r.HasVerdict {
						st.Badges = append(st.Badges, r)
						if r.Classical.Class == "bad" {
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

func shortAlg(id string) string { return strings.TrimPrefix(id, "alg:") }

func (b *builder) verdict(assetID string) (badge, badge) {
	vd, ok := b.a.Assets[assetID]
	if !ok {
		return badge{}, badge{}
	}
	for _, id := range vd.Rules {
		b.used[id] = true
	}
	return quantumBadge[vd.Quantum], classicalBadge[vd.Classical]
}

func (b *builder) assetRow(o model.Occurrence) (assetRow, bool) {
	as, ok := b.assets[o.Asset]
	if !ok {
		return assetRow{}, false
	}
	row := assetRow{Path: o.Location.Path}
	if o.Location.Container != "" {
		row.Path += "（" + o.Location.Container + " の中）"
	}
	if o.Activity != nil {
		row.Activity = activityLabel[o.Activity.Level]
		for _, e := range o.Activity.Evidence {
			row.Evidence = append(row.Evidence, evidenceText(e))
		}
	}
	switch {
	case as.Type == "certificate" && as.Certificate != nil:
		c := as.Certificate
		row.Kind, row.Name = "証明書", c.Subject
		if c.IsCA {
			row.Kind = "CA 証明書"
		}
		row.Algorithm = "鍵 " + shortAlg(c.PublicKey.Algorithm) + "、署名 " + shortAlg(c.SignatureAlgorithm)
		row.Expiry = c.NotAfter
		if t, err := time.Parse(time.RFC3339, c.NotAfter); err == nil && !b.scanTime.IsZero() {
			switch {
			case t.Before(b.scanTime):
				row.ExpiryTag = badge{"期限切れ", "bad", "スキャンした時点で、有効期限を過ぎていた証明書"}
			case t.Before(b.scanTime.AddDate(0, 0, expiringDays)):
				row.ExpiryTag = badge{strconv.Itoa(expiringDays) + " 日以内に期限", "warn", "スキャンした時点から数えて、まもなく有効期限が来る証明書"}
			}
		}
	case (as.Type == "private-key" || as.Type == "public-key") && as.Key != nil:
		row.Kind = map[string]string{"private-key": "秘密鍵", "public-key": "公開鍵"}[as.Type]
		row.Name = shortAlg(as.Key.Algorithm)
		if row.Name == "" {
			row.Name = "（アルゴリズムを確認できない）"
		}
		if o.Detail != nil && o.Detail.Encrypted != nil && *o.Detail.Encrypted {
			row.Name += "（暗号化されている）"
		}
	case as.Type == "csr" && as.CSR != nil:
		row.Kind, row.Name = "証明書署名要求", as.CSR.Subject
		row.Algorithm = "鍵 " + shortAlg(as.CSR.PublicKey.Algorithm) + "、署名 " + shortAlg(as.CSR.SignatureAlgorithm)
	case as.Type == "keystore" && as.Keystore != nil:
		row.Kind, row.Name = "キーストア", as.Keystore.Format
		if as.Keystore.Unreadable {
			row.Name += "（暗号化されていて、中身の一部を確認できない）"
		}
	default:
		return assetRow{}, false
	}
	row.Quantum, row.Classical = b.verdict(as.ID)
	return row, true
}

func (b *builder) files(v *view) {
	stores := map[string]map[string]*storeGroup{}
	counts := map[string]int{}
	for _, o := range b.inv.Occurrences {
		row, ok := b.assetRow(o)
		if !ok {
			continue
		}
		as := b.assets[o.Asset]
		if o.Store != "" {
			// 証明書ストアの中身は、署名の方式ごとにまとめる
			sig := "（証明書以外）"
			if as.Certificate != nil {
				sig = shortAlg(as.Certificate.SignatureAlgorithm)
			}
			if stores[o.Store] == nil {
				stores[o.Store] = map[string]*storeGroup{}
			}
			g := stores[o.Store][sig]
			if g == nil {
				g = &storeGroup{Signature: sig}
				if as.Certificate != nil {
					if vd, ok := b.a.Assets[as.Certificate.SignatureAlgorithm]; ok {
						g.Quantum, g.Classical = quantumBadge[vd.Quantum], classicalBadge[vd.Classical]
						for _, id := range vd.Rules {
							b.used[id] = true
						}
					}
				}
				stores[o.Store][sig] = g
			}
			g.Count++
			g.Rows = append(g.Rows, row)
			counts[o.Store]++
			continue
		}
		level := ""
		if o.Activity != nil {
			level = o.Activity.Level
		}
		if as.Type == "private-key" && (level == "" || level == "unknown" || level == "installed") {
			v.Unconfirmed = append(v.Unconfirmed, row)
			v.Summary.Unconfirmed++
		}
		v.Files = append(v.Files, row)
		if row.Quantum.Class == "bad" {
			v.Summary.FileQuantum++
		}
		switch row.Classical.Class {
		case "bad":
			v.Summary.FileWeak++
		case "warn":
			v.Summary.FileLegacy++
		}
		switch row.ExpiryTag.Class {
		case "bad":
			v.Summary.Expired++
		case "warn":
			v.Summary.Expiring++
		}
	}
	byPath := func(rows []assetRow) {
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].Path != rows[j].Path {
				return rows[i].Path < rows[j].Path
			}
			return rows[i].Name < rows[j].Name
		})
	}
	byPath(v.Files)
	byPath(v.Unconfirmed)
	var names []string
	for name := range stores {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		sv := storeView{Name: name, Count: counts[name]}
		for _, g := range stores[name] {
			sort.SliceStable(g.Rows, func(i, j int) bool { return g.Rows[i].Name < g.Rows[j].Name })
			sv.Groups = append(sv.Groups, *g)
		}
		sort.SliceStable(sv.Groups, func(i, j int) bool {
			if sv.Groups[i].Count != sv.Groups[j].Count {
				return sv.Groups[i].Count > sv.Groups[j].Count
			}
			return sv.Groups[i].Signature < sv.Groups[j].Signature
		})
		v.Stores = append(v.Stores, sv)
	}
}

func (b *builder) misc(v *view) {
	for _, s := range b.inv.OSSettings {
		v.OSSettings = append(v.OSSettings, kv{s.ID, s.Value, location(s.Path, s.Line)})
	}
	for _, p := range b.inv.Packages {
		ver := p.Version
		if p.Release != "" {
			ver += "-" + p.Release
		}
		v.Packages = append(v.Packages, kv{p.Name, ver, p.Manager})
	}
	for _, c := range b.inv.Components {
		val := c.Path
		if c.Version != nil {
			val += "（版 " + c.Version.Value + "）"
		}
		var links []string
		for _, l := range c.Links {
			if l.Path != "" {
				links = append(links, l.SOName+" → "+l.Path)
			}
		}
		v.Components = append(v.Components, kv{c.Name, val, strings.Join(links, "、")})
	}
	for _, s := range b.inv.Skipped {
		name := skipLabel[s.Reason]
		if name == "" {
			name = s.Reason
		}
		v.Skipped = append(v.Skipped, kv{s.Path, name, s.Detail})
	}
	var reasons []string
	for r := range b.inv.Coverage.SkippedByReason {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	for _, r := range reasons {
		n := b.inv.Coverage.SkippedByReason[r]
		name := skipLabel[r]
		if name == "" {
			name = r
		}
		v.SkippedBy = append(v.SkippedBy, kv{name, strconv.Itoa(n), r})
		switch r {
		case "permission-denied":
			v.Summary.Permission += n
		case "excluded":
		default:
			v.Summary.OtherSkips += n
		}
	}
	v.Summary.Files, v.Summary.Dirs = b.inv.Coverage.FilesExamined, b.inv.Coverage.DirsExamined
	v.SkippedCut = b.inv.Coverage.SkippedTruncated
}
