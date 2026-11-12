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
}

var quantumBadge = map[string]badge{
	"vulnerable":   {"量子計算機に弱い", "bad"},
	"hybrid":       {"ハイブリッド", "good"},
	"resistant":    {"耐量子", "good"},
	"reduced":      {"量子計算機で強度が下がる", "warn"},
	"not-targeted": {"対象外", "none"},
	"unknown":      {"判定できない", "unk"},
}

var classicalBadge = map[string]badge{
	"weak":    {"危殆化", "bad"},
	"legacy":  {"非推奨", "warn"},
	"ok":      {"該当なし", "none"},
	"unknown": {"判定できない", "unk"},
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
	Name         string
	Kx, Au, Enc  string // 暗号スイートの場合だけ
	Quantum      badge
	Classical    badge
	HasVerdict   bool
	KeyEstablish bool // 鍵共有が量子計算機に弱い
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
	Name      string
	Activity  string
	Evidence  []string
	Component string
	Configs   []string
	Notes     []string
	Scopes    []scopeView
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

type summaryView struct {
	ActiveServices   int
	KeyEstablishment int // 有効なサービスが許可している、鍵共有が量子計算機に弱い方式の数
	QuantumOther     int
	Hybrid           int
	Weak             int
	Legacy           int
	Unknown          int
	Unresolved       int
	FileQuantum      int
	FileWeak         int
	FileLegacy       int
	Expired          int
	Expiring         int
	Unreferenced     int
	Skipped          int
}

type view struct {
	Host, OSArch, Started, Finished string
	ToolVersion, RulesVersion       string
	RulesSource                     string
	Labels                          []string
	Incomplete                      bool
	IncompleteReason                string
	Elevated                        bool
	Warnings                        []string
	PolicyTitle, PolicyVersion      string
	ExpiringDays                    int

	Summary      summaryView
	Active       []serviceView
	Inactive     []serviceView
	Unreferenced []assetRow
	Files        []assetRow
	Stores       []storeView
	OSSettings   []kv
	Packages     []kv
	Components   []kv
	Skipped      []kv
	SkippedBy    []kv
	SkippedCut   bool
	Coverage     model.Coverage
	Rules        []ruleView
	Refs         []refView
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

// Render は、1ホスト分の結果からレポートを書き出す。
func Render(w io.Writer, inv *model.Inventory, rs *ruleset.RuleSet, policy string) error {
	ev, err := assess.New(rs, policy)
	if err != nil {
		return err
	}
	b := &builder{inv: inv, ev: ev, a: ev.Assess(inv), rs: rs, settings: map[string]model.Setting{}, assets: map[string]model.Asset{}, used: map[string]bool{}}
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
	return tmpl.Execute(w, b.build())
}

func (b *builder) build() *view {
	m := b.inv.Meta
	p := b.ev.Policy()
	v := &view{Host: m.Host.Hostname, OSArch: m.Host.OS + " / " + m.Host.Arch, Started: m.StartedAt, Finished: m.FinishedAt,
		ToolVersion: m.Tool.Version, RulesVersion: m.Rules.Version, RulesSource: m.Rules.Source,
		Incomplete: !m.Completed, IncompleteReason: m.Incomplete, Elevated: m.Privilege.Elevated, Warnings: m.Warnings,
		PolicyTitle: p.Title, PolicyVersion: p.Version, ExpiringDays: expiringDays, Coverage: b.inv.Coverage}
	for k, val := range m.Labels {
		v.Labels = append(v.Labels, k+"="+val)
	}
	sort.Strings(v.Labels)

	b.services(v)
	b.files(v)
	b.misc(v)

	// 判定の理由として挙げた規則と、出典
	titles := map[string]string{}
	for _, r := range p.References {
		titles[r.ID] = r.Title
		v.Refs = append(v.Refs, refView{ID: r.ID, Title: r.Title, URL: r.URL, Note: r.Note})
	}
	for _, r := range p.Rules {
		if b.used[r.ID] {
			v.Rules = append(v.Rules, b.rule(r, titles))
		}
	}
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
					if r, found := b.policyRule(id); found && r.Role == "key-establishment" && r.Quantum == "vulnerable" {
						row.KeyEstablish = true
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

func countText(rows []valueRow) string {
	var ke, q, hy, weak, legacy, unk int
	for _, r := range rows {
		switch {
		case r.KeyEstablish:
			ke++
		case r.Quantum.Class == "bad":
			q++
		}
		if r.Quantum.Label == "ハイブリッド" {
			hy++
		}
		switch r.Classical.Class {
		case "bad":
			weak++
		case "warn":
			legacy++
		}
		if r.HasVerdict && (r.Quantum.Class == "unk" || r.Classical.Class == "unk") {
			unk++
		}
	}
	parts := []string{strconv.Itoa(len(rows)) + " 個"}
	add := func(n int, s string) {
		if n > 0 {
			parts = append(parts, s+" "+strconv.Itoa(n))
		}
	}
	add(ke, "鍵共有が量子計算機に弱い")
	add(q, "量子計算機に弱い")
	add(hy, "ハイブリッド")
	add(weak, "危殆化")
	add(legacy, "非推奨")
	add(unk, "判定できない")
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
		sv := serviceView{Name: s.App, Activity: activityLabel[s.Activity.Level], Configs: s.ConfigFiles, Notes: s.Notes}
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
		active := s.Activity.Level == "running" || s.Activity.Level == "enabled"

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
				if active {
					for _, r := range ef.Rows {
						switch {
						case r.KeyEstablish:
							v.Summary.KeyEstablishment++
						case r.Quantum.Class == "bad":
							v.Summary.QuantumOther++
						}
						if r.Quantum.Label == "ハイブリッド" {
							v.Summary.Hybrid++
						}
						switch r.Classical.Class {
						case "bad":
							v.Summary.Weak++
						case "warn":
							v.Summary.Legacy++
						}
						if r.HasVerdict && (r.Quantum.Class == "unk" || r.Classical.Class == "unk") {
							v.Summary.Unknown++
						}
					}
				}
			} else if active {
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
						if active && r.Classical.Class == "bad" {
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
		if active {
			v.Summary.ActiveServices++
			v.Active = append(v.Active, sv)
		} else {
			v.Inactive = append(v.Inactive, sv)
		}
	}
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
				row.ExpiryTag = badge{"期限切れ", "bad"}
			case t.Before(b.scanTime.AddDate(0, 0, expiringDays)):
				row.ExpiryTag = badge{strconv.Itoa(expiringDays) + " 日以内に期限", "warn"}
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
			v.Unreferenced = append(v.Unreferenced, row)
			v.Summary.Unreferenced++
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
	byPath(v.Unreferenced)
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
		v.Skipped = append(v.Skipped, kv{s.Path, s.Reason, s.Detail})
	}
	var reasons []string
	for r := range b.inv.Coverage.SkippedByReason {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	for _, r := range reasons {
		n := b.inv.Coverage.SkippedByReason[r]
		v.SkippedBy = append(v.SkippedBy, kv{r, strconv.Itoa(n), ""})
		v.Summary.Skipped += n
	}
	v.SkippedCut = b.inv.Coverage.SkippedTruncated
}
