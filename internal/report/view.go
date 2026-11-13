// このファイルは、表示用のデータの型（render.go が HTML として書き出す）と、要点の数え方。

package report

import (
	"strconv"
	"strings"

	"kagiya/internal/model"
)

type badge struct {
	Label string
	Class string
	Tip   string // マウスを載せると出る説明
}

type valueRow struct {
	Name        string
	Kx, Au, Enc string // 暗号スイートの場合だけ
	Quantum     badge
	Classical   badge
	Verdict     model.Verdict // 評価の値（数えるときは、表示名ではなくこちらを見る）
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
	Kind        string
	Name        string
	Algorithm   string
	Expiry      string
	ExpiryTag   badge
	Path        string
	Activity    string
	Evidence    []string
	Quantum     badge
	Classical   badge
	Verdict     model.Verdict // 評価の値（数えるときは、表示名ではなくこちらを見る）
	ExpiryState string        // expired | expiring | 空（スキャンした時点を基準にした期限の状態）
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
	RootList                                      []string // 探索の起点（要点の「探索した範囲」に並べる）
	CBOM                                          []byte   // このホストの CBOM（CycloneDX の JSON）。埋め込まない場合は空
	CBOMName                                      string   // 保存するときのファイル名

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

// tally は、値の一覧を要点の数に数える。
func tally(rows []valueRow) summaryView {
	var t summaryView
	for _, r := range rows {
		if !r.HasVerdict {
			continue
		}
		if r.VulnKex || r.VulnSig || r.Verdict.Quantum == model.QuantumVulnerable {
			t.Quantum++
		}
		if r.VulnKex {
			t.Kex++
		}
		if r.VulnSig {
			t.Sig++
		}
		switch r.Verdict.Quantum {
		case model.QuantumReduced:
			t.Reduced++
		case model.QuantumHybrid:
			t.Hybrid++
		}
		switch r.Verdict.Classical {
		case model.ClassicalWeak:
			t.Weak++
		case model.ClassicalLegacy:
			t.Legacy++
		}
		if r.Verdict.Quantum == model.QuantumUnknown || r.Verdict.Classical == model.ClassicalUnknown {
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
