package report

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"kagiya/internal/model"
)

// 利用者の指摘（2026-11-13、2 回目）を受けた、画面の構成。

func section(t *testing.T, html, id, nextID string) string {
	t.Helper()
	a := strings.Index(html, `id="`+id+`"`)
	b := strings.Index(html, `id="`+nextID+`"`)
	if a < 0 || b < a {
		t.Fatalf("no section %s (before %s)", id, nextID)
	}
	return html[a:b]
}

// 要点は 4 つの枠: サービスの設定、ファイルとして見つかった証明書・鍵、証明書ストア、探索した範囲。
func TestReportSummaryHasStoreCard(t *testing.T) {
	html := render(t, sample())
	sum := section(t, html, "h1-summary", "h1-services")
	var titles []string
	for _, m := range regexp.MustCompile(`<div class="card">\s*<h3>([^<（]*)`).FindAllStringSubmatch(sum, -1) {
		titles = append(titles, strings.TrimSpace(m[1]))
	}
	if strings.Join(titles, " | ") != "ソフトウェアが用いる暗号の状況 | ファイルとして見つかった証明書・鍵 | 証明書ストア | 探索した範囲" {
		t.Errorf("cards = %v", titles)
	}
	if strings.Contains(html, "証明書ストアを除く") {
		t.Error("the old card title remains")
	}
	// 証明書ストアの枠: 見つかったストアごとの件数（ストアをまたいで足さない）と、期限の状態
	card := regexp.MustCompile(`(?s)<h3>証明書ストア</h3>(.*?)</div>\s*<div class="card">`).FindStringSubmatch(sum)
	if card == nil {
		t.Fatal("no store card")
	}
	if !regexp.MustCompile(`system-trust</span>\s*<span class="num[^"]*">3<`).MatchString(card[1]) || !strings.Contains(card[1], "期限切れの証明書") {
		t.Errorf("store card = %s", card[1])
	}
	// 4 つの枠が横に並ぶ幅にする
	if !regexp.MustCompile(`\.cards \{[^}]*minmax\(2[0-9]{2}px`).MatchString(html) {
		t.Error("the cards must fit four in a row")
	}
}

// 「ファイルとして見つかった証明書・鍵」と「証明書ストア」は、別の項目にする。
// 設定からの参照を確認できなかった秘密鍵の一覧は置かない（注意書きは、共通の「分からないこと」に残す）。
func TestReportFilesAndStoresAreSeparate(t *testing.T) {
	html := render(t, sample())
	files := section(t, html, "h1-files", "h1-stores")
	stores := section(t, html, "h1-stores", "h1-system")
	if !strings.Contains(files, ">ファイルとして見つかった証明書・鍵（") || strings.Contains(files, "system-trust") || strings.Contains(files, "<details") {
		t.Errorf("files section = %.300s", files)
	}
	if !strings.Contains(stores, ">証明書ストア</h2>") || !strings.Contains(stores, "system-trust") || !strings.Contains(stores, "Root CA Two") {
		t.Errorf("stores section = %.300s", stores)
	}
	for _, gone := range []string{"<h3>設定からの参照を確認できなかった秘密鍵", "<h2 id=\"h1-files\">証明書と鍵</h2>", "ファイルとして見つかったもの（"} {
		if strings.Contains(html, gone) {
			t.Errorf("the report still contains %q", gone)
		}
	}
	// 参照の見つからない鍵についての注意は、共通の項目に残す
	limits := regexp.MustCompile(`(?s)<section class="common" id="limits">(.*?)</section>`).FindStringSubmatch(html)
	if limits == nil || !strings.Contains(limits[1], "使われていないことを意味しません") || !strings.Contains(limits[1], "削除しないでください") {
		t.Error("the caution about keys without a found reference must remain in the common section")
	}
	// 左の欄
	side := regexp.MustCompile(`(?s)<nav class="side">(.*?)</nav>`).FindStringSubmatch(html)[1]
	for _, want := range []string{`href="#h1-files">ファイルとして見つかった証明書・鍵<`, `href="#h1-stores">証明書ストア<`, `href="#h1-coverage">読み飛ばしたもの<`} {
		if !strings.Contains(side, want) {
			t.Errorf("the side pane has no %s", want)
		}
	}
}

// 「読み飛ばしたもの」: 探索した範囲は要点にあるので、ここでは読めなかったもの・読み飛ばしたものだけを示す。
func TestReportSkippedSection(t *testing.T) {
	html := render(t, sample())
	sec := section(t, html, "h1-coverage", "limits")
	mustContain(t, sec, ">読み飛ばしたもの</h2>", "権限がなく読めなかった", "/etc/ssl/private", "/mnt/share", "ネットワーク越しのファイルシステム", "nfs4")
	for _, gone := range []string{"探索の起点:", "この起点の外は調べていません", "探索した範囲と、読み飛ばしたもの"} {
		if strings.Contains(html, gone) {
			t.Errorf("the report still contains %q", gone)
		}
	}
}

// 全体の集計の説明の文は置かない。全体の集計の要点にも、証明書ストアの枠がある。
func TestReportDashboardTexts(t *testing.T) {
	a, b := sample(), sample()
	b.Meta.Host.Hostname = "db01.example.jp"
	var buf bytes.Buffer
	if err := RenderAll(&buf, []*model.Inventory{a, b}, rules(t), "default"); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	if strings.Contains(html, "ホストごとのスキャン結果を足し合わせたものです") {
		t.Error("the dashboard description remains")
	}
	dash := regexp.MustCompile(`(?s)<section class="dashboard" id="dashboard">(.*?)</section>`).FindStringSubmatch(html)
	if dash == nil || !regexp.MustCompile(`system-trust</span>\s*<span class="num[^"]*">6<`).MatchString(dash[1]) {
		t.Error("the dashboard must total the store counts over the hosts")
	}
}

// サービスの欄を開いたとき、中身の左右に余白を取る（中身の側の余白の指定に打ち消されない書き方にする）。
func TestReportServiceBodyHasSideMargins(t *testing.T) {
	html := render(t, sample())
	m := regexp.MustCompile(`details\.svc > \*:not\(summary\) \{([^}]*)\}`).FindStringSubmatch(html)
	if m == nil || !regexp.MustCompile(`margin-left: (1[6-9]|2[0-9])px`).MatchString(m[1]) || !regexp.MustCompile(`margin-right: (1[6-9]|2[0-9])px`).MatchString(m[1]) {
		t.Errorf("no side margins for the body of a service: %v", m)
	}
	// 範囲のブロックの指定（左右 0）より後ろに置く
	if strings.Index(html, "details.svc > *:not(summary)") < strings.Index(html, ".scope {") {
		t.Error("the rule must come after the scope block rule")
	}
}

// 証明書ストアの欄を開いたときも、中身の左右に余白を取る。
func TestReportStoreBodyHasSideMargins(t *testing.T) {
	html := render(t, sample())
	m := regexp.MustCompile(`details\.store > \*:not\(summary\) \{([^}]*)\}`).FindStringSubmatch(html)
	if m == nil || !regexp.MustCompile(`margin-left: (1[6-9]|2[0-9])px`).MatchString(m[1]) || !regexp.MustCompile(`margin-right: (1[6-9]|2[0-9])px`).MatchString(m[1]) {
		t.Errorf("no side margins for the body of a store: %v", m)
	}
	if !regexp.MustCompile(`(?s)<details class="store">\s*<summary>[^<]*system-trust`).MatchString(html) {
		t.Error("the store section must carry the class the rule applies to")
	}
}

// 要点の見出しが長くても、数の部分（「（計 3 ソフト）」）は途中で折り返さない。
func TestReportCardTitleCountDoesNotBreak(t *testing.T) {
	html := render(t, sample())
	if !regexp.MustCompile(`\.nowrap \{[^}]*white-space: nowrap`).MatchString(html) {
		t.Error("no rule that keeps the count on one line")
	}
	if strings.Contains(html, "サービスの設定（") {
		t.Error("the old card title remains")
	}
}

// 見出しと説明の文言（2026-11-14、利用者の指定）: 節の名前は「各ソフトでの暗号利用状況」。証明書ストアの説明に、畳んでいる理由は書かない。
func TestReportSoftwareWording(t *testing.T) {
	html := render(t, sample())
	for _, want := range []string{">各ソフトでの暗号利用状況</h2>", ">各ソフトでの暗号利用状況</a>"} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, bad := range []string{"サービスの設定</h2>", "サービスの設定</a>", "サーバアプリで用いる暗号の状況", "件数が多いので畳んでいます", "見つかったサービスです", "名前を選ぶと開きます"} {
		if strings.Contains(html, bad) {
			t.Errorf("old wording remains: %q", bad)
		}
	}
}

// 情報量を落とす（2026-11-14、利用者の指定）: 範囲ごとの値の下に、求め方の手順と、値ごとの注意書きは出さない。
// 「設定の記載と既定値から算出」という説明も出さない（確度は出す）。これらは結果の JSON には残る。
func TestReportEffectiveValuesAreTerse(t *testing.T) {
	html := render(t, sample())
	for _, bad := range []string{"求め方", "設定の記載と既定値から算出", "the cipher table measured on openssl-libs 3.5.9-1.el9_9", "暗号ライブラリでの展開"} {
		if strings.Contains(html, bad) {
			t.Errorf("must not be shown: %q", bad)
		}
	}
	// 確度と、求められなかった理由、サービス全体についての注意は残す
	for _, want := range []string{"確度: 中", "no default values are recorded for openssh-server 9.9p1-99.el9", "ssl_module is not loaded by the configuration"} {
		if !strings.Contains(html, want) {
			t.Errorf("must still be shown: %q", want)
		}
	}
	// 証明書ストアの説明は短くする
	if !strings.Contains(html, "署名の方式ごとの件数と、その方式の判定です。</p>") || strings.Contains(html, "同じ行の証明書すべてに当てはまります") {
		t.Error("the description of certificate stores must be the short one")
	}
}

// 暗号ライブラリが、耐量子のアルゴリズムに対応している版かどうかを、ソフトの一覧に短く出す。
func TestReportLibraryPQCSupport(t *testing.T) {
	inv := sample()
	inv.Components = append(inv.Components,
		model.Component{ID: "lib:bouncycastle:/opt/app/app.jar!/BOOT-INF/lib/bcprov-jdk18on-1.78.1.jar", Kind: "library", Name: "bouncycastle",
			Path: "/opt/app/app.jar!/BOOT-INF/lib/bcprov-jdk18on-1.78.1.jar", Version: &model.ComponentVersion{Value: "1.78.1", Source: "file-name"},
			PQC: &model.ComponentPQC{NotSupported: []string{"ML-KEM", "ML-DSA", "SLH-DSA"}, Basis: "measured"}},
		model.Component{ID: "lib:bouncycastle:/opt/b/bctls-jdk18on-1.80.jar", Kind: "library", Name: "bouncycastle",
			Path: "/opt/b/bctls-jdk18on-1.80.jar", Version: &model.ComponentVersion{Value: "1.80", Source: "file-name"},
			PQC: &model.ComponentPQC{Supported: []string{"TLS-MLKEM"}, NotSupported: []string{"TLS-MLKEM-hybrid"}, Basis: "measured"}},
		model.Component{ID: "lib:bouncycastle:/opt/c/bcprov-jdk18on-1.90.jar", Kind: "library", Name: "bouncycastle",
			Path: "/opt/c/bcprov-jdk18on-1.90.jar", Version: &model.ComponentVersion{Value: "1.90", Source: "file-name"},
			PQC: &model.ComponentPQC{Supported: []string{"ML-KEM", "ML-DSA", "SLH-DSA"}, Basis: "extrapolated"}},
		model.Component{ID: "lib:bouncycastle:/opt/d/bc-fips-2.2.0.jar", Kind: "library", Name: "bouncycastle",
			Path: "/opt/d/bc-fips-2.2.0.jar", Version: &model.ComponentVersion{Value: "2.2.0", Source: "file-name"},
			PQC: &model.ComponentPQC{Unknown: []string{"ML-KEM", "ML-DSA", "SLH-DSA"}, Basis: "measured"}})
	html := render(t, inv)
	for _, want := range []string{
		"耐量子: 未対応（ML-KEM・ML-DSA・SLH-DSA）",
		"耐量子: ML-KEM 単独の鍵交換（TLS）に対応、ハイブリッドの鍵交換（TLS）は未対応",
		"耐量子: ML-KEM・ML-DSA・SLH-DSA に対応（版からの推定）",
		"耐量子: 不明（ML-KEM・ML-DSA・SLH-DSA）",
		"ライブラリがその方式を持っているかどうか",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %q", want)
		}
	}
}
