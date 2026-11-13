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
	if strings.Join(titles, " | ") != "サービスの設定 | ファイルとして見つかった証明書・鍵 | 証明書ストア | 探索した範囲" {
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
