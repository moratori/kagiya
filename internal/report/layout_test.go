package report

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"kagiya/internal/model"
)

// 利用者の指摘（2026-11-13）を受けた、画面の構成。

// 名前は「クリプトインベントリ」。説明の文と、ページ上部の移動用の並びは置かない。
func TestReportTitleAndRemovedTexts(t *testing.T) {
	html := render(t, sample())
	mustContain(t, html, "<title>クリプトインベントリ web01.example.jp</title>", `<div class="brand">クリプトインベントリ`)
	for _, gone := range []string{
		"暗号の棚卸しレポート",
		"1 ホスト分のスキャン結果",
		`<nav class="local">`,
		"受け入れる方式を特定できなかった項目",
		"見つかったサービスすべてについて",
		"期限は、スキャンした時点を基準に判定しています",
		"調べるのは、決まった起点の下だけです",
	} {
		if strings.Contains(html, gone) {
			t.Errorf("the report still contains %q", gone)
		}
	}
}

// 要点の「探索した範囲」の直下に、探索の起点を並べる。
func TestReportRootsInSummaryCard(t *testing.T) {
	html := render(t, sample())
	m := regexp.MustCompile(`(?s)<h3>探索した範囲</h3>(.*?)</div>\s*</div>`).FindStringSubmatch(html)
	if m == nil {
		t.Fatal("no coverage card")
	}
	for _, root := range []string{"/etc", "/opt", "/usr/local"} {
		if !strings.Contains(m[1], `<li class="mono">`+root+`</li>`) {
			t.Errorf("the coverage card does not list %s: %s", root, m[1])
		}
	}
	if strings.Index(m[1], "/etc") > strings.Index(m[1], "調べたファイル") {
		t.Error("the roots must come right under the heading")
	}
}

// 「このレポートでは分からないこと」と「判定の基準と出典」は、左の欄の「共通」から開く独立した表示にする。
// ホストの表示や、全体の集計の表示の中には置かない（1 回だけ出す）。
func TestReportCommonViews(t *testing.T) {
	a, b := sample(), sample()
	b.Meta.Host.Hostname = "db01.example.jp"
	for name, invs := range map[string][]*model.Inventory{"single": {sample()}, "multi": {a, b}} {
		var buf bytes.Buffer
		if err := RenderAll(&buf, invs, rules(t), "default"); err != nil {
			t.Fatal(err)
		}
		html := buf.String()
		for _, heading := range []string{"このレポートでは分からないこと", "判定の基準と出典"} {
			if n := strings.Count(html, "<h2>"+heading+"</h2>"); n != 1 {
				t.Errorf("%s: %q appears %d times as a heading, want 1", name, heading, n)
			}
		}
		for _, id := range []string{"limits", "criteria"} {
			if !regexp.MustCompile(`<section class="common" id="` + id + `">`).MatchString(html) {
				t.Errorf("%s: no common view %q", name, id)
			}
		}
		side := regexp.MustCompile(`(?s)<nav class="side">(.*?)</nav>`).FindStringSubmatch(html)[1]
		tail := side[strings.Index(side, "共通"):]
		if !strings.Contains(tail, `href="#limits"`) || !strings.Contains(tail, `href="#criteria"`) {
			t.Errorf("%s: the common links are missing: %s", name, tail)
		}
		// ホストの表示（と全体の集計）の中には入れない
		for _, m := range regexp.MustCompile(`(?s)<section class="(?:view|dashboard)".*?</section>`).FindAllString(html, -1) {
			if strings.Contains(m, "実際にネゴシエーションされている暗号") || strings.Contains(m, "NIST IR 8547, Transition") {
				t.Errorf("%s: a host or dashboard view contains the common content", name)
			}
		}
		// 共通の表示は、選ばれたときだけ出す（スタイルシートで切り替える）
		if !strings.Contains(html, ".common:target") {
			t.Errorf("%s: the common views must be switched by the style sheet", name)
		}
	}
}

// 名前の右に、CBOM（CycloneDX）を保存するためのリンクを置く。中身はレポートを作るときに作って埋め込む（スクリプトは使わない）。
func TestReportEmbedsCBOM(t *testing.T) {
	html := render(t, sample())
	m := regexp.MustCompile(`(?s)<div class="brand">クリプトインベントリ\s*<a class="dl"[^>]*download="([^"]+)"[^>]*href="data:application/vnd\.cyclonedx\+json;base64,([A-Za-z0-9+/=]+)"`).FindStringSubmatch(html)
	if m == nil {
		t.Fatal("no CBOM download link next to the name")
	}
	if m[1] != "kagiya-web01.example.jp.cdx.json" {
		t.Errorf("file name = %q", m[1])
	}
	raw, err := base64.StdEncoding.DecodeString(m[2])
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		BomFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Metadata    struct {
			Component struct{ Name string } `json:"component"`
		} `json:"metadata"`
		Components []json.RawMessage `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.BomFormat != "CycloneDX" || doc.SpecVersion != "1.6" || doc.Metadata.Component.Name != "web01.example.jp" || len(doc.Components) == 0 {
		t.Errorf("embedded CBOM = %+v (%v)", doc, err)
	}
	if strings.Contains(strings.ToLower(html), "<script") {
		t.Error("the report must not use scripts")
	}
	// ファイル名に使えない文字を含むホスト名でも、安全な名前にする
	evil := sample()
	evil.Meta.Host.Hostname = `a/b"<x>`
	if n := regexp.MustCompile(`download="([^"]+)"`).FindStringSubmatch(render(t, evil)); n == nil || n[1] != "kagiya-a_b__x_.cdx.json" {
		t.Errorf("file name for a hostile host name = %v", n)
	}
	// 複数ホストのときは、ホストごとの表示の見出しに、そのホストの CBOM を置く（名前の右には置かない）
	a, b := sample(), sample()
	b.Meta.Host.Hostname = "db01.example.jp"
	var buf bytes.Buffer
	if err := RenderAll(&buf, []*model.Inventory{a, b}, rules(t), "default"); err != nil {
		t.Fatal(err)
	}
	multi := buf.String()
	if regexp.MustCompile(`<div class="brand">クリプトインベントリ\s*<a class="dl"`).MatchString(multi) {
		t.Error("with several hosts, the link next to the name would be ambiguous")
	}
	for _, name := range []string{"kagiya-web01.example.jp.cdx.json", "kagiya-db01.example.jp.cdx.json"} {
		if strings.Count(multi, `download="`+name+`"`) != 1 {
			t.Errorf("no download link for %s", name)
		}
	}
}
