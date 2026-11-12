package report

import (
	"strings"
	"testing"
)

// 書き出しの規則: 文字列は必ずエスケープされ、固定の HTML（raw）だけがそのまま出る。
func TestHTMLWriterEscapes(t *testing.T) {
	h := &htmlWriter{}
	h.w(raw(`<td title="`), `"><script>alert(1)</script>&'+`+"\x00", raw(`">`), 42, raw(`</td>`))
	got := h.buf.String()
	want := `<td title="&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;&amp;&#39;&#43;` + "�" + `">42</td>`
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

// リンクにするのは、https で、URL に使える文字だけからなるものに限る。
func TestSafeURL(t *testing.T) {
	for u, want := range map[string]bool{
		"https://doi.org/10.6028/NIST.IR.8547":           true,
		"https://example.jp/a?b=c&d=e#f":                 true,
		"http://example.jp/":                             false,
		"javascript:alert(1)":                            false,
		"https://example.jp/\"onmouseover=\"x":           false,
		"https://example.jp/<script>":                    false,
		"https://example.jp/ space":                      false,
		"https://example.jp/" + strings.Repeat("a", 600): false,
		"": false,
	} {
		if safeURL(u) != want {
			t.Errorf("safeURL(%q) = %v, want %v", u, !want, want)
		}
	}
}

// 評価ポリシーの文書の URL が https でなければ、リンクにせず文字として示す。
func TestUnsafeReferenceURLIsNotLinked(t *testing.T) {
	var b strings.Builder
	pg := &page{Refs: []refView{{Title: "doc", URL: "javascript:alert(1)", Note: "n"}}}
	if err := renderPage(&b, pg); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), `href="javascript:`) || !strings.Contains(b.String(), "javascript:alert(1)") {
		t.Error("an unsafe URL must be shown as text, not as a link")
	}
}
