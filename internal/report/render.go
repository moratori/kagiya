// このファイルは、表示用のデータ（page、view）を HTML として書き出す部分。
//
// テンプレートエンジン（html/template、text/template）は使わない。テンプレートエンジンは名前からメソッドを呼ぶため、
// リンカが未使用のメソッドを捨てられなくなり、標準ライブラリの通信用のメソッドが実体に残る（internal/buildcheck で検査している）。
//
// エスケープの規則: 書き出しは htmlWriter.w だけで行う。w に渡した文字列は、必ずエスケープされる。
// エスケープせずに書き出されるのは、型 raw の値だけで、raw にしてよいのは、このファイルに直接書いた固定の HTML に限る。
// 結果に含まれる文字列（証明書の Subject、ファイルのパスなど、攻撃者が決められるもの）を raw に変換してはならない。
// 値は、要素の内容か、二重引用符で囲んだ属性値の位置にだけ置く（スクリプト、スタイル、引用符なしの属性値の位置には置かない）。

package report

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"io"
	"strconv"
	"strings"
)

//go:embed style.css
var styleSheet string

// raw は、エスケープせずに書き出す固定の HTML。
type raw string

type htmlWriter struct{ buf bytes.Buffer }

// escaper は、要素の内容と、引用符で囲んだ属性値のどちらでも安全になるように置き換える。
var escaper = strings.NewReplacer("\x00", "�", `"`, "&#34;", "&", "&amp;", "'", "&#39;", "+", "&#43;", "<", "&lt;", ">", "&gt;")

// w は、引数を順に書き出す。raw はそのまま、文字列はエスケープして、整数は数字として書く。
func (h *htmlWriter) w(parts ...any) {
	for _, p := range parts {
		switch v := p.(type) {
		case raw:
			h.buf.WriteString(string(v))
		case string:
			escaper.WriteString(&h.buf, v)
		case int:
			h.buf.WriteString(strconv.Itoa(v))
		default:
			panic("report: unsupported value in the HTML writer")
		}
	}
}

// joined は、文字列の並びを、区切り（固定の HTML か文字列）を挟んで書き出す。
func (h *htmlWriter) joined(items []string, sep any) {
	for i, s := range items {
		if i > 0 {
			h.w(sep)
		}
		h.w(s)
	}
}

// safeURL は、リンクにしてよい URL かどうかを返す（https で、URL に使える文字だけからなるもの）。
func safeURL(u string) bool {
	if !strings.HasPrefix(u, "https://") || len(u) > 512 {
		return false
	}
	for _, c := range u {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~:/?#[]@!$&()*,;=%", c)) {
			return false
		}
	}
	return true
}

func (h *htmlWriter) badge(b badge) {
	h.w(raw(`<span class="badge `), b.Class, raw(` tip" data-tip="`), b.Tip, raw(`">`), b.Label, raw(`</span>`))
}

// num は、要点の数。0 でなければ class を付けて目立たせる（class が空なら、常にそのまま）。
func (h *htmlWriter) num(n int, class string) {
	switch {
	case class == "":
		h.w(raw(`<span class="num">`), n, raw(`</span>`))
	case n != 0:
		h.w(raw(`<span class="num `), class, raw(`">`), n, raw(`</span>`))
	default:
		h.w(raw(`<span class="num zero">`), n, raw(`</span>`))
	}
}

// row は、要点の1行。tip が空でなければ、項目名に説明を付ける。
func (h *htmlWriter) row(tip, label string, n int, class string) {
	h.w(raw(`<div class="row">`))
	if tip != "" {
		h.w(raw(`<span class="tip" tabindex="0" data-tip="`), tip, raw(`">`), label, raw(`</span> `))
	} else {
		h.w(raw(`<span>`), label, raw(`</span> `))
	}
	h.num(n, class)
	h.w(raw(`</div>`))
}

func (h *htmlWriter) item(tip, label string, n int, class string) {
	h.w(raw(`<li>`))
	h.row(tip, label, n, class)
	h.w(raw("</li>\n"))
}

func renderPage(out io.Writer, pg *page) error {
	h := &htmlWriter{}
	h.w(raw(`<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>クリプトインベントリ`))
	if pg.Multi {
		h.w("（", len(pg.Hosts), " ホスト）")
	} else {
		for _, v := range pg.Hosts {
			h.w(" ", v.Host)
		}
	}
	h.w(raw("</title>\n<style>\n"), raw(styleSheet), raw("</style>\n</head>\n"))
	if pg.Multi {
		h.w(raw(`<body class="multi">`))
	} else {
		h.w(raw(`<body class="single">`))
	}
	h.w(raw(`
<nav class="side">
<div class="brand">クリプトインベントリ`))
	if !pg.Multi && len(pg.Hosts) == 1 {
		h.download(pg.Hosts[0])
	}
	h.w(raw("</div>\n"))
	if pg.Multi {
		h.w(raw(`<a href="#dashboard">全体の集計（`), len(pg.Hosts), raw(` ホスト）</a>
<div class="grp">ホストごとの詳細</div>
`))
		for _, v := range pg.Hosts {
			h.w(raw(`<a href="#`), v.ViewID, raw(`">`), v.Host, raw("</a>\n"))
		}
	} else {
		for _, v := range pg.Hosts {
			h.w(raw(`<div class="grp">`), v.Host, raw("</div>\n"))
			for _, l := range [][2]string{{"overview", "スキャンの概要"}, {"summary", "要点"}, {"services", "サービスの設定"}, {"files", "証明書と鍵"},
				{"system", "OS とライブラリ"}, {"coverage", "探索した範囲"}} {
				h.w(raw(`<a href="#`), v.H, "-", l[0], raw(`">`), l[1], raw("</a>\n"))
			}
		}
	}
	h.w(raw(`<div class="grp">共通</div>
<a href="#limits">このレポートでは分からないこと</a>
<a href="#criteria">判定の基準と出典</a>
</nav>
<div class="wrap">
<main>
`))
	for _, v := range pg.Hosts {
		h.host(v, pg.Multi)
	}
	if pg.Multi {
		h.dashboard(pg)
	}
	h.limits()
	h.w(raw(`<section class="common" id="criteria">
<div class="block">
<h2>判定の基準と出典</h2>
<p class="sub">評価の基準: `), pg.PolicyTitle, "（版 ", pg.PolicyVersion, raw(`）。このレポートを作った時点の基準で判定しています。判定は、下の文書に照らした目安です。個々のシステムで移行が必要か、いつまでに行うかは、扱う情報と利用期間に応じて判断してください。</p>
`))
	if len(pg.Rules) > 0 {
		h.w(raw(`<h3>このレポートで使った判定</h3>
<div class="tablewrap"><table><tr><th>判定の理由</th><th>根拠にした文書</th></tr>
`))
		for _, r := range pg.Rules {
			h.w(raw(`<tr><td>`), r.Summary, raw(`</td><td>`))
			h.joined(r.Refs, raw(`<br>`))
			h.w(raw("</td></tr>\n"))
		}
		h.w(raw("</table></div>\n"))
	}
	h.w(raw(`<h3>文書</h3>
<div class="tablewrap"><table><tr><th>文書</th><th>該当する内容</th></tr>
`))
	for _, r := range pg.Refs {
		h.w(raw(`<tr><td>`), r.Title, raw(`<br>`))
		if safeURL(r.URL) {
			h.w(raw(`<a href="`), r.URL, raw(`" rel="noopener noreferrer">`), r.URL, raw(`</a>`))
		} else {
			h.w(r.URL)
		}
		h.w(raw(`</td><td>`), r.Note, raw("</td></tr>\n"))
	}
	h.w(raw(`</table></div>
</div>
</section>
</main>
<footer>このファイルは外部の資源を読み込みません。スキャン結果は機密として扱ってください。</footer>
</div>
</body>
</html>
`))
	_, err := out.Write(h.buf.Bytes())
	return err
}

// dashboard は、複数ホストのときの全体の集計。
func (h *htmlWriter) dashboard(pg *page) {
	h.w(raw(`<section class="dashboard" id="dashboard">
<header class="top"><div class="in">
<h1>全体の集計（`), len(pg.Hosts), raw(` ホスト）</h1>
<p>ホストごとのスキャン結果を足し合わせたものです。ホストの名前を選ぶと、そのホストの詳細に移ります。</p>
</div></header>
<div class="block">
<h2>要点</h2>
`))
	h.cards(pg.TotalView)
	h.w(raw(`</div>
<div class="block">
<h2>ホストごとの状況</h2>
<div class="tablewrap"><table>
<tr><th>ホスト</th><th>OS</th><th>ラベル</th><th>サービス</th><th>量子計算機に弱い方式<br>（うち鍵交換）</th><th>強度が下がる方式</th><th>危殆化</th><th>非推奨</th><th>期限切れの証明書</th><th>権限がなく読めなかった</th></tr>
`))
	for _, v := range pg.Hosts {
		h.w(raw(`<tr><td><a href="#`), v.ViewID, raw(`">`), v.Host, raw(`</a>`))
		if v.Incomplete {
			h.w(raw(` <span class="badge bad">未完了</span>`))
		}
		h.w(raw(`</td><td>`))
		if v.Distribution != "" {
			h.w(v.Distribution)
		} else {
			h.w(v.OSArch)
		}
		h.w(raw(`</td><td>`))
		h.joined(v.Labels, "、")
		s := v.Summary
		h.w(raw(`</td><td>`), s.Services, raw(`</td><td>`), s.Quantum, "（", s.Kex, "）", raw(`</td><td>`), s.Reduced, raw(`</td><td>`), s.Weak,
			raw(`</td><td>`), s.Legacy, raw(`</td><td>`), s.Expired, raw(`</td><td>`), s.Permission, raw("</td></tr>\n"))
	}
	h.w(raw(`</table></div>
<p class="sub">数は、サービス・範囲ごとに許可されている方式の延べ数です。</p>
</div>
</section>
`))
}

// cards は、要点（サービスの設定、ファイルとして見つかった証明書・鍵、探索した範囲）。
func (h *htmlWriter) cards(v *view) {
	s, tips := v.Summary, v.Tips
	h.w(raw(`<div class="cards">
<div class="card">
<h3>サービスの設定（`), s.Services, raw(` サービス）</h3>
<ul>
<li>`))
	h.row(tips["quantum"], "量子計算機に弱い方式", s.Quantum, "bad")
	h.w(raw("\n<ul class=\"sub\">\n"))
	h.item(tips["kex"], "鍵交換", s.Kex, "bad")
	h.item(tips["sig"], "署名・認証", s.Sig, "bad")
	h.w(raw("</ul></li>\n"))
	h.item(tips["reduced"], "量子計算機で強度が下がる方式", s.Reduced, "warn")
	h.item(tips["hybrid"], "ハイブリッドの方式", s.Hybrid, "good")
	h.item(tips["weak"], "危殆化している方式・プロトコル", s.Weak, "bad")
	h.item(tips["legacy"], "非推奨の方式", s.Legacy, "warn")
	h.item(tips["unknown"], "判定できない方式", s.Unknown, "unk")
	h.w(raw(`</ul>
</div>
<div class="card">
<h3>ファイルとして見つかった証明書・鍵（証明書ストアを除く）</h3>
<ul>
`))
	h.item(tips["quantum"], "量子計算機に弱い", s.FileQuantum, "bad")
	h.item(tips["weak"], "危殆化している", s.FileWeak, "bad")
	h.item(tips["legacy"], "非推奨", s.FileLegacy, "warn")
	h.item("", "期限切れの証明書", s.Expired, "bad")
	h.item("", strconv.Itoa(v.ExpiringDays)+" 日以内に期限が来る証明書", s.Expiring, "warn")
	h.item(tips["unconfirmed"], "設定からの参照を確認できなかった秘密鍵", s.Unconfirmed, "warn")
	h.w(raw(`</ul>
</div>
<div class="card">
<h3>探索した範囲</h3>
`))
	if len(v.RootList) > 0 {
		h.w(raw(`<ul class="roots">`))
		for _, r := range v.RootList {
			h.w(raw(`<li class="mono">`), r, raw(`</li>`))
		}
		h.w(raw("</ul>\n"))
	}
	h.w(raw("<ul>\n"))
	h.item("", "調べたファイル", s.Files, "")
	h.item("", "調べたディレクトリ", s.Dirs, "")
	h.item("", "権限がなく読めなかったもの", s.Permission, "warn")
	h.item("", "そのほかの理由で読み飛ばしたもの", s.OtherSkips, "warn")
	h.w(raw(`</ul>
</div>
</div>
`))
}

// host は、1 ホスト分の詳細。
func (h *htmlWriter) host(v *view, multi bool) {
	id := func(suffix string) []any { return []any{v.H, "-", suffix} }
	h.w(raw(`<section class="view" id="`), v.ViewID, raw(`">
<header class="top"><div class="in">
<h1>`), v.Host)
	if multi {
		h.download(v)
	}
	h.w(raw(`</h1>
</div></header>
<div class="block">
<h2 id="`))
	h.w(id("overview")...)
	h.w(raw("\">スキャンの概要</h2>\n"))
	if v.Incomplete {
		h.w(raw(`<div class="alert"><strong>このスキャンは完了していません。</strong>結果は途中までのものです`))
		if v.IncompleteReason != "" {
			h.w("（理由: ", v.IncompleteReason, "）")
		}
		h.w(raw("。</div>"))
	}
	h.w(raw(`
<dl class="meta">
<dt>ホスト</dt><dd>`), v.Host, raw(`</dd>
<dt>OS</dt><dd>`))
	if v.Distribution != "" {
		h.w(v.Distribution, "（", v.OSArch, "）")
	} else {
		h.w(v.OSArch)
	}
	h.w(raw(`</dd>
<dt>スキャンの開始 / 終了</dt><dd>`), v.Started, " / ", v.Finished, raw(`</dd>
<dt>ツールの版</dt><dd>`), v.ToolVersion, raw(`</dd>
<dt>検出ルールの版</dt><dd>`), v.RulesVersion, "（", v.RulesSource, "）", raw(`</dd>
<dt>実行した権限</dt><dd>`))
	if v.Elevated {
		h.w("管理者権限")
	} else {
		h.w("一般ユーザー（権限がなく読めないファイルは結果に含まれません）")
	}
	h.w(raw("</dd>\n"))
	if len(v.Labels) > 0 {
		h.w(raw(`<dt>ラベル</dt><dd>`))
		h.joined(v.Labels, "、")
		h.w(raw(`</dd>`))
	}
	h.w(raw("\n</dl>\n"))
	for _, s := range v.Warnings {
		h.w(raw(`<p class="note">注意: `), s, raw(`</p>`))
	}
	h.w(raw(`
</div>

<div class="block">
<h2 id="`))
	h.w(id("summary")...)
	h.w(raw("\">要点</h2>\n"))
	h.cards(v)
	h.w(raw(`</div>

<div class="block">
<h2 id="`))
	h.w(id("services")...)
	h.w(raw("\">サービスの設定</h2>\n"))
	if len(v.Services) == 0 {
		h.w(raw(`<p>サービスは見つかりませんでした。</p>`))
	} else {
		h.w(raw(`<p class="sub">見つかったサービスです。名前を選ぶと開きます。</p>`))
	}
	h.w(raw("\n"))
	for i := range v.Services {
		h.service(&v.Services[i])
	}
	h.w(raw(`</div>

<div class="block">
<h2 id="`))
	h.w(id("files")...)
	h.w(raw("\">証明書と鍵</h2>\n"))
	if len(v.Unconfirmed) > 0 {
		h.w(raw(`<h3>設定からの参照を確認できなかった秘密鍵（`), len(v.Unconfirmed), raw(` 件）</h3>
<div class="alert">このツールが読んだ設定（対応しているサービスの設定ファイル）からは、参照が見つからなかった秘密鍵です。<strong>使われていないことを示すものではありません。</strong>このツールが対応していないアプリや、調べていない場所から使われている可能性があります。この表示だけを根拠に削除しないでください。</div>
`))
		h.assets(v.Unconfirmed)
	}
	h.w(raw(`<h3>ファイルとして見つかったもの（`), len(v.Files), raw(" 件）</h3>\n"))
	if len(v.Files) > 0 {
		h.assets(v.Files)
	} else {
		h.w(raw(`<p>証明書ストアの外では、証明書や鍵は見つかりませんでした。</p>`))
	}
	h.w(raw("\n"))
	if len(v.Stores) > 0 {
		h.w(raw(`<h3>証明書ストア</h3>
<p class="sub">OS や実行環境が信頼する CA 証明書の置き場です。件数が多いので畳んでいます。</p>
`))
		for i := range v.Stores {
			h.store(&v.Stores[i])
		}
	}
	h.w(raw(`</div>

<div class="block">
<h2 id="`))
	h.w(id("system")...)
	h.w(raw("\">OS とライブラリ</h2>\n"))
	if len(v.OSSettings) > 0 {
		h.w(raw("<h3>OS 全体の暗号設定</h3>\n"))
		h.kvTable([3]string{"項目", "値", "場所"}, v.OSSettings, [3]bool{true, true, true})
	}
	if len(v.Components) > 0 {
		h.w(raw("<h3>アプリケーションと暗号ライブラリ</h3>\n"))
		h.kvTable([3]string{"名前", "場所と版", "リンクしている暗号ライブラリ"}, v.Components, [3]bool{false, true, true})
	}
	if len(v.Packages) > 0 {
		h.w(raw("<h3>暗号に関係するパッケージ</h3>\n"))
		h.kvTable([3]string{"パッケージ", "版", "管理方式"}, v.Packages, [3]bool{true, true, false})
	}
	if len(v.OSSettings) == 0 && len(v.Components) == 0 && len(v.Packages) == 0 {
		h.w(raw(`<p>該当する情報はありませんでした。</p>`))
	}
	h.w(raw(`
</div>

<div class="block">
<h2 id="`))
	h.w(id("coverage")...)
	h.w(raw(`">探索した範囲と、読み飛ばしたもの</h2>
<p>探索の起点: <span class="mono">`))
	if v.Roots != "" {
		h.w(v.Roots)
	} else {
		h.w("（記録なし）")
	}
	c := v.Coverage
	h.w(raw(`</span></p>
<p class="sub">この起点の外は調べていません（例: 利用者のホームディレクトリ、アプリケーションが独自に使う場所）。起点の下で調べたのは、ファイル `), c.FilesExamined,
		"、ディレクトリ ", c.DirsExamined, " です（辿らなかったシンボリックリンク ", c.SymlinksIgnored, "、開かなかった特殊ファイル ", c.SpecialIgnored, raw(`）。</p>
<h3>起点の下で読み飛ばしたもの</h3>
`))
	if len(v.SkippedBy) > 0 {
		h.w(raw(`<div class="tablewrap"><table><tr><th>理由</th><th>件数</th></tr>
`))
		for _, r := range v.SkippedBy {
			h.w(raw(`<tr><td>`), r.Key, raw(`</td><td>`), r.Value, raw("</td></tr>\n"))
		}
		h.w(raw("</table></div>\n"))
	} else {
		h.w(raw("<p>読み飛ばしたものは記録されていません。</p>\n"))
	}
	if len(v.Skipped) > 0 {
		h.w(raw(`<details>
<summary>読み飛ばした場所の一覧（`), len(v.Skipped), " 件")
		if v.SkippedCut {
			h.w("。件数が多いため一部だけを載せています。全件はスキャンのログにあります")
		}
		h.w(raw("）</summary>\n"))
		h.kvTable([3]string{"場所", "理由", "詳細"}, v.Skipped, [3]bool{true, false, true})
		h.w(raw("</details>\n"))
	}
	h.w(raw(`</div>
</section>
`))
}

// download は、そのホストの CBOM を保存するためのリンク（中身を埋め込む。スクリプトは使わない）。
func (h *htmlWriter) download(v *view) {
	if len(v.CBOM) == 0 {
		return
	}
	h.w(raw(` <a class="dl" title="CBOM（CycloneDX 1.6）を保存" aria-label="CBOM（CycloneDX 1.6）を保存" download="`), v.CBOMName,
		raw(`" href="data:application/vnd.cyclonedx+json;base64,`))
	// base64 にした結果は、英数字と + / = だけからなるので、そのまま書き出してよい
	enc := base64.NewEncoder(base64.StdEncoding, &h.buf)
	enc.Write(v.CBOM)
	enc.Close()
	h.w(raw(`"><svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path d="M12 3v11m0 0l-4-4m4 4l4-4M5 19h14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></a>`))
}

// limits は、このレポートでは分からないこと（どのホストにも共通。左の欄の「共通」から開く）。
func (h *htmlWriter) limits() {
	h.w(raw(`<section class="common" id="limits">
<div class="block">
<h2>このレポートでは分からないこと</h2>
<ul class="plain">
<li>実際にネゴシエーションされている暗号。設定から分かるのは「受け入れる設定になっている」ものまでで、相手との間でどれが選ばれているかは通信を観測しないと分かりません。</li>
<li>サービスが実際に動いているか。「有効」は起動するよう設定されているという意味で、止まっていることも、手動で動かされていることもあり得ます。</li>
<li>どのプロトコルの版（TLS 1.0〜1.3）が実際に通るか。プロトコルは設定に書かれた値を示すにとどめています。暗号スイートは、いずれかの版が有効なら受け入れ得るものの一覧です。</li>
<li>このツールが対応していないアプリケーションの設定と、そこからの鍵・証明書の利用。対応しているのは一部のサーバーソフトウェアだけです。</li>
<li>クライアントとしての利用。定期実行されるスクリプトなどからの暗号の利用は、サービスとしては見えません。</li>
<li>探索の起点の外にあるもの、ネットワーク越しのファイルシステム上のもの、権限がなく読めなかったもの、パスワードで保護されたキーストアの中身。</li>
<li>証明書の信頼性。署名の検証、信頼の連鎖、失効は確認していません。自己署名のルート証明書の署名方式は、判定には出ますが、安全性には影響しません。</li>
<li>パッケージの版を変えずに中身が差し替えられている場合（独自にビルドしたプログラムへの置き換えなど）。判定は、導入されているパッケージの版で実測した挙動に基づいています。</li>
</ul>
</div>
</section>
`))
}

// kvTable は、3 列の表。mono は、各列を等幅で示すかどうか。
func (h *htmlWriter) kvTable(head [3]string, rows []kv, mono [3]bool) {
	h.w(raw(`<div class="tablewrap"><table><tr><th>`), head[0], raw(`</th><th>`), head[1], raw(`</th><th>`), head[2], raw("</th></tr>\n"))
	td := func(m bool, s string) {
		if m {
			h.w(raw(`<td class="mono">`), s, raw(`</td>`))
		} else {
			h.w(raw(`<td>`), s, raw(`</td>`))
		}
	}
	for _, r := range rows {
		h.w(raw(`<tr>`))
		td(mono[0], r.Key)
		td(mono[1], r.Value)
		td(mono[2], r.Where)
		h.w(raw("</tr>\n"))
	}
	h.w(raw("</table></div>\n"))
}

func (h *htmlWriter) service(s *serviceView) {
	h.w(raw(`<details class="svc">
<summary>`), s.Name, "（", s.Activity, "）", raw(`</summary>
<dl class="meta">
<dt>状態</dt><dd><span class="tip" data-tip="`), s.ActivityTip, raw(`">`), s.Activity, raw("</span></dd>\n"))
	if len(s.Evidence) > 0 {
		h.w(raw(`<dt>状態の根拠</dt><dd>`))
		h.joined(s.Evidence, raw(`<br>`))
		h.w(raw("</dd>\n"))
	}
	if s.Component != "" {
		h.w(raw(`<dt>プログラム</dt><dd class="mono">`), s.Component, raw("</dd>\n"))
	}
	if len(s.Configs) > 0 {
		h.w(raw(`<dt>設定ファイル</dt><dd class="mono">`))
		h.joined(s.Configs, "、")
		h.w(raw("</dd>\n"))
	}
	h.w(raw("</dl>\n"))
	for _, n := range s.Notes {
		h.w(raw(`<p class="note">注意: `), n, raw("</p>\n"))
	}
	if len(s.Scopes) == 0 {
		h.w(raw("<p class=\"sub\">暗号に関する設定は見つかりませんでした。</p>\n"))
	}
	for i := range s.Scopes {
		sc := &s.Scopes[i]
		h.w(raw("<div class=\"scope\">\n<h4>"))
		if sc.Name != "" {
			h.w("範囲: ", sc.Name)
		} else {
			h.w("サービス全体")
		}
		h.w(raw("</h4>\n"))
		for j := range sc.Effective {
			h.effective(&sc.Effective[j])
		}
		if len(sc.Settings) > 0 {
			h.w(raw(`<div class="tablewrap"><table>
<tr><th>設定に書かれている項目</th><th>値</th><th>場所</th></tr>
`))
			for _, st := range sc.Settings {
				h.w(raw(`<tr><td>`), st.Label)
				if st.Shadowed {
					h.w("（他の記載が優先され、効いていない）")
				}
				h.w(raw(`</td><td class="mono">`), st.Values)
				for _, b := range st.Badges {
					if b.Classical.Class == "bad" {
						h.w(raw(` <span class="badge bad tip" data-tip="`), b.Classical.Tip, raw(`">`), b.Name, ": ", b.Classical.Label, raw(`</span>`))
					}
				}
				h.w(raw(`</td><td class="mono">`), st.Location, raw("</td></tr>\n"))
			}
			h.w(raw("</table></div>\n"))
		}
		h.w(raw("</div>\n"))
	}
	h.w(raw("</details>\n"))
}

func (h *htmlWriter) effective(e *effectiveView) {
	h.w(raw(`<p><strong>`), e.Label, raw(`</strong>`))
	if e.Resolved {
		h.w(raw(` — このサービスが受け入れる設定になっている方式です（設定の記載と既定値から算出。<span class="tip" data-tip="確度「高」は、導入されている版そのもので実測した表から求めた値。「中」は、近い版の実測を当てはめたか、証明書などを読めずに絞り込みの一部をしていない値">`),
			e.Confidence, raw(`</span>）`))
	} else {
		h.w(raw(` <span class="badge unk">特定できませんでした</span>`))
	}
	h.w(raw("</p>\n"))
	if !e.Resolved {
		h.w(raw(`<p class="note">理由: `), e.Reason, raw("</p>\n"))
	}
	for _, n := range e.Notes {
		h.w(raw(`<p class="note">注意: `), n, raw("</p>\n"))
	}
	if len(e.Steps) > 0 {
		h.w(raw(`<p class="sub">求め方:</p><ol class="steps">`))
		for _, s := range e.Steps {
			h.w(raw(`<li>`), s, raw(`</li>`))
		}
		h.w(raw("</ol>\n"))
	}
	if !e.Resolved {
		return
	}
	if e.Fold {
		h.w(raw(`<details><summary>`), e.Counts, raw(`（一覧を開く）</summary>`))
		h.values(e)
		h.w(raw("</details>\n"))
		return
	}
	h.w(raw(`<p class="sub">`), e.Counts, raw(`</p>`))
	h.values(e)
}

// values は、受け入れる方式の一覧と判定。
func (h *htmlWriter) values(e *effectiveView) {
	verdicts := func(r *valueRow) {
		h.w(raw(`<td>`))
		if r.HasVerdict {
			h.badge(r.Quantum)
		}
		h.w(raw(`</td><td>`))
		if r.HasVerdict {
			h.badge(r.Classical)
		}
		h.w(raw("</td></tr>\n"))
	}
	h.w(raw("\n<div class=\"tablewrap\"><table>\n"))
	if e.IsSuite {
		h.w(raw("<tr><th>スイート</th><th>鍵交換</th><th>認証</th><th>暗号化</th><th>量子計算機に対して</th><th>現在の計算機に対して</th></tr>\n"))
		for i := range e.Rows {
			r := &e.Rows[i]
			h.w(raw(`<tr><td class="mono">`), r.Name, raw(`</td><td class="mono">`), r.Kx, raw(`</td><td class="mono">`), r.Au, raw(`</td><td class="mono">`), r.Enc, raw(`</td>`))
			verdicts(r)
		}
	} else {
		h.w(raw("<tr><th>値</th><th>量子計算機に対して</th><th>現在の計算機に対して</th></tr>\n"))
		for i := range e.Rows {
			r := &e.Rows[i]
			h.w(raw(`<tr><td class="mono">`), r.Name, raw(`</td>`))
			verdicts(r)
		}
	}
	h.w(raw("</table></div>\n"))
	if len(e.Reasons) > 0 {
		h.w(raw(`<p class="sub">判定の理由:</p><ul class="reasons">`))
		for _, r := range e.Reasons {
			h.w(raw(`<li>`), r.Summary, raw(`</li>`))
		}
		h.w(raw("</ul>\n"))
	}
}

// assets は、ファイルとして見つかった証明書・鍵の表。
func (h *htmlWriter) assets(rows []assetRow) {
	h.w(raw(`
<div class="tablewrap"><table>
<tr><th>種類</th><th>名前</th><th>アルゴリズム</th><th>有効期限</th><th>場所</th><th>設定からの参照</th><th>量子計算機に対して</th><th>現在の計算機に対して</th></tr>
`))
	for i := range rows {
		r := &rows[i]
		h.w(raw(`<tr><td>`), r.Kind, raw(`</td><td>`), r.Name, raw(`</td><td class="mono">`), r.Algorithm, raw(`</td><td>`), r.Expiry)
		if r.ExpiryTag.Label != "" {
			h.w(raw(" "))
			h.badge(r.ExpiryTag)
		}
		h.w(raw(`</td><td class="mono">`), r.Path, raw(`</td><td>`), r.Activity)
		for _, e := range r.Evidence {
			h.w(raw(`<br><span class="sub">`), e, raw(`</span>`))
		}
		h.w(raw(`</td><td>`))
		if r.Quantum.Label != "" {
			h.badge(r.Quantum)
		}
		h.w(raw(`</td><td>`))
		if r.Classical.Label != "" {
			h.badge(r.Classical)
		}
		h.w(raw("</td></tr>\n"))
	}
	h.w(raw("</table></div>\n"))
}

// store は、証明書ストア1つ（署名の方式ごとにまとめる）。
func (h *htmlWriter) store(s *storeView) {
	h.w(raw(`<details>
<summary>`), s.Name, "（", s.Count, " 件）", raw(`</summary>
<p class="sub">署名の方式ごとの件数と、その方式の判定です。判定は署名の方式に対するもので、同じ行の証明書すべてに当てはまります。</p>
<div class="tablewrap"><table>
<tr><th>署名の方式</th><th>件数</th><th>量子計算機に対して</th><th>現在の計算機に対して</th></tr>
`))
	for i := range s.Groups {
		g := &s.Groups[i]
		h.w(raw(`<tr><td class="mono">`), g.Signature, raw(`</td><td>`), g.Count, raw(`</td><td>`))
		if g.Quantum.Label != "" {
			h.badge(g.Quantum)
		}
		h.w(raw(`</td><td>`))
		if g.Classical.Label != "" {
			h.badge(g.Classical)
		}
		h.w(raw("</td></tr>\n"))
	}
	h.w(raw("</table></div>\n"))
	for i := range s.Groups {
		g := &s.Groups[i]
		h.w(raw(`<h4>署名 `), g.Signature, "（", g.Count, " 件）", raw(`</h4>
<div class="tablewrap"><table>
<tr><th>種類</th><th>名前</th><th>アルゴリズム</th><th>有効期限</th><th>場所</th></tr>
`))
		for j := range g.Rows {
			r := &g.Rows[j]
			h.w(raw(`<tr><td>`), r.Kind, raw(`</td><td>`), r.Name, raw(`</td><td class="mono">`), r.Algorithm, raw(`</td><td>`), r.Expiry)
			if r.ExpiryTag.Label != "" {
				h.w(raw(` <span class="badge `), r.ExpiryTag.Class, raw(`">`), r.ExpiryTag.Label, raw(`</span>`))
			}
			h.w(raw(`</td><td class="mono">`), r.Path, raw("</td></tr>\n"))
		}
		h.w(raw("</table></div>\n"))
	}
	h.w(raw("</details>\n"))
}
