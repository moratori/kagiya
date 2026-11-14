package ruleset

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// rules/README.md（これまでに測ったものの一覧）は、ルールのデータから作る。ルールを足したら、一覧も新しくする:
//
//	KAGIYA_UPDATE_README=1 go test ./internal/ruleset -run TestRulesReadme
//
// このテストは、README がルールと合っていること（測ったものを足したのに一覧が古いまま、にならないこと）を確かめる。
func TestRulesReadme(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	want := rulesReadme(rs)
	path := filepath.Join("..", "..", "rules", "README.md")
	if os.Getenv("KAGIYA_UPDATE_README") != "" {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("rules/README.md is missing; create it with KAGIYA_UPDATE_README=1 go test ./internal/ruleset -run TestRulesReadme (%v)", err)
	}
	if strings.ReplaceAll(string(got), "\r\n", "\n") != want {
		t.Error("rules/README.md is out of date; update it with: KAGIYA_UPDATE_README=1 go test ./internal/ruleset -run TestRulesReadme")
	}
}

var (
	osVersion = regexp.MustCompile(`[0-9]+(\.[0-9]+)?`)
	epoch     = regexp.MustCompile(`^[0-9]+:`)
)

// osLabel は、出典の OS の名前を、表の行の名前（ディストリビューションと系列）にする。並べ替え用のキーも返す。
func osLabel(os string) (label, key string) {
	v := osVersion.FindString(os)
	major := v
	if i := strings.IndexByte(v, '.'); i >= 0 {
		major = v[:i]
	}
	n, _ := strconv.Atoi(major)
	switch {
	case strings.HasPrefix(os, "Red Hat Enterprise Linux"):
		return "RHEL " + major + "（UBI）", fmt.Sprintf("1-%03d-1", n)
	case strings.HasPrefix(os, "AlmaLinux"):
		return "AlmaLinux " + major, fmt.Sprintf("1-%03d-2", n)
	case strings.HasPrefix(os, "Rocky Linux"):
		return "Rocky Linux " + major, fmt.Sprintf("1-%03d-3", n)
	case strings.HasPrefix(os, "Debian"):
		return "Debian " + major, fmt.Sprintf("2-%03d", n)
	case strings.HasPrefix(os, "Ubuntu"):
		return "Ubuntu " + v, "3-" + v // 20.04 のように、系列は小数点まで
	case strings.HasPrefix(os, "Amazon Linux"):
		return "Amazon Linux " + major, fmt.Sprintf("4-%03d", n)
	}
	return os, "9-" + os
}

// upstreamOf は、パッケージの版から、開発元の版の部分を取り出す（先頭の「数字:」と、「-」より後ろを除く）。
func readmeUpstream(version string) string {
	v := epoch.ReplaceAllString(version, "")
	if i := strings.IndexByte(v, '-'); i >= 0 {
		v = v[:i]
	}
	for _, sep := range []string{"+dfsg", "+ds", "~"} {
		if i := strings.Index(v, sep); i >= 0 {
			v = v[:i]
		}
	}
	return v
}

// matrix は、「行（OS）× 列」の表。セルは、測った版の集まり。
type matrix struct {
	rows  map[string]string // 並べ替えのキー → 行の名前
	cells map[string]map[string]map[string]bool
}

func (m *matrix) add(os, col, version string) {
	if m.rows == nil {
		m.rows, m.cells = map[string]string{}, map[string]map[string]map[string]bool{}
	}
	label, key := osLabel(os)
	m.rows[key] = label
	if m.cells[key] == nil {
		m.cells[key] = map[string]map[string]bool{}
	}
	if m.cells[key][col] == nil {
		m.cells[key][col] = map[string]bool{}
	}
	m.cells[key][col][version] = true
}

func (m *matrix) write(b *strings.Builder, first string, cols []string, names map[string]string) {
	b.WriteString("| " + first + " |")
	for _, c := range cols {
		n := names[c]
		if n == "" {
			n = c
		}
		b.WriteString(" " + n + " |")
	}
	b.WriteString("\n|---|" + strings.Repeat("---|", len(cols)) + "\n")
	keys := make([]string, 0, len(m.rows))
	for k := range m.rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString("| " + m.rows[k] + " |")
		for _, c := range cols {
			var vs []string
			for v := range m.cells[k][c] {
				vs = append(vs, v)
			}
			sortVersions(vs)
			cell := strings.Join(vs, "<br>")
			if cell == "" {
				cell = "—"
			}
			b.WriteString(" " + cell + " |")
		}
		b.WriteString("\n")
	}
}

// sortVersions は、版を、数字の並びとして小さい順に並べる（比べられないものは、文字の順）。
func sortVersions(vs []string) {
	sort.Slice(vs, func(i, j int) bool {
		if c, ok := CompareVersions(vs[i], vs[j]); ok && c != 0 {
			return c < 0
		}
		return vs[i] < vs[j]
	})
}

// ranges は、版の並びを、系列（先頭の 2 つの数字）ごとの「最小〜最大（件数）」にまとめる。
func ranges(versions []string) []string {
	bySeries := map[string][]string{}
	for _, v := range versions {
		parts := strings.SplitN(v, ".", 3)
		s := parts[0]
		if len(parts) > 1 {
			s += "." + parts[1]
		}
		bySeries[s] = append(bySeries[s], v)
	}
	var series []string
	for s := range bySeries {
		series = append(series, s)
	}
	sortVersions(series)
	var out []string
	for _, s := range series {
		vs := bySeries[s]
		sortVersions(vs)
		if len(vs) == 1 {
			out = append(out, vs[0])
		} else {
			out = append(out, fmt.Sprintf("%s〜%s（%d 版）", vs[0], vs[len(vs)-1], len(vs)))
		}
	}
	return out
}

func rulesReadme(rs *RuleSet) string {
	var b strings.Builder
	b.WriteString("# 検出ルールと、これまでに測ったもの\n\n")
	b.WriteString("このディレクトリは、kagiya の実行ファイルに内蔵する検出ルール（データだけ。YAML）です。\n")
	b.WriteString("既定値や対応表は、記憶ではなく、実物のパッケージや配布物を検証用のコンテナに導入して測ったものだけを載せています。\n")
	b.WriteString("各項目には、測ったイメージ（ダイジェストつき）と OS が、出典として書いてあります。\n\n")
	b.WriteString("**この一覧は、ルールのデータから自動で作っています。手で編集しないでください。**\n")
	b.WriteString("ルールを足したら、`KAGIYA_UPDATE_README=1 go test ./internal/ruleset -run TestRulesReadme` で作り直します。\n\n")
	b.WriteString("ルールのバージョン: `" + rs.Version + "`\n\n")

	// 1. ディストリビューションのパッケージ
	apps := &matrix{}
	names := map[string]string{"openssl": "OpenSSL", "openssh": "OpenSSH（sshd）", "nginx": "nginx", "httpd": "Apache httpd", "haproxy": "HAProxy",
		"stunnel": "stunnel", "postfix": "Postfix", "dovecot": "Dovecot", "postgresql": "PostgreSQL", "mariadb": "MariaDB", "mysql": "MySQL", "tomcat": "Tomcat"}
	order := []string{"openssl", "openssh", "nginx", "httpd", "haproxy", "stunnel", "postfix", "dovecot", "postgresql", "mariadb", "mysql", "tomcat"}
	seen := map[string]bool{}
	for _, c := range order {
		seen[c] = true
	}
	col := func(c string) string {
		if !seen[c] {
			seen[c] = true
			order = append(order, c)
		}
		return c
	}
	for _, t := range rs.CipherTables {
		for _, bd := range t.Builds {
			apps.add(bd.Source.OS, col(t.Library), readmeUpstream(bd.Version))
		}
	}
	for _, d := range rs.Defaults {
		apps.add(d.Source.OS, col(d.App), readmeUpstream(d.Version))
	}
	for _, t := range rs.TomcatTables {
		for _, bd := range t.Builds {
			apps.add(bd.Source.OS, col(t.Server), readmeUpstream(bd.Version))
		}
	}
	b.WriteString("## ディストリビューションのパッケージ\n\n")
	b.WriteString("ディストリビューションのリポジトリから導入したパッケージで、既定値と挙動を測ったものです。セルは、測ったパッケージの、開発元の版です\n")
	b.WriteString("（パッケージの版の全体と出典は、`defaults/`・`ciphers/`・`groups/`・`java/` の各ファイルにあります）。「—」は、測っていない組み合わせです。\n\n")
	b.WriteString("同じ開発元の版・同じ系列で、ディストリビューションが作り直した番号だけが違うパッケージは、測った表で補います（確度を下げます）。\n")
	b.WriteString("それ以外の、測っていない版では、既定値に頼る項目を「不明」とします。\n\n")
	apps.write(&b, "OS", order, names)

	// 2. JDK
	jdk := &matrix{}
	majors := map[string]bool{}
	for _, t := range rs.JDKTables {
		major := t.JavaVersion
		if strings.HasPrefix(major, "1.8") {
			major = "8"
		} else if i := strings.IndexByte(major, '.'); i >= 0 {
			major = major[:i]
		}
		majors[major] = true
		for _, bd := range t.Builds {
			jdk.add(bd.Source.OS, major, t.JavaVersion)
		}
	}
	var jcols []string
	for m := range majors {
		jcols = append(jcols, m)
	}
	sort.Slice(jcols, func(i, j int) bool { a, _ := strconv.Atoi(jcols[i]); c, _ := strconv.Atoi(jcols[j]); return a < c })
	jnames := map[string]string{}
	for _, m := range jcols {
		jnames[m] = "Java " + m
	}
	b.WriteString("\n## Java（OpenJDK）\n\n")
	b.WriteString("JDK が、アプリが何も指定しない場合に受け入れるプロトコル・暗号スイート・鍵交換のグループを測ったものです。セルは、JDK の開発元の版です。\n")
	b.WriteString("JDK だけは、開発元の版が同じなら、配布元（ディストリビューション）が違っても、測った表で補います（確度を下げます）。\n\n")
	jdk.write(&b, "OS（配布元）", jcols, jnames)

	// 3. 配布物として測ったもの
	b.WriteString("\n## ディストリビューションによらないもの\n\n")
	b.WriteString("開発元が配っている成果物（Maven Central の JAR など）を取得して測ったものです。\n\n")
	b.WriteString("| 対象 | 測った版 | 測り方 |\n|---|---|---|\n")
	var boots []string
	for _, t := range rs.SpringBootTables {
		boots = append(boots, t.Versions...)
	}
	if len(boots) > 0 {
		b.WriteString("| Spring Boot（組み込みの Tomcat） | " + strings.Join(ranges(boots), "<br>") + "<br>計 " + strconv.Itoa(len(boots)) +
			" 版 | 各版でアプリをビルドして起動し、設定を変えた場面ごとに、受け入れるものを数え上げた |\n")
	}
	var embeds []string
	for _, t := range rs.EmbeddedTomcatTables {
		for _, v := range t.Versions {
			embeds = append(embeds, v.Version)
		}
	}
	if len(embeds) > 0 {
		b.WriteString("| アプリに同梱される Tomcat（tomcat-embed-core） | " + strings.Join(ranges(embeds), "<br>") + "<br>計 " + strconv.Itoa(len(embeds)) +
			" 版 | Tomcat 自身に、暗号の指定の解釈の表を出力させた |\n")
	}

	// 4. 耐量子のアルゴリズムに対応している版
	b.WriteString("\n## 暗号ライブラリが耐量子のアルゴリズムに対応している版\n\n")
	b.WriteString("「対応」は、ライブラリがその方式を持っていることです（使う設定になっているかは別）。「確かめた範囲」の外の版は、前後から推定します。\n\n")
	b.WriteString("| ライブラリ | 対象 | 方式 | 対応している版 | 確かめた範囲 | 根拠 |\n|---|---|---|---|---|---|\n")
	// 対象・版・範囲・根拠が同じ方式は、1 行にまとめる
	type pqcRow struct{ lib, target, since, checked, basis string }
	var rows []pqcRow
	features := map[pqcRow][]string{}
	add := func(lib string, f PQCFeature) {
		r := pqcRow{lib: lib, target: strings.Join(f.Artifacts, "、"), since: f.Since + " 以降", checked: f.Checked.From + "〜" + f.Checked.To, basis: "実物で確かめた"}
		if r.target == "" {
			r.target = "ライブラリ全体"
		}
		if f.Since == "" {
			r.since = "確かめた範囲では、対応していない"
		}
		if f.Evidence == PQCDocumented {
			r.basis = "開発元の資料"
		}
		if len(f.Unmeasured) > 0 {
			r.basis += "（" + strings.Join(f.Unmeasured, "、") + " は測れなかった）"
		}
		if _, ok := features[r]; !ok {
			rows = append(rows, r)
		}
		features[r] = append(features[r], f.Name)
	}
	for _, l := range rs.Libraries {
		if l.PQC != nil {
			for _, f := range l.PQC.Features {
				add(l.ID, f)
			}
		}
	}
	for _, l := range rs.JavaLibraries {
		if l.PQC != nil {
			for _, f := range l.PQC.Features {
				add(l.ID, f)
			}
		}
	}
	for _, r := range rows {
		b.WriteString("| " + r.lib + " | " + r.target + " | " + strings.Join(features[r], "・") + " | " + r.since + " | " + r.checked + " | " + r.basis + " |\n")
	}
	b.WriteString("\n方式の名前: `TLS-MLKEM` は TLS の ML-KEM 単独の鍵交換、`TLS-MLKEM-hybrid` は TLS のハイブリッドの鍵交換（X25519MLKEM768 など）です。\n")

	b.WriteString("\n## ファイルの構成\n\n")
	b.WriteString("| 場所 | 内容 |\n|---|---|\n")
	b.WriteString("| `manifest.yaml` | ルールの版 |\n")
	b.WriteString("| `catalog/` | 暗号アルゴリズムの名前と別名（OID、OpenSSL の名前、SSH の名前など） |\n")
	b.WriteString("| `policies/` | 評価の基準（量子計算機への耐性、古典的な安全性） |\n")
	b.WriteString("| `apps/` | 対応しているソフトウェアの定義（設定ファイルの場所、読む項目） |\n")
	b.WriteString("| `defaults/` | ソフトウェアの既定値（パッケージの版ごと） |\n")
	b.WriteString("| `ciphers/`、`groups/` | OpenSSL の暗号スイートと鍵交換のグループの表（パッケージの版ごと） |\n")
	b.WriteString("| `java/` | JDK、Tomcat、Spring Boot の表 |\n")
	b.WriteString("| `libraries/` | 暗号ライブラリの見分け方と、耐量子のアルゴリズムに対応している版 |\n")
	b.WriteString("| `os/` | パッケージの役割、証明書ストアの場所 |\n")
	return b.String()
}
