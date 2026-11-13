// このファイルは、JDK の TLS（JSSE）の対応表の読み込みと検索。

package ruleset

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// JDKName は、名前と「制限をすべて外したときにサーバーで有効か」の組（プロトコル、暗号スイート）。
type JDKName struct {
	Name    string `yaml:"name"`
	Default bool   `yaml:"default"`
}

// JDKGroup は、制限をすべて外したときに JDK が受け入れる鍵交換のグループ 1 つ。
type JDKGroup struct {
	Name  string `yaml:"name"`  // 本体での正式な名前（rules/groups と同じ表記）
	JSSE  string `yaml:"jsse"`  // Java での名前（設定に書く名前）
	ID    int    `yaml:"id"`    // TLS での番号（測った事実）
	TLS13 bool   `yaml:"tls13"` // TLS 1.3 の鍵交換で受け入れる
	TLS12 bool   `yaml:"tls12"` // TLS 1.2 以下の鍵交換（ECDHE）で受け入れる
	Key   string `yaml:"key"`   // 鍵長の条件に当てはめるときの種類と長さ（「EC 256」）。空なら、鍵長の条件に当たらない
}

// JDKTable は、JDK のあるパッケージ版での、TLS の対応表。出典が必須。
type JDKTable struct {
	Runtime  string        `yaml:"runtime"`
	Upstream string        `yaml:"upstream"`
	Builds   []CipherBuild `yaml:"builds"`
	// 開発元の版（JDK のディレクトリにある release ファイルの JAVA_VERSION と同じ値）。配布元をまたぐ補間（JDKTableForJavaVersion）に使う
	JavaVersion string `yaml:"java_version"`
	// 無効にする方式（jdk.tls.disabledAlgorithms）の解釈のうち、版によって違うところ
	Wildcard            bool `yaml:"wildcard"`               // 「TLS_RSA_*」のような名前のパターンを解釈する
	DisableGroupsByName bool `yaml:"disable_groups_by_name"` // グループの名前を書くと、そのグループを受け入れなくなる
	// TLS 1.2 以下の DHE で、クライアントが ffdhe のグループを示さないときに使う DH パラメータの長さ
	DHEDefaultBits int `yaml:"dhe_default_bits"`
	// 暗号ポリシーとのつなぎ方（RHEL 系）。どちらも、その読み方で JDK 自身の報告を再現できた版にだけ付く
	SystemPropertiesFile bool `yaml:"system_properties_file"` // security.useSystemPropertiesFile=true で、暗号ポリシーの java.config が上書きする
	SecurityInclude      bool `yaml:"security_include"`       // java.security の include での取り込みを確かめた
	// jdk.tls.namedGroups で名前を挙げても受け入れなかったグループ（Java での名前。測った範囲で）
	UnusableGroups []string   `yaml:"unusable_groups"`
	Protocols      []JDKName  `yaml:"protocols"`
	Suites         []JDKName  `yaml:"suites"`
	Groups         []JDKGroup `yaml:"groups"`
}

type jdkFile struct {
	JDKTables []*JDKTable `yaml:"jdk_tables"`
}

var (
	// パッケージ版の「-」より前。Debian 系の版には「+」「~」が入る（21.0.13+9、11.0.27+6~us1）
	jdkUpstreamPattern    = regexp.MustCompile(`^[0-9][0-9A-Za-z.+~]{0,47}$`)
	jdkJavaVersionPattern = regexp.MustCompile(`^[0-9][0-9A-Za-z._]{0,31}$`)
	jdkGroupKeyPattern    = regexp.MustCompile(`^(EC|DH) [1-9][0-9]{2,4}$`)
)

func (rs *RuleSet) addJDKTable(t *JDKTable, ids map[string]bool) error {
	if t == nil || !idPattern.MatchString(t.Runtime) || !jdkUpstreamPattern.MatchString(t.Upstream) {
		return errors.New("JDK table needs a runtime and an upstream version")
	}
	where := "JDK table for " + t.Runtime + " " + t.Upstream
	if err := checkBuilds("jdk", t.Runtime, t.Upstream, t.Builds, ids); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	if t.JavaVersion != "" && !jdkJavaVersionPattern.MatchString(t.JavaVersion) {
		return fmt.Errorf("%s: invalid java_version", where)
	}
	if t.DHEDefaultBits < 512 || t.DHEDefaultBits > 16384 {
		return fmt.Errorf("%s: invalid dhe_default_bits", where)
	}
	checkNames := func(what string, list []JDKName, max int) error {
		if len(list) == 0 || len(list) > max {
			return fmt.Errorf("%s: invalid number of %s", where, what)
		}
		seen := map[string]bool{}
		hasDefault := false
		for _, n := range list {
			if !suiteNamePattern.MatchString(n.Name) || seen[n.Name] {
				return fmt.Errorf("%s: invalid or duplicate %s %q", where, what, n.Name)
			}
			seen[n.Name] = true
			hasDefault = hasDefault || n.Default
		}
		if !hasDefault {
			return fmt.Errorf("%s: no default in %s", where, what)
		}
		return nil
	}
	if err := checkNames("protocols", t.Protocols, 16); err != nil {
		return err
	}
	if err := checkNames("suites", t.Suites, 500); err != nil {
		return err
	}
	if len(t.Groups) == 0 || len(t.Groups) > 200 {
		return fmt.Errorf("%s: invalid number of groups", where)
	}
	names, jsse := map[string]bool{}, map[string]bool{}
	for _, g := range t.Groups {
		// Java は名前の大文字小文字を区別しないので、区別しない形で重なりを確かめる
		j := strings.ToLower(g.JSSE)
		if !suiteNamePattern.MatchString(g.Name) || !suiteNamePattern.MatchString(g.JSSE) || names[g.Name] || jsse[j] {
			return fmt.Errorf("%s: invalid or duplicate group %q (%q)", where, g.Name, g.JSSE)
		}
		names[g.Name], jsse[j] = true, true
		if g.ID <= 0 || g.ID > 0xffff || (!g.TLS13 && !g.TLS12) {
			return fmt.Errorf("%s: group %s: invalid id or not accepted in any protocol", where, g.Name)
		}
		if g.Key != "" && !jdkGroupKeyPattern.MatchString(g.Key) {
			return fmt.Errorf("%s: group %s: invalid key %q", where, g.Name, g.Key)
		}
	}
	for _, n := range t.UnusableGroups {
		if !suiteNamePattern.MatchString(n) || jsse[strings.ToLower(n)] {
			return fmt.Errorf("%s: invalid unusable group %q", where, n)
		}
	}
	rs.JDKTables = append(rs.JDKTables, t)
	return nil
}

// JDKTableFor は、JDK のパッケージ版に対応する対応表と、その実測元を返す。
// 引き方と補間の条件は、暗号スイートの対応表（CipherTableFor）と同じ。
func (rs *RuleSet) JDKTableFor(runtime, pkg, version string) (t *JDKTable, build CipherBuild, exact, ok bool) {
	i, build, exact, ok := findBuild(runtime, pkg, version, len(rs.JDKTables), func(i int) (string, string, []CipherBuild) {
		tb := rs.JDKTables[i]
		return tb.Runtime, tb.Upstream, tb.Builds
	})
	if !ok {
		return nil, CipherBuild{}, false, false
	}
	return rs.JDKTables[i], build, exact, true
}

// ValidJavaVersion は、文字列が JDK の開発元の版の形（21.0.13、1.8.0_512 など）かを返す。
func ValidJavaVersion(v string) bool { return jdkJavaVersionPattern.MatchString(v) }

// JDKTableForJavaVersion は、開発元の版（release ファイルの JAVA_VERSION）が同じ JDK の表を返す。
//
// 配布元をまたぐ補間で、JDK の表だけの扱い。「開発元の版が同じなら、配布元が違っても表の中身は同じ」ことを、
// 配布元の公式イメージの JDK（Temurin、Corretto）の実測で確かめたうえで使っている（rules/java/openjdk.yaml の冒頭に記録）。
// 暗号スイートやグループの対応表、アプリの既定値表は、この引き方をしない（findBuild の条件は変えていない）。
//
//   - 版は完全に一致するものだけ（21.0.13 と 21.0.13.0.3 は別の版）。
//   - 同じ版の表が複数あり、中身が食い違う場合は返さない。
//   - 暗号ポリシーとのつなぎ方（SystemPropertiesFile、SecurityInclude）は、測ったディストリの JDK のものなので、引き継がない
//     （返すのは写しで、元の表は変えない）。
//
// 呼び出し側は、補間であることを結果に残し、確度を下げること。
func (rs *RuleSet) JDKTableForJavaVersion(runtime, javaVersion string) (t *JDKTable, build CipherBuild, ok bool) {
	if !jdkJavaVersionPattern.MatchString(javaVersion) {
		return nil, CipherBuild{}, false
	}
	var first *JDKTable
	for _, tb := range rs.JDKTables {
		if tb.Runtime != runtime || tb.JavaVersion != javaVersion {
			continue
		}
		if first == nil {
			first = tb
			continue
		}
		if !sameJDKContents(first, tb) {
			return nil, CipherBuild{}, false
		}
	}
	if first == nil {
		return nil, CipherBuild{}, false
	}
	c := *first
	c.SystemPropertiesFile, c.SecurityInclude = false, false
	return &c, first.Builds[0], true
}

// sameJDKContents は、2 つの表の中身（暗号ポリシーとのつなぎ方を除く）が同じかを返す。
func sameJDKContents(a, b *JDKTable) bool {
	if a.Wildcard != b.Wildcard || a.DisableGroupsByName != b.DisableGroupsByName || a.DHEDefaultBits != b.DHEDefaultBits ||
		strings.Join(a.UnusableGroups, ",") != strings.Join(b.UnusableGroups, ",") ||
		len(a.Protocols) != len(b.Protocols) || len(a.Suites) != len(b.Suites) || len(a.Groups) != len(b.Groups) {
		return false
	}
	for i := range a.Protocols {
		if a.Protocols[i] != b.Protocols[i] {
			return false
		}
	}
	for i := range a.Suites {
		if a.Suites[i] != b.Suites[i] {
			return false
		}
	}
	for i := range a.Groups {
		if a.Groups[i] != b.Groups[i] {
			return false
		}
	}
	return true
}
