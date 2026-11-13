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
	// 無効にする方式（jdk.tls.disabledAlgorithms）の解釈のうち、版によって違うところ
	Wildcard            bool `yaml:"wildcard"`               // 「TLS_RSA_*」のような名前のパターンを解釈する
	DisableGroupsByName bool `yaml:"disable_groups_by_name"` // グループの名前を書くと、そのグループを受け入れなくなる
	// TLS 1.2 以下の DHE で、クライアントが ffdhe のグループを示さないときに使う DH パラメータの長さ
	DHEDefaultBits int `yaml:"dhe_default_bits"`
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
	jdkUpstreamPattern = regexp.MustCompile(`^[0-9][0-9A-Za-z.+~]{0,47}$`)
	jdkGroupKeyPattern = regexp.MustCompile(`^(EC|DH) [1-9][0-9]{2,4}$`)
)

func (rs *RuleSet) addJDKTable(t *JDKTable, ids map[string]bool) error {
	if t == nil || !idPattern.MatchString(t.Runtime) || !jdkUpstreamPattern.MatchString(t.Upstream) {
		return errors.New("JDK table needs a runtime and an upstream version")
	}
	where := "JDK table for " + t.Runtime + " " + t.Upstream
	if err := checkBuilds("jdk", t.Runtime, t.Upstream, t.Builds, ids); err != nil {
		return fmt.Errorf("%s: %w", where, err)
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
