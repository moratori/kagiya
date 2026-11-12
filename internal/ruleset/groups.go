// このファイルは、暗号ライブラリの鍵交換のグループの対応表の読み込みと検索。

package ruleset

import (
	"errors"
	"fmt"
	"strings"
)

// Group は、鍵交換のグループ1つ（TLS の supported_groups）。
type Group struct {
	Name    string `yaml:"name"`    // 正式な名前
	Aliases string `yaml:"aliases"` // 同じグループを指す別の名前（空白区切り）
	TLS13   bool   `yaml:"tls13"`   // TLS 1.3 の鍵交換で使える
	TLS12   bool   `yaml:"tls12"`   // TLS 1.2 以下の鍵交換（ECDHE）で使える
	// そのグループを受け入れる最大のセキュリティレベル（測定できた範囲で）。nil は、レベルごとの測定で確かめられていない
	Level   *int `yaml:"level"`
	Default bool `yaml:"default"` // 何も指定しないときに受け入れる
}

// グループの指定の書き方。
const (
	GroupSyntaxBasic    = "basic"    // 「:」区切りだけ。名前は大文字小文字を区別し、同じグループを2回書くと拒否される
	GroupSyntaxExtended = "extended" // 「/」での区切り、接頭辞（? * -）、DEFAULT が使える。名前は大文字小文字を区別しない
)

// GroupTable は、暗号ライブラリのあるパッケージ版での、鍵交換のグループの対応表。出典が必須。
type GroupTable struct {
	Library        string        `yaml:"library"`
	Upstream       string        `yaml:"upstream"`
	Builds         []CipherBuild `yaml:"builds"`
	Syntax         string        `yaml:"syntax"`
	MeasuredLevels int           `yaml:"measured_levels"` // セキュリティレベルごとの測定ができた最大のレベル
	Groups         []Group       `yaml:"groups"`          // 既定で受け入れるものを、既定の並びの順で先に置く
}

type groupFile struct {
	GroupTables []*GroupTable `yaml:"group_tables"`
}

func (rs *RuleSet) addGroupTable(t *GroupTable, ids map[string]bool) error {
	if t == nil || !idPattern.MatchString(t.Library) || !upstreamPattern.MatchString(t.Upstream) {
		return errors.New("group table needs a library and an upstream version")
	}
	where := "group table for " + t.Library + " " + t.Upstream
	if err := checkBuilds("group", t.Library, t.Upstream, t.Builds, ids); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	if t.Syntax != GroupSyntaxBasic && t.Syntax != GroupSyntaxExtended {
		return fmt.Errorf("%s: unknown syntax %q", where, t.Syntax)
	}
	if t.MeasuredLevels < 0 || t.MeasuredLevels > 5 {
		return fmt.Errorf("%s: invalid measured_levels", where)
	}
	if len(t.Groups) == 0 || len(t.Groups) > 500 {
		return fmt.Errorf("%s: invalid number of groups", where)
	}
	names := map[string]int{} // 名前 → グループの位置
	hasDefault := false
	for i, g := range t.Groups {
		for _, n := range append([]string{g.Name}, strings.Fields(g.Aliases)...) {
			// extended の版は大文字小文字を区別しないので、区別しない形で重なりを確かめる。
			// 同じグループの中での表記の違い（X25519 と x25519）は構わない。別のグループと重なる名前は受け付けない
			key := n
			if t.Syntax == GroupSyntaxExtended {
				key = strings.ToLower(n)
			}
			if !suiteNamePattern.MatchString(n) {
				return fmt.Errorf("%s: invalid group name %q", where, n)
			}
			if j, seen := names[key]; seen && (j != i || t.Syntax != GroupSyntaxExtended) {
				return fmt.Errorf("%s: duplicate group name %q", where, n)
			}
			names[key] = i
		}
		if g.Level != nil && (*g.Level < 0 || *g.Level > t.MeasuredLevels) {
			return fmt.Errorf("%s: group %s: invalid level", where, g.Name)
		}
		hasDefault = hasDefault || g.Default
	}
	if !hasDefault {
		return fmt.Errorf("%s: no default group", where)
	}
	rs.GroupTables = append(rs.GroupTables, t)
	return nil
}

// GroupTableFor は、暗号ライブラリのパッケージ版に対応する、鍵交換のグループの対応表と、その実測元を返す。
// 引き方と補間の条件は、暗号スイートの対応表（CipherTableFor）と同じ。
func (rs *RuleSet) GroupTableFor(library, pkg, version string) (t *GroupTable, build CipherBuild, exact, ok bool) {
	i, build, exact, ok := findBuild(library, pkg, version, len(rs.GroupTables), func(i int) (string, string, []CipherBuild) {
		tb := rs.GroupTables[i]
		return tb.Library, tb.Upstream, tb.Builds
	})
	if !ok {
		return nil, CipherBuild{}, false, false
	}
	return rs.GroupTables[i], build, exact, true
}
