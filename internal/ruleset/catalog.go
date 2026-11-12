// このファイルは、暗号カタログ（アルゴリズムの正規 ID と別名）の読み込みと検索。

package ruleset

import (
	"fmt"
	"strings"
)

// Algorithm は暗号カタログの1エントリ。
type Algorithm struct {
	ID         string              `yaml:"id"`
	Family     string              `yaml:"family"`
	Primitive  string              `yaml:"primitive"`
	KeyBits    int                 `yaml:"key_bits"`
	Aliases    map[string][]string `yaml:"aliases"`
	References []string            `yaml:"references"`
}

type catalogFile struct {
	Algorithms []Algorithm `yaml:"algorithms"`
}

func (rs *RuleSet) add(a Algorithm, ids map[string]bool) error {
	if !idPattern.MatchString(a.ID) {
		return fmt.Errorf("invalid algorithm id %q", a.ID)
	}
	if ids[a.ID] {
		return fmt.Errorf("duplicate algorithm id %q", a.ID)
	}
	ids[a.ID] = true
	if !textPattern.MatchString(a.Family) {
		return fmt.Errorf("algorithm %q: missing or invalid family", a.ID)
	}
	if !primitives[a.Primitive] {
		return fmt.Errorf("algorithm %q: unknown primitive %q", a.ID, a.Primitive)
	}
	if a.KeyBits < 0 || a.KeyBits > 1<<20 {
		return fmt.Errorf("algorithm %q: invalid key_bits", a.ID)
	}
	for _, r := range a.References {
		if !textPattern.MatchString(r) {
			return fmt.Errorf("algorithm %q: invalid reference", a.ID)
		}
	}
	idx := len(rs.Algorithms)
	for scheme, names := range a.Aliases {
		if !idPattern.MatchString(scheme) {
			return fmt.Errorf("algorithm %q: invalid alias scheme %q", a.ID, scheme)
		}
		for _, n := range names {
			if !aliasPattern.MatchString(n) {
				return fmt.Errorf("algorithm %q: invalid alias %q", a.ID, n)
			}
			k := aliasKey(scheme, n)
			if _, dup := rs.byAlias[k]; dup {
				return fmt.Errorf("algorithm %q: alias %s:%s is already used", a.ID, scheme, n)
			}
			rs.byAlias[k] = idx
		}
	}
	rs.Algorithms = append(rs.Algorithms, a)
	return nil
}

func aliasKey(scheme, name string) string {
	return scheme + "\x00" + strings.ToLower(name)
}

// LookupAlias は命名体系（oid, jca, ...）と名前からカタログのエントリを引く。大文字小文字は区別しない。
func (rs *RuleSet) LookupAlias(scheme, name string) (Algorithm, bool) {
	i, ok := rs.byAlias[aliasKey(scheme, name)]
	if !ok {
		return Algorithm{}, false
	}
	return rs.Algorithms[i], true
}
