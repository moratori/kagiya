// このファイルは、証明書ストアの場所の定義の読み込みと検索。

package ruleset

import (
	"fmt"
	"sort"
	"strings"
)

// Store は証明書ストアの場所の定義。出典（Sources）が必須。
type Store struct {
	ID      string   `yaml:"id"`
	Paths   []string `yaml:"paths"`
	Sources []Source `yaml:"sources"`
}

type storesFile struct {
	Stores []Store `yaml:"stores"`
}

func (rs *RuleSet) addStore(s Store, ids map[string]bool) error {
	if !idPattern.MatchString(s.ID) {
		return fmt.Errorf("invalid store id %q", s.ID)
	}
	key := "store\x00" + s.ID
	if ids[key] {
		return fmt.Errorf("duplicate store id %q", s.ID)
	}
	ids[key] = true
	if len(s.Paths) == 0 {
		return fmt.Errorf("store %q: no paths", s.ID)
	}
	// 出典のない定義は受け付けない。
	if err := checkSources(s.Sources); err != nil {
		return fmt.Errorf("store %q: %w", s.ID, err)
	}
	for _, p := range s.Paths {
		if !cleanAbsPath(p) {
			return fmt.Errorf("store %q: path %q must be a clean absolute path", s.ID, p)
		}
		if _, dup := rs.storePaths[p]; dup {
			return fmt.Errorf("store %q: path %q is already assigned to a store", s.ID, p)
		}
		rs.storePaths[p] = s.ID
	}
	rs.Stores = append(rs.Stores, s)
	return nil
}

// StoreFor は、パスが属する証明書ストアの ID を返す（最も深い定義が優先）。どれにも属さなければ空。
func (rs *RuleSet) StoreFor(path string) string {
	for p := path; len(p) > 1; {
		if id, ok := rs.storePaths[p]; ok {
			return id
		}
		i := strings.LastIndexByte(p, '/')
		if i <= 0 {
			break
		}
		p = p[:i]
	}
	return ""
}

// StorePaths は定義されているストアの場所の一覧（整列済み）。
func (rs *RuleSet) StorePaths() []string {
	out := make([]string, 0, len(rs.storePaths))
	for p := range rs.storePaths {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
