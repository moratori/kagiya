package safefs

import (
	"fmt"
	"regexp"
	"strings"
)

// Excludes はスキャン除外パターンの集合。
// パターンはグロブ: `*` は1要素内の任意列、`?` は1文字、`**` は要素をまたぐ任意列。
// `/` を含まないパターンはファイル名（パスの最後の要素）に対して照合する。
type Excludes struct {
	full, base []*regexp.Regexp
}

func NewExcludes(patterns []string) (*Excludes, error) {
	ex := &Excludes{}
	for _, p := range patterns {
		if p == "" {
			return nil, fmt.Errorf("empty exclude pattern")
		}
		re, err := regexp.Compile("^" + globToRegexp(p) + "$")
		if err != nil {
			return nil, fmt.Errorf("exclude pattern %q: %w", p, err)
		}
		if strings.Contains(p, "/") {
			ex.full = append(ex.full, re)
		} else {
			ex.base = append(ex.base, re)
		}
	}
	return ex, nil
}

// Match はパス（`/` 区切りの絶対パス）が除外対象かを返す。
func (ex *Excludes) Match(path string) bool {
	if ex == nil {
		return false
	}
	for _, re := range ex.full {
		if re.MatchString(path) {
			return true
		}
	}
	if len(ex.base) > 0 {
		name := path[strings.LastIndex(path, "/")+1:]
		for _, re := range ex.base {
			if re.MatchString(name) {
				return true
			}
		}
	}
	return false
}

func globToRegexp(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); {
		switch {
		case strings.HasPrefix(p[i:], "**/"):
			b.WriteString(`(?:.*/)?`)
			i += 3
		case strings.HasPrefix(p[i:], "**"):
			b.WriteString(`.*`)
			i += 2
		case p[i] == '*':
			b.WriteString(`[^/]*`)
			i++
		case p[i] == '?':
			b.WriteString(`[^/]`)
			i++
		default:
			j := i + 1
			for j < len(p) && p[j] != '*' && p[j] != '?' {
				j++
			}
			b.WriteString(regexp.QuoteMeta(p[i:j]))
			i = j
		}
	}
	return b.String()
}
