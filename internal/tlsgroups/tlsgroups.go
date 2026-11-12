// Package tlsgroups は、OpenSSL の鍵交換のグループの指定（Groups、Curves、-groups など）を、
// サーバーが受け入れるグループの一覧に解釈する。
//
// 指定の書き方の解釈、知っている名前と別名、既定で受け入れるグループは、パッケージ版ごとに実物で採取した対応表
// （ruleset.GroupTable）から得る。実物（各パッケージ版の openssl s_server）の結果と一致することを、テストで確かめている。
package tlsgroups

import (
	"errors"
	"strings"

	"kagiya/internal/ruleset"
)

// ErrInvalid は、その版の OpenSSL が拒否する指定（知らない名前、空の項目、重複、その版にない書き方）。
var ErrInvalid = errors.New("invalid group list")

// MaxSpecLen は、解釈する指定の長さの上限。
const MaxSpecLen = 8192

// Result は、グループの指定の解釈の結果。
type Result struct {
	Groups  []string // 受け入れるグループ（正式な名前、指定の順）
	TLS13   []string // そのうち、TLS 1.3 の鍵交換で使えるもの
	TLS12   []string // そのうち、TLS 1.2 以下の鍵交換（ECDHE）で使えるもの
	Ignored []string // 「?」付きで書かれていて、この版が知らないために無視された名前
}

// Resolve は、グループの指定 spec を、対応表 t の版の OpenSSL と同じように解釈する。spec が空なら、ライブラリの既定。
func Resolve(t *ruleset.GroupTable, spec string) (Result, error) {
	if len(spec) > MaxSpecLen {
		return Result{}, ErrInvalid
	}
	extended := t.Syntax == ruleset.GroupSyntaxExtended
	key := func(n string) string {
		if extended {
			return strings.ToLower(n) // この版は大文字小文字を区別しない
		}
		return n
	}
	byName := map[string]int{}
	var defaults []int
	for i, g := range t.Groups {
		byName[key(g.Name)] = i
		for _, a := range strings.Fields(g.Aliases) {
			byName[key(a)] = i
		}
		if g.Default {
			defaults = append(defaults, i)
		}
	}
	var order []int
	in := map[int]bool{}
	add := func(i int) {
		if !in[i] {
			in[i] = true
			order = append(order, i)
		}
	}
	var r Result
	if strings.TrimSpace(spec) == "" {
		for _, i := range defaults {
			add(i)
		}
	} else {
		items := strings.Split(spec, ":")
		if extended {
			items = strings.FieldsFunc(spec, func(c rune) bool { return c == ':' || c == '/' })
			// 区切りの前後や連続（空の項目）は拒否される
			if n := strings.Count(spec, ":") + strings.Count(spec, "/"); n+1 != len(items) {
				return Result{}, ErrInvalid
			}
		}
		for _, raw := range items {
			item := strings.TrimSpace(raw)
			if item == "" {
				return Result{}, ErrInvalid
			}
			optional, remove := false, false
			if extended {
				for len(item) > 0 && strings.ContainsRune("?*-", rune(item[0])) {
					optional = optional || item[0] == '?'
					remove = remove || item[0] == '-'
					item = item[1:]
				}
				if item == "DEFAULT" {
					for _, i := range defaults {
						add(i)
					}
					continue
				}
			}
			i, known := byName[key(item)]
			switch {
			case !known && (optional || remove):
				if optional {
					r.Ignored = append(r.Ignored, item)
				}
			case !known:
				return Result{}, ErrInvalid
			case remove:
				if in[i] {
					delete(in, i)
					for k, x := range order {
						if x == i {
							order = append(order[:k], order[k+1:]...)
							break
						}
					}
				}
			case in[i] && !extended:
				return Result{}, ErrInvalid // 同じグループを2回書くと拒否される
			default:
				add(i)
			}
		}
	}
	if len(order) == 0 {
		return Result{}, ErrInvalid
	}
	for _, i := range order {
		g := t.Groups[i]
		r.Groups = append(r.Groups, g.Name)
		if g.TLS13 {
			r.TLS13 = append(r.TLS13, g.Name)
		}
		if g.TLS12 {
			r.TLS12 = append(r.TLS12, g.Name)
		}
	}
	return r, nil
}

// Usable は、グループの一覧を、セキュリティレベル level で受け入れられるものに絞る。level が負なら絞らない。
// そのレベルでの測定ができていない版では絞り込めないので、ok = false を返す。
// レベルごとの測定で確かめられていないグループは、落とさずに残す。
func Usable(t *ruleset.GroupTable, groups []string, level int) (usable []string, ok bool) {
	if level < 0 {
		return append([]string{}, groups...), true
	}
	if level > t.MeasuredLevels {
		return nil, false
	}
	max := map[string]*int{}
	for _, g := range t.Groups {
		max[g.Name] = g.Level
	}
	for _, n := range groups {
		if m := max[n]; m == nil || *m >= level {
			usable = append(usable, n)
		}
	}
	return usable, true
}
