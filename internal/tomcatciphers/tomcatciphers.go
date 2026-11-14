// Package tomcatciphers は、Tomcat の暗号指定（server.xml の ciphers。OpenSSL の書き方）を、スイートの一覧に直す。
//
// Tomcat は、この書き方を OpenSSL に渡さず、自分の持つ表で解釈する（JDK の実装で動く場合）。
// どの語がどのスイートを指すかは Tomcat の版ごとに違うので、版ごとに実物で採取した表（rules/java/tomcat.yaml）に従う。
// ここにあるのは式の読み方だけで、Tomcat 自身の解釈結果と、版ごとに約 5,200 の式で突き合わせて確かめている。
//
// 求めるのは、スイートの集合。並び順（+語 で後ろへ送る順、@STRENGTH の並べ替え）は版によって違い、再現していない。
package tomcatciphers

import (
	"strings"

	"kagiya/internal/ruleset"
)

const (
	maxExpression = 8192 // 解釈する式の長さの上限
	maxElements   = 512  // 解釈する要素の数の上限
)

// Expand は、暗号指定を解釈し、当てはまるスイートの Java での名前を返す（重なりなし）。
// 上限を超える式は解釈せず、空を返す。
func Expand(t *ruleset.TomcatTable, expr string) []string {
	if t == nil || len(expr) > maxExpression {
		return nil
	}
	elements := strings.FieldsFunc(expr, func(r rune) bool { return r == ':' || r == ',' || r == ' ' })
	if len(elements) > maxElements {
		return nil
	}
	n := len(t.Suites)
	in := make([]bool, n)      // いま一覧にあるか
	removed := make([]bool, n) // ! で外したもの（後から足しても戻らない）
	var order []int            // 足した順
	add := func(idx []int) {
		for _, i := range idx {
			if !in[i] {
				in[i] = true
				order = append(order, i)
			}
		}
	}
loop:
	for _, el := range elements {
		switch {
		case strings.HasPrefix(el, "-"):
			if idx, ok := t.Word(el[1:]); ok {
				for _, i := range idx {
					in[i] = false
				}
			}
		case strings.HasPrefix(el, "!"):
			if idx, ok := t.Word(el[1:]); ok {
				for _, i := range idx {
					removed[i] = true
				}
			}
		case strings.HasPrefix(el, "+"):
			// 後ろへ送るだけで、集合は変わらない
		case el == "@STRENGTH":
			// 並べ替えるだけで、集合は変わらない。この後ろの要素を読まない版がある
			if t.StrengthEnds {
				break loop
			}
		default:
			if idx, ok := t.Word(el); ok {
				add(idx)
				continue
			}
			if !strings.Contains(el, "+") {
				continue // 知らない語は読み飛ばす
			}
			// 「A+B」: どちらにも当てはまるもの。先頭が知らない語なら全体を読み飛ばし、2 つ目以降の知らない語は条件から外す
			parts := strings.Split(el, "+")
			first, ok := t.Word(parts[0])
			if !ok {
				continue
			}
			keep := append([]int{}, first...)
			for _, p := range parts[1:] {
				idx, ok := t.Word(p)
				if !ok {
					continue
				}
				has := make(map[int]bool, len(idx))
				for _, i := range idx {
					has[i] = true
				}
				k := keep[:0]
				for _, i := range keep {
					if has[i] {
						k = append(k, i)
					}
				}
				keep = k
			}
			add(keep)
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, i := range order {
		if !in[i] || removed[i] {
			continue
		}
		for _, name := range t.Suites[i].JSSE {
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}
