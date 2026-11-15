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

// syntax は、グループの指定の書き方の決まり（版によって違う。ruleset の GroupSyntax〜 に対応する）。
type syntax struct {
	separators      string // 項目の区切りに使える文字
	prefixes        string // 名前の前に付けられる記号（「?」= 知らない名前なら無視、「-」= それまでの並びから取り除く、「*」= 受け入れには関係しない印）
	multiplePrefix  bool   // 記号を、いくつも重ねて書ける。false なら 1 つだけで、その後ろは、そのまま名前として扱う
	defaultKeyword  bool   // 「DEFAULT」（既定の並びを足す）が使える
	caseInsensitive bool   // 名前の大文字小文字を区別しない
	repeatable      bool   // 同じグループを 2 回書いてもよい（2 回目は無視される）。false なら、拒否される
}

var syntaxes = map[string]syntax{
	ruleset.GroupSyntaxBasic:    {separators: ":"},
	ruleset.GroupSyntaxOptional: {separators: ":", prefixes: "?", repeatable: true},
	ruleset.GroupSyntaxExtended: {separators: ":/", prefixes: "?*-", multiplePrefix: true, defaultKeyword: true, caseInsensitive: true, repeatable: true},
}

// item は、指定の中の 1 つの項目を、記号と名前に分けたもの。
type item struct {
	name     string
	optional bool // 「?」: 知らない名前なら無視する
	remove   bool // 「-」: それまでの並びから取り除く
}

// parseItem は、項目 1 つを、記号と名前に分ける。
func (sx syntax) parseItem(text string) item {
	it := item{name: text}
	for it.name != "" && strings.IndexByte(sx.prefixes, it.name[0]) >= 0 {
		it.optional = it.optional || it.name[0] == '?'
		it.remove = it.remove || it.name[0] == '-'
		it.name = it.name[1:]
		if !sx.multiplePrefix {
			break
		}
	}
	return it
}

// orderedSet は、グループ（対応表の中の位置）の、重複のない並び。
type orderedSet struct {
	order []int
	in    map[int]bool
}

func (s *orderedSet) add(i int) {
	if s.in == nil {
		s.in = map[int]bool{}
	}
	if !s.in[i] {
		s.in[i] = true
		s.order = append(s.order, i)
	}
}

func (s *orderedSet) remove(i int) {
	if !s.in[i] {
		return
	}
	delete(s.in, i)
	for k, x := range s.order {
		if x == i {
			s.order = append(s.order[:k], s.order[k+1:]...)
			return
		}
	}
}

// Resolve は、グループの指定 spec を、対応表 t の版の OpenSSL と同じように解釈する。spec が空なら、ライブラリの既定。
func Resolve(t *ruleset.GroupTable, spec string) (Result, error) {
	if len(spec) > MaxSpecLen {
		return Result{}, ErrInvalid
	}
	sx := syntaxes[t.Syntax]
	key := func(n string) string {
		if sx.caseInsensitive {
			return strings.ToLower(n)
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
	var chosen orderedSet
	var r Result
	if strings.TrimSpace(spec) == "" {
		for _, i := range defaults {
			chosen.add(i)
		}
	} else {
		// 区切りの前後や連続（空の項目）は、どの書き方でも拒否される
		for _, raw := range splitKeepEmpty(spec, sx.separators) {
			text := strings.TrimSpace(raw)
			if text == "" {
				return Result{}, ErrInvalid
			}
			it := sx.parseItem(text)
			if sx.defaultKeyword && it.name == "DEFAULT" {
				for _, i := range defaults {
					chosen.add(i)
				}
				continue
			}
			i, known := byName[key(it.name)]
			switch {
			case !known && it.optional:
				r.Ignored = append(r.Ignored, it.name)
			case !known && it.remove: // 知らない名前を取り除く指定は、何もしない
			case !known:
				return Result{}, ErrInvalid
			case it.remove:
				chosen.remove(i)
			case chosen.in[i] && !sx.repeatable:
				return Result{}, ErrInvalid
			default:
				chosen.add(i)
			}
		}
	}
	if len(chosen.order) == 0 {
		return Result{}, ErrInvalid
	}
	for _, i := range chosen.order {
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

// splitKeepEmpty は、text を、separators のどれかの文字で区切る。区切りの前後や連続による空の項目も、そのまま返す。
func splitKeepEmpty(text, separators string) []string {
	var out []string
	start := 0
	for i := 0; i < len(text); i++ {
		if strings.IndexByte(separators, text[i]) >= 0 {
			out = append(out, text[start:i])
			start = i + 1
		}
	}
	return append(out, text[start:])
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
