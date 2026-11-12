// Package tlsciphers は、OpenSSL の暗号文字列（HIGH:!aNULL など）を、実際の暗号スイートの一覧に展開する。
//
// 展開の手順は上流の ssl/ssl_ciph.c（ssl_cipher_process_rulestr、ssl_cipher_apply_rule、ssl_cipher_strength_sort、
// ssl_create_cipher_list）に従う。どの語がどのスイートを指すか、スイートの並び、強度、既定で有効なもの、
// セキュリティレベルごとに使えるものは、パッケージ版ごとに実物で採取した対応表（ruleset.CipherTable）から得る。
// 実物（各パッケージ版の openssl 自身）の展開結果と一致することを、テストで確かめている。
package tlsciphers

import (
	"errors"
	"strings"

	"kagiya/internal/ruleset"
)

var (
	// ErrNoCipherMatch は、展開した結果スイートが1つも残らない場合（OpenSSL も設定を拒否する）。
	ErrNoCipherMatch = errors.New("no cipher match")
	// ErrInvalidCommand は、「@」で始まる指定がこの版で使えない場合（OpenSSL も設定を拒否する）。
	ErrInvalidCommand = errors.New("invalid command in the cipher string")
	// ErrUnsupported は、この実装が展開しない書き方（SUITEB〜、長すぎる文字列）。
	ErrUnsupported = errors.New("this form of cipher string is not supported")
	// ErrProfileNeeded は、「PROFILE=SYSTEM」が書かれているが、暗号ポリシーの内容が渡されていない場合。
	ErrProfileNeeded = errors.New("PROFILE=SYSTEM needs the content of the system crypto policy")
)

// MaxRuleLen は、展開する暗号文字列の長さの上限。これを超えるものは展開しない（ErrUnsupported）。
const MaxRuleLen = 8192

// Expansion は暗号文字列の展開結果。
type Expansion struct {
	Suites  []string // TLS 1.2 以下のスイート（優先順）。TLS 1.3 のスイートは含まない
	Level   int      // @SECLEVEL= で指定されたセキュリティレベル。指定がなければ -1
	Ignored []string // この版が知らないために無視された語
}

type entry struct {
	idx    int // 対応表での位置
	active bool
}

type state struct {
	t        *ruleset.CipherTable
	list     []*entry // OpenSSL 内部の連結リストに対応する並び
	keywords map[string][]int
	names    map[string]int
	x        Expansion
}

// Expand は、暗号文字列 rule を対応表 t の版の OpenSSL と同じ手順で展開する。
// profile は、「PROFILE=SYSTEM」が指す暗号文字列（暗号ポリシーのファイルの内容）。読めていなければ nil。
func Expand(t *ruleset.CipherTable, rule string, profile *string) (Expansion, error) {
	if len(rule) > MaxRuleLen || (profile != nil && len(*profile) > MaxRuleLen) {
		return Expansion{Level: -1}, ErrUnsupported
	}
	s := &state{t: t, keywords: map[string][]int{}, names: map[string]int{}}
	s.x.Level = -1
	for i, c := range t.Suites {
		s.list = append(s.list, &entry{idx: i})
		s.names[c.Name] = i
		for _, k := range strings.Fields(c.Keywords) {
			s.keywords[k] = append(s.keywords[k], i)
		}
	}
	if t.StandardNames {
		for i, c := range t.Suites {
			if c.Standard != "" {
				if _, dup := s.names[c.Standard]; !dup {
					s.names[c.Standard] = i
				}
			}
		}
	}
	rest := rule
	const profileWord = "PROFILE=SYSTEM"
	if t.ProfileSystem != "" && strings.HasPrefix(rest, profileWord) {
		// RHEL 系: 先頭の PROFILE=SYSTEM は、暗号ポリシーのファイルの内容に置き換わる。後ろの規則はそのまま続く。
		if profile == nil {
			return s.x, ErrProfileNeeded
		}
		rest = *profile + rest[len(profileWord):]
	}
	if strings.HasPrefix(rest, "DEFAULT") {
		// 先頭の DEFAULT は既定の暗号文字列の展開に置き換わる。既定に含まれないスイートは、以後復活しない。
		in := map[int]bool{}
		for i, c := range t.Suites {
			if c.Default {
				in[i] = true
			}
		}
		s.apply('a', in)
		out := map[int]bool{}
		for i := range t.Suites {
			if !in[i] {
				out[i] = true
			}
		}
		s.apply('!', out)
		rest = rest[len("DEFAULT"):]
	}
	if err := s.process(rest); err != nil {
		return s.x, err
	}
	for _, e := range s.list {
		if e.active {
			s.x.Suites = append(s.x.Suites, t.Suites[e.idx].Name)
		}
	}
	if len(s.x.Suites) == 0 {
		return s.x, ErrNoCipherMatch
	}
	return s.x, nil
}

func isSeparator(c rune) bool { return c == ':' || c == ' ' || c == ',' || c == ';' }

func (s *state) process(text string) error {
	for _, item := range strings.FieldsFunc(text, isSeparator) {
		op := byte('a')
		switch item[0] {
		case '-', '+', '!':
			op, item = item[0], item[1:]
		case '@':
			if err := s.command(item[1:]); err != nil {
				return err
			}
			continue
		}
		if item == "" {
			continue
		}
		var match map[int]bool
		known := true
		for i, word := range strings.Split(item, "+") {
			if strings.HasPrefix(word, "SUITEB") {
				return ErrUnsupported // 暗号文字列全体を置き換える特別な動作で、展開しない
			}
			members, ok := s.lookup(word)
			if !ok {
				known = false
				break
			}
			if i == 0 {
				match = members
				continue
			}
			for k := range match {
				if !members[k] {
					delete(match, k)
				}
			}
		}
		if !known {
			// 知らない語を含む規則は、まるごと無視される
			s.x.Ignored = append(s.x.Ignored, item)
			continue
		}
		s.apply(op, match)
	}
	return nil
}

// lookup は、語が指すスイートを返す。語（HIGH など）か、スイートの名前。
func (s *state) lookup(word string) (map[int]bool, bool) {
	out := map[int]bool{}
	if m, ok := s.keywords[word]; ok {
		for _, i := range m {
			out[i] = true
		}
		return out, true
	}
	if i, ok := s.names[word]; ok {
		out[i] = true
		return out, true
	}
	// どちらでもない語は無視される。TLS 1.3 のスイートの名前も暗号文字列の対象外で、同じ扱いになる
	return nil, false
}

func (s *state) command(cmd string) error {
	switch {
	case cmd == "STRENGTH":
		// 強い順に、同じ強さのものを末尾へ送ることを繰り返す（結果として、有効なものが強さの順に安定に並ぶ）
		seen := map[int]bool{}
		var strengths []int
		for _, e := range s.list {
			if b := s.t.Suites[e.idx].Strength; e.active && !seen[b] {
				seen[b] = true
				strengths = append(strengths, b)
			}
		}
		for i := 1; i < len(strengths); i++ { // 降順に並べる（数が少ないので挿入ソート）
			for j := i; j > 0 && strengths[j] > strengths[j-1]; j-- {
				strengths[j], strengths[j-1] = strengths[j-1], strengths[j]
			}
		}
		for _, b := range strengths {
			m := map[int]bool{}
			for _, e := range s.list {
				if e.active && s.t.Suites[e.idx].Strength == b {
					m[e.idx] = true
				}
			}
			s.apply('+', m)
		}
		return nil
	case strings.HasPrefix(cmd, "SECLEVEL="):
		v := cmd[len("SECLEVEL="):]
		if !s.t.SecurityLevels || len(v) != 1 || v[0] < '0' || v[0] > '5' {
			return ErrInvalidCommand
		}
		s.x.Level = int(v[0] - '0')
		return nil
	}
	return ErrInvalidCommand
}

// apply は、規則1つを並びに適用する。
//
//	a（接頭辞なし）: 無効なものを有効にして末尾へ。すでに有効なものは動かさない。
//	+ : 有効なものを末尾へ動かす。
//	- : 有効なものを無効にして先頭へ（順は保つ）。後で足し直せる。
//	! : 並びから取り除く。以後、足し直せない。
func (s *state) apply(op byte, match map[int]bool) {
	var stay, moved []*entry
	for _, e := range s.list {
		hit := match[e.idx]
		switch {
		case op == '!' && hit:
			// 取り除く
		case op == 'a' && hit && !e.active:
			e.active = true
			moved = append(moved, e)
		case op == '+' && hit && e.active:
			moved = append(moved, e)
		case op == '-' && hit && e.active:
			e.active = false
			moved = append(moved, e)
		default:
			stay = append(stay, e)
		}
	}
	if op == '-' {
		s.list = append(moved, stay...)
		return
	}
	s.list = append(stay, moved...)
}

// DefaultTLS13 は、その版で既定で有効な TLS 1.3 のスイートを返す（優先順）。
func DefaultTLS13(t *ruleset.CipherTable) []string {
	var out []string
	for _, c := range t.TLS13 {
		if c.Default {
			out = append(out, c.Name)
		}
	}
	return out
}

// Usable は、スイートの一覧を、セキュリティレベル level で実際に使えるものに絞る。
// level が負なら、その版の既定のレベルを使う。レベルの仕組みがない版では絞り込めないので、ok = false を返す。
//
// アプリ側の追加の設定がないと使えないスイート（事前共有鍵の PSK、SRP）は、どのレベルでも落とす。
func Usable(t *ruleset.CipherTable, suites []string, level int) (usable []string, ok bool) {
	if !t.SecurityLevels || t.DefaultLevel == nil {
		return nil, false
	}
	if level < 0 {
		level = *t.DefaultLevel
	}
	max := map[string]int{}
	for _, list := range [][]ruleset.CipherSuite{t.TLS13, t.Suites} {
		for _, c := range list {
			if c.Level != nil {
				max[c.Name] = *c.Level
			}
		}
	}
	for _, n := range suites {
		if m, found := max[n]; found && level <= m {
			usable = append(usable, n)
		}
	}
	return usable, true
}
