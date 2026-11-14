// Package shellconf は、シェルが取り込む（source する）設定ファイルのうち、「名前=値」が並ぶ単純なものを読む。
// シェルとしては実行しない。展開（変数、コマンドの置き換えなど）を含む値は「決まらない」とし、代入でない行があれば
// 全体を読めないものとして扱う。値を返すのは、呼び出し側が指定した名前だけ（それ以外は、代入があったことだけ）。
package shellconf

import "strings"

const (
	MaxSize = 64 << 10 // これより大きいファイルは読まない
	MaxLine = 4096     // これより長い行があれば読まない
)

// Result は、読み取った結果。
type Result struct {
	Values   map[string]string // 指定した名前のうち、値が決まったもの
	Unknown  map[string]bool   // 代入はあるが、値が決まらないもの（展開を含む）
	Assigned map[string]bool   // 代入があった名前すべて
	Opaque   int               // 0 でなければ、解釈できない行（代入でない行など）の番号。このとき、ほかの項目は当てにできない
}

// Parse は、設定ファイルを読む。names は、値を取り出す名前。
func Parse(data []byte, names ...string) Result {
	r := Result{Values: map[string]string{}, Unknown: map[string]bool{}, Assigned: map[string]bool{}}
	if len(data) > MaxSize {
		r.Opaque = 1
		return r
	}
	wanted := map[string]bool{}
	for _, n := range names {
		wanted[n] = true
	}
	for i, raw := range strings.Split(string(data), "\n") {
		if len(raw) > MaxLine || strings.ContainsRune(raw, 0) {
			r.Opaque = i + 1
			return r
		}
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "export"); ok && rest != "" && (rest[0] == ' ' || rest[0] == '\t') {
			line = strings.TrimLeft(rest, " \t")
		}
		name, rest, ok := cutName(line)
		if !ok {
			r.Opaque = i + 1
			return r
		}
		w := scanWord(rest)
		tail := strings.TrimLeft(rest[w.end:], " \t")
		switch {
		case !w.closed, tail != "" && tail[0] != '#', !w.simple && strings.ContainsAny(rest[:w.end], ";&|<>"):
			// 閉じていない引用符、値の後ろに続くコマンド、複数の文
			r.Opaque = i + 1
			return r
		case !w.simple:
			delete(r.Values, name)
			r.Unknown[name] = true
		default:
			delete(r.Unknown, name)
			if wanted[name] {
				r.Values[name] = w.value
			}
		}
		r.Assigned[name] = true
	}
	return r
}

// cutName は、行の先頭の「名前=」を切り出す。
func cutName(line string) (name, rest string, ok bool) {
	i := 0
	for ; i < len(line); i++ {
		c := line[i]
		if c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (i > 0 && c >= '0' && c <= '9') {
			continue
		}
		break
	}
	if i == 0 || i >= len(line) || line[i] != '=' {
		return "", "", false
	}
	return line[:i], line[i+1:], true
}

type word struct {
	end    int    // 語の終わり（空白の手前）
	closed bool   // 引用符や括弧が閉じている
	simple bool   // 展開を含まない、1 つの部分だけの語（そのままの文字、'...'、"..." のいずれか）
	value  string // simple のときの値
}

// 引用符の外で、シェルが特別に扱う文字。
const special = "(){}*?[]~#!;&|<>"

// scanWord は、シェルの語を 1 つ読む（値は展開しない。展開が要るかどうかを見分けるだけ）。
func scanWord(s string) word {
	w := word{closed: true, simple: true}
	parts := 0
	i := 0
	// until は、s[i] から始まる区切りの、対応する閉じを探して、その次の位置へ進める。なければ閉じていない
	until := func(open, close byte) {
		depth := 0
		for ; i < len(s); i++ {
			switch {
			case s[i] == '\\':
				i++
			case s[i] == open:
				depth++
			case s[i] == close:
				if depth--; depth <= 0 {
					i++
					return
				}
			}
		}
		w.closed = false
	}
	for i < len(s) && s[i] != ' ' && s[i] != '\t' {
		parts++
		start := i
		switch c := s[i]; {
		case c == '\'':
			i++
			if j := strings.IndexByte(s[i:], '\''); j >= 0 {
				w.value = s[i : i+j]
				i += j + 1
			} else {
				w.closed, i = false, len(s)
			}
		case c == '"':
			i++
			j := i
			for ; j < len(s) && s[j] != '"'; j++ {
				if s[j] == '\\' {
					j++
				}
			}
			if j >= len(s) {
				w.closed, i = false, len(s)
				break
			}
			w.value = s[i:j]
			if strings.ContainsAny(w.value, "$`\\") {
				w.simple = false
			}
			i = j + 1
		case c == '\\':
			w.simple = false
			i += 2
		case c == '`':
			w.simple = false
			i++
			if j := strings.IndexByte(s[i:], '`'); j >= 0 {
				i += j + 1
			} else {
				w.closed, i = false, len(s)
			}
		case c == '$':
			w.simple = false
			i++
			if i < len(s) && s[i] == '(' {
				until('(', ')')
			} else if i < len(s) && s[i] == '{' {
				until('{', '}')
			}
		default:
			for i < len(s) && !strings.ContainsRune(" \t'\"\\`$", rune(s[i])) {
				if strings.IndexByte(special, s[i]) >= 0 {
					w.simple = false
				}
				i++
			}
			w.value = s[start:i]
		}
	}
	if i > len(s) {
		i = len(s)
	}
	if parts > 1 {
		w.simple = false
	}
	if !w.simple {
		w.value = ""
	}
	w.end = i
	return w
}
