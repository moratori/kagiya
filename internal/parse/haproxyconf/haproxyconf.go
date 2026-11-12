// Package haproxyconf は HAProxy の設定ファイルを読む。
//
// 文法: 1行に1項目。「#」以降はコメント（引用符の中と、バックスラッシュで逃がしたものを除く）。
// 語は空白で区切り、引用符（" と '）とバックスラッシュで空白を含められる。
// 節（global、defaults、frontend、listen、backend など）は、その語で始まる行から次の節の行までが続く。
// 環境変数（$NAME、${NAME}）は展開しない。含んでいる行には印を付ける。
package haproxyconf

import (
	"strconv"
	"strings"
)

// Directive は設定の1項目。
type Directive struct {
	Section     string // 属する節の種類（global、defaults、frontend、listen、backend など）。節の外なら空
	Name        string // 節の名前（frontend fe_web の fe_web）。なければ空
	Keyword     string
	Args        []string
	File        string
	Line        int
	HasVariable bool // 環境変数を含む（値は展開していない）
}

const (
	maxSize  = 1 << 20
	maxLines = 100_000
	maxLine  = 16384
)

// 節の始まりになる語。
var sections = map[string]bool{
	"global": true, "defaults": true, "frontend": true, "backend": true, "listen": true, "userlist": true, "peers": true,
	"resolvers": true, "mailers": true, "cache": true, "program": true, "ring": true, "http-errors": true, "crt-store": true,
	"fcgi-app": true, "traces": true, "log-forward": true, "acme": true,
}

// Parse は設定ファイル1つを読む。読めなかった行は problems に報告し、残りを返す。
func Parse(file string, data []byte) (ds []Directive, problems []string) {
	if len(data) > maxSize {
		return nil, []string{"the configuration file is too large"}
	}
	section, name := "", ""
	for i, line := range strings.Split(string(data), "\n") {
		n := i + 1
		if n > maxLines {
			problems = append(problems, "too many lines")
			break
		}
		if len(line) > maxLine {
			problems = append(problems, "line "+strconv.Itoa(n)+": too long")
			continue
		}
		words, hasVar, ok := split(strings.TrimRight(line, "\r"))
		if !ok {
			problems = append(problems, "line "+strconv.Itoa(n)+": not interpreted (unterminated quote or control character)")
			continue
		}
		if len(words) == 0 {
			continue
		}
		if sections[words[0]] {
			section, name = words[0], ""
			if len(words) > 1 {
				name = words[1]
			}
			continue
		}
		ds = append(ds, Directive{Section: section, Name: name, Keyword: words[0], Args: words[1:], File: file, Line: n, HasVariable: hasVar})
	}
	return ds, problems
}

// split は1行を語に分ける。
func split(line string) (words []string, hasVar, ok bool) {
	var cur strings.Builder
	has := false
	quote := byte(0)
	flush := func() {
		if has {
			words = append(words, cur.String())
			cur.Reset()
			has = false
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c < 0x20 && c != '\t' || c == 0x7f {
			return nil, false, false
		}
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '\\' && i+1 < len(line):
			i++
			cur.WriteByte(line[i])
			has = true
		case quote == '"':
			if c == '"' {
				quote = 0
			} else {
				if c == '$' {
					hasVar = true
				}
				cur.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote, has = c, true
		case c == '#':
			flush()
			return words, hasVar, true
		case c == ' ' || c == '\t':
			flush()
		default:
			if c == '$' {
				hasVar = true
			}
			cur.WriteByte(c)
			has = true
		}
	}
	if quote != 0 {
		return nil, false, false
	}
	flush()
	return words, hasVar, true
}
