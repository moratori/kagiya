// Package postfixconf は、Postfix の設定ファイル（main.cf、master.cf）を読む。
//
// 読み方は、Postfix 自身（postconf）が同じファイルをどう読むかを、検証ラボで実物（3.1.0、3.5.25、3.10.13）に確かめたもの。
//
//	main.cf   : 「名前 = 値」。空白で始まる行は、前の行の続き。空行と、最初の空白でない文字が「#」の行は読み飛ばす
//	            （続きの途中にあってもよい）。同じ名前は、後に書かれたものが効く。
//	master.cf : 1 行が 1 つのサービス（名前、種類、5 つの欄、コマンド、引数）。空白で始まる行は続き。
//	            引数の「-o 名前=値」は、そのサービスだけの上書き。「-o { 名前 = 値 }」と書けば、値に空白を含められる。
//	値の中の $名前、${名前}、$(名前) は、ほかの項目の値に置き換わる。「$$」は「$」そのもの。
package postfixconf

import (
	"errors"
	"regexp"
	"strings"
)

// Param は、設定の 1 項目（main.cf の記載、または master.cf の -o による上書き）。
type Param struct {
	Name  string
	Value string // 展開する前の値。前後の空白は含まず、途中の空白の並びは 1 つの空白にしてある
	File  string
	Line  int // 記載が始まる行
}

// Service は、master.cf の 1 つのサービス。
type Service struct {
	Name      string // 待ち受ける場所（smtp、127.0.0.1:587 など）、またはソケットの名前
	Type      string // inet | unix | unix-dgram | fifo | pass
	Command   string // 起動するプログラム（smtpd など）
	Overrides []Param
	File      string
	Line      int
}

const (
	maxFileSize = 4 << 20
	maxValueLen = 16384
	maxDepth    = 16
)

var (
	paramName = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)
	space     = regexp.MustCompile(`[ \t\r\n]+`)

	// ErrUnknownName は、展開の途中で、値の分からない名前が出てきた場合（エラーの文に名前が入る）。
	ErrUnknownName = errors.New("unknown parameter name")
	// ErrUnsupported は、この実装が展開しない書き方（条件つきの ${名前?値} など）。
	ErrUnsupported = errors.New("this form of parameter expansion is not supported")
	// ErrLoop は、参照が循環しているか、深すぎる場合（Postfix も停止する）。
	ErrLoop = errors.New("parameter expansion is nested too deeply")
)

type logical struct {
	text string
	line int
}

// logicalLines は、継続行をつないだ「論理行」に分ける。
func logicalLines(data []byte) (lines []logical, orphan []int) {
	for i, l := range strings.Split(string(data), "\n") {
		l = strings.TrimRight(l, "\r")
		trimmed := strings.TrimLeft(l, " \t")
		if trimmed == "" || trimmed[0] == '#' {
			continue // 空行とコメント行（続きの途中にあっても、続きを切らない）
		}
		if l[0] == ' ' || l[0] == '\t' {
			if len(lines) == 0 {
				orphan = append(orphan, i+1)
				continue
			}
			lines[len(lines)-1].text += " " + trimmed
			continue
		}
		lines = append(lines, logical{text: l, line: i + 1})
	}
	return lines, orphan
}

func clean(s string) string { return space.ReplaceAllString(strings.TrimSpace(s), " ") }

// ParseMain は main.cf を読み、書かれている項目をすべて、書かれた順に返す（同じ名前は、後のものが効く）。
func ParseMain(file string, data []byte) (params []Param, problems []string) {
	if len(data) > maxFileSize {
		return nil, []string{"the file is too large"}
	}
	lines, orphan := logicalLines(data)
	if len(orphan) > 0 {
		problems = append(problems, "a continuation line has no line to continue")
	}
	bad := 0
	for _, l := range lines {
		name, value, ok := strings.Cut(l.text, "=")
		name = strings.TrimSpace(name)
		if !ok || !paramName.MatchString(name) || len(value) > maxValueLen {
			bad++
			continue
		}
		params = append(params, Param{Name: name, Value: clean(value), File: file, Line: l.line})
	}
	if bad > 0 {
		problems = append(problems, "some lines are not in the form \"name = value\"")
	}
	return params, problems
}

// ParseMaster は master.cf を読み、サービスと、サービスごとの上書き（-o）を返す。
func ParseMaster(file string, data []byte) (services []Service, problems []string) {
	if len(data) > maxFileSize {
		return nil, []string{"the file is too large"}
	}
	add := func(p string) {
		for _, have := range problems {
			if have == p {
				return
			}
		}
		problems = append(problems, p)
	}
	lines, orphan := logicalLines(data)
	if len(orphan) > 0 {
		add("a continuation line has no line to continue")
	}
	for _, l := range lines {
		if len(l.text) > maxValueLen {
			add("a service entry is too long")
			continue
		}
		f := strings.Fields(l.text)
		if len(f) < 8 {
			add("a service entry has too few fields")
			continue
		}
		s := Service{Name: f[0], Type: f[1], Command: f[7], File: file, Line: l.line}
		// 引数を、書かれた行ごとに読み直す（-o の記載の行番号を残すため）
		for _, a := range masterArgs(data, l.line) {
			if !a.option {
				continue
			}
			if a.problem != "" {
				add(a.problem)
				continue
			}
			name, value, found := strings.Cut(a.text, "=")
			name = strings.TrimSpace(name)
			if !found || !paramName.MatchString(name) {
				add("a -o option is not in the form \"name=value\"")
				continue
			}
			s.Overrides = append(s.Overrides, Param{Name: name, Value: clean(value), File: file, Line: a.line})
		}
		services = append(services, s)
	}
	return services, problems
}

type masterArg struct {
	text    string
	line    int
	option  bool   // -o の値
	problem string // 読めなかった理由（空でなければ、この -o は使わない）
}

// masterArgs は、start 行から始まるサービスの記載の、コマンドより後ろの引数を、行番号つきで返す。
// 「-o」の次の語（波括弧で囲まれていれば、その中身）を、上書きの指定として返す。
func masterArgs(data []byte, start int) []masterArg {
	type word struct {
		text string
		line int
	}
	var words []word
	lines := strings.Split(string(data), "\n")
	for i := start - 1; i < len(lines); i++ {
		l := strings.TrimRight(lines[i], "\r")
		trimmed := strings.TrimLeft(l, " \t")
		if trimmed == "" || trimmed[0] == '#' {
			continue
		}
		if i > start-1 && l[0] != ' ' && l[0] != '\t' {
			break // 次のサービス
		}
		// 語に分ける。波括弧で囲まれた部分は、空白を含めて 1 語
		for pos := 0; pos < len(l); {
			for pos < len(l) && (l[pos] == ' ' || l[pos] == '\t') {
				pos++
			}
			if pos >= len(l) {
				break
			}
			begin := pos
			if l[pos] == '{' {
				depth := 0
				for pos < len(l) {
					if l[pos] == '{' {
						depth++
					} else if l[pos] == '}' {
						depth--
						if depth == 0 {
							pos++
							break
						}
					}
					pos++
				}
			} else {
				for pos < len(l) && l[pos] != ' ' && l[pos] != '\t' {
					pos++
				}
			}
			words = append(words, word{l[begin:pos], i + 1})
		}
	}
	var out []masterArg
	for i := 8; i < len(words); i++ { // 先頭の 8 語は、名前、種類、5 つの欄、コマンド
		w := words[i]
		if w.text != "-o" {
			out = append(out, masterArg{text: w.text, line: w.line})
			continue
		}
		if i+1 >= len(words) {
			out = append(out, masterArg{line: w.line, option: true, problem: "a -o option has no value"})
			break
		}
		i++
		v := words[i].text
		if strings.HasPrefix(v, "{") {
			if !strings.HasSuffix(v, "}") || len(v) < 2 {
				out = append(out, masterArg{line: words[i].line, option: true, problem: "a -o option has an unterminated brace"})
				continue
			}
			v = strings.TrimSpace(v[1 : len(v)-1])
		}
		out = append(out, masterArg{text: v, line: words[i].line, option: true})
	}
	return out
}

// Expand は、値の中の $名前、${名前}、$(名前) を、lookup が返す値に置き換える（置き換えた値の中の参照も展開する）。
// lookup が知らない名前は ErrUnknownName（Postfix は空の値として扱うが、既定値を持つ項目かどうかをここでは判断できないため、
// 呼び出し側に委ねる）。
func Expand(value string, lookup func(name string) (string, bool)) (string, error) {
	return expand(value, lookup, 0)
}

func expand(value string, lookup func(name string) (string, bool), depth int) (string, error) {
	if depth > maxDepth {
		return "", ErrLoop
	}
	if len(value) > maxValueLen {
		return "", ErrUnsupported
	}
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c != '$' {
			b.WriteByte(c)
			continue
		}
		if i+1 >= len(value) {
			b.WriteByte('$')
			break
		}
		next := value[i+1]
		name := ""
		switch {
		case next == '$':
			b.WriteByte('$')
			i++
			continue
		case next == '{' || next == '(':
			closer := byte('}')
			if next == '(' {
				closer = ')'
			}
			end := strings.IndexByte(value[i+2:], closer)
			if end < 0 {
				return "", ErrUnsupported
			}
			name = value[i+2 : i+2+end]
			i += 2 + end
		default:
			j := i + 1
			for j < len(value) && (value[j] == '_' || value[j] >= '0' && value[j] <= '9' || value[j] >= 'a' && value[j] <= 'z' || value[j] >= 'A' && value[j] <= 'Z') {
				j++
			}
			if j == i+1 {
				b.WriteByte('$') // 名前が続かない「$」は、そのまま
				continue
			}
			name = value[i+1 : j]
			i = j - 1
		}
		if !paramName.MatchString(name) {
			return "", ErrUnsupported // ${名前?値}、${名前:値} などの条件つきの書き方
		}
		v, ok := lookup(name)
		if !ok {
			return "", errors.Join(ErrUnknownName, errors.New(name))
		}
		x, err := expand(v, lookup, depth+1)
		if err != nil {
			return "", err
		}
		b.WriteString(x)
		if b.Len() > maxValueLen {
			return "", ErrUnsupported
		}
	}
	return b.String(), nil
}
