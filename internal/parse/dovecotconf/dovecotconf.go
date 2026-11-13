// Package dovecotconf は、Dovecot の設定ファイル（dovecot.conf と、そこから取り込まれるファイル）を読む。
//
// 読み方は、検証ラボで Dovecot 自身の出力（doveconf）と突き合わせて確かめたもの。
//
//	名前 = 値          値の前後の空白は含まない。値の後ろの「 #」以降はコメント。行頭の「#」もコメント。
//	名前 [引数] {      入れ子の始まり（protocol imap、service imap-login、inet_listener imaps など）。「}」で閉じる。
//	!include パターン  その位置で取り込む（相対パスは、書かれているファイルのあるディレクトリから）。名前の順に読む。
//	!include_try       同じ。ただし、当てはまるファイルがなくてもよい。
//	同じ名前は、後に読まれたものが効く。
package dovecotconf

import (
	"sort"
	"strings"
)

// FS は、設定ファイルを読む手段。
type FS interface {
	ReadFile(path string) ([]byte, error)
	Glob(pattern string) ([]string, error)
}

// Directive は、設定の 1 項目。
type Directive struct {
	Key      string
	Value    string
	Sections []string // 外側から順に、入れ子の見出し（「protocol imap」など）。最上位なら空
	File     string
	Line     int
}

const (
	maxFileSize = 4 << 20
	maxDepth    = 10
	maxFiles    = 512
	maxValueLen = 16384
)

type parser struct {
	fs       FS
	out      []Directive
	problems map[string]bool
	order    []string
	files    int
}

func (p *parser) problem(s string) {
	if !p.problems[s] {
		p.problems[s] = true
		p.order = append(p.order, s)
	}
}

// Parse は、設定ファイルと、そこから取り込まれるファイルを読み、書かれている項目をすべて、読まれる順に返す。
func Parse(file string, fs FS) (directives []Directive, problems []string) {
	p := &parser{fs: fs, problems: map[string]bool{}}
	p.file(file, 0, true, nil)
	return p.out, p.order
}

func dir(path string) string {
	if i := strings.LastIndexByte(path, '/'); i > 0 {
		return path[:i]
	}
	return "/"
}

func isKey(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c == '_' || c == '-' || c == '.' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

func (p *parser) file(path string, depth int, required bool, outer []string) {
	if depth > maxDepth {
		p.problem("include files are nested too deeply")
		return
	}
	p.files++
	if p.files > maxFiles {
		p.problem("too many include files")
		return
	}
	data, err := p.fs.ReadFile(path)
	if err != nil {
		if required {
			p.problem("a configuration file is not readable")
		}
		return
	}
	if len(data) > maxFileSize {
		p.problem("a configuration file is too large")
		return
	}
	sections := append([]string{}, outer...)
	base := len(sections)
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || line[0] == '#' {
			continue
		}
		if j := strings.Index(line, " #"); j >= 0 {
			line = strings.TrimSpace(line[:j])
		}
		switch {
		case strings.HasPrefix(line, "!include"):
			f := strings.Fields(line)
			if len(f) != 2 || (f[0] != "!include" && f[0] != "!include_try") {
				p.problem("an include line is not interpreted")
				continue
			}
			pattern := f[1]
			if !strings.HasPrefix(pattern, "/") {
				pattern = strings.TrimRight(dir(path), "/") + "/" + pattern
			}
			need := f[0] == "!include"
			if !strings.ContainsAny(pattern, "*?[") {
				p.file(pattern, depth+1, need, sections)
				continue
			}
			names, _ := p.fs.Glob(pattern)
			sort.Strings(names)
			for _, n := range names {
				p.file(n, depth+1, need, sections)
			}
		case line == "}":
			if len(sections) == base {
				p.problem("a closing brace has no opening brace")
				continue
			}
			sections = sections[:len(sections)-1]
		case strings.HasSuffix(line, "{"):
			head := strings.Join(strings.Fields(strings.TrimSuffix(line, "{")), " ")
			if head == "" || len(head) > 256 || strings.ContainsAny(head, "={}") {
				p.problem("a section heading is not interpreted")
				head = "?"
			}
			sections = append(append([]string{}, sections...), head)
		default:
			key, value, ok := strings.Cut(line, "=")
			key, value = strings.TrimSpace(key), strings.TrimSpace(value)
			if !ok || !isKey(key) || len(value) > maxValueLen {
				p.problem("some lines are not in the form \"name = value\"")
				continue
			}
			if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
				value = value[1 : len(value)-1]
			}
			p.out = append(p.out, Directive{Key: key, Value: value, Sections: sections, File: path, Line: i + 1})
		}
	}
	if len(sections) != base {
		p.problem("a section is not closed")
	}
}
