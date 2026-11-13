// Package mycnf は、MariaDB / MySQL の設定ファイル（my.cnf と、そこから取り込まれるファイル）を読む。
//
// 読み方は、検証ラボでサーバー自身の読み取り（my_print_defaults）と突き合わせて確かめたもの。
//
//	[グループ]            以降の項目が属するグループ（mysqld、server、client など）。どのグループを読むかは、プログラムごとに決まっている。
//	名前 = 値 / 名前      項目名の「-」と「_」は同じ。値を囲む引用符と、値の後ろの「 #」以降は値に含まれない。値のない項目もある。
//	!include ファイル     その位置で取り込む。
//	!includedir ディレクトリ   その中の、名前が「.cnf」で終わるファイルを、名前の順に取り込む。
//	行頭の「#」「;」はコメント。同じ名前は、後に読まれたものが効く（グループの順ではなく、書かれた順）。
package mycnf

import (
	"sort"
	"strings"
)

// FS は、設定ファイルを読む手段。
type FS interface {
	ReadFile(path string) ([]byte, error)
	Glob(pattern string) ([]string, error)
}

// Option は、設定の 1 項目。
type Option struct {
	Group string
	Name  string // 「-」を「_」にそろえた名前
	Value string // 値のない項目は空
	File  string
	Line  int
}

const (
	maxFileSize = 4 << 20
	maxDepth    = 10
	maxFiles    = 512
	maxValueLen = 16384
)

type parser struct {
	fs       FS
	out      []Option
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
func Parse(file string, fs FS) (options []Option, problems []string) {
	p := &parser{fs: fs, problems: map[string]bool{}}
	p.file(file, 0)
	return p.out, p.order
}

func isName(s string) bool {
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

func (p *parser) file(path string, depth int) {
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
		p.problem("a configuration file is not readable")
		return
	}
	if len(data) > maxFileSize {
		p.problem("a configuration file is too large")
		return
	}
	group := ""
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		switch {
		case strings.HasPrefix(line, "!include"):
			f := strings.Fields(line)
			switch {
			case len(f) == 2 && f[0] == "!include" && strings.HasPrefix(f[1], "/"):
				p.file(f[1], depth+1)
			case len(f) == 2 && f[0] == "!includedir" && strings.HasPrefix(f[1], "/"):
				names, _ := p.fs.Glob(strings.TrimRight(f[1], "/") + "/*.cnf")
				sort.Strings(names)
				for _, n := range names {
					p.file(n, depth+1)
				}
			default:
				p.problem("an include line is not interpreted")
			}
			group = "" // 取り込みの後は、グループを指定し直す必要がある
		case line[0] == '[':
			end := strings.IndexByte(line, ']')
			if end < 0 || !isName(line[1:end]) {
				p.problem("a group heading is not interpreted")
				group = ""
				continue
			}
			group = strings.ToLower(line[1:end])
		default:
			name, value, hasValue := strings.Cut(line, "=")
			name = strings.TrimSpace(name)
			if !hasValue {
				if j := strings.Index(name, " #"); j >= 0 {
					name = strings.TrimSpace(name[:j])
				}
			}
			value = strings.TrimSpace(value)
			if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') {
				if end := strings.IndexByte(value[1:], value[0]); end >= 0 {
					value = value[1 : 1+end]
				}
			} else if j := strings.Index(value, " #"); j >= 0 {
				value = strings.TrimSpace(value[:j])
			} else if j := strings.Index(value, "\t#"); j >= 0 {
				value = strings.TrimSpace(value[:j])
			}
			if !isName(name) || len(value) > maxValueLen {
				p.problem("some lines are not in the form \"name = value\"")
				continue
			}
			if group == "" {
				p.problem("an option is written outside of any group")
				continue
			}
			p.out = append(p.out, Option{Group: group, Name: strings.ReplaceAll(strings.ToLower(name), "-", "_"), Value: value, File: path, Line: i + 1})
		}
	}
}
