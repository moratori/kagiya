// Package pgconf は、PostgreSQL の設定ファイル（postgresql.conf と、そこから取り込まれるファイル）を読む。
//
// 読み方は、検証ラボで実際に起動したサーバー自身の答え（pg_settings）で確かめたもの。
//
//	名前 = 値   「=」は省略できる。名前は大文字小文字を区別しない。「#」から行末まではコメント。
//	値          引用符（'）で囲む。中の引用符は 2 つ重ねるか「\'」。単純な値（数値、識別子）は引用符なしでも書ける。
//	include 'ファイル' / include_if_exists 'ファイル' / include_dir 'ディレクトリ'
//	            その位置で取り込む（相対パスは、書かれているファイルのあるディレクトリから）。
//	            include_dir は、名前が「.conf」で終わり、「.」で始まらないファイルを、名前の順に読む。
//	同じ名前は、後に読まれたものが効く。
package pgconf

import (
	"sort"
	"strings"
)

// FS は、設定ファイルを読む手段。
type FS interface {
	ReadFile(path string) ([]byte, error)
	Glob(pattern string) ([]string, error)
}

// Setting は、設定の 1 項目。
type Setting struct {
	Name  string // 小文字にした名前
	Value string
	File  string
	Line  int
}

const (
	maxFileSize = 4 << 20
	maxDepth    = 10 // PostgreSQL 自身の入れ子の上限と同じ
	maxFiles    = 256
	maxValueLen = 16384
)

type parser struct {
	fs       FS
	settings []Setting
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
func Parse(file string, fs FS) (settings []Setting, problems []string) {
	p := &parser{fs: fs, problems: map[string]bool{}}
	p.file(file, 0, true)
	return p.settings, p.order
}

func dir(path string) string {
	if i := strings.LastIndexByte(path, '/'); i > 0 {
		return path[:i]
	}
	return "/"
}

func (p *parser) file(path string, depth int, required bool) {
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
	for i, line := range strings.Split(string(data), "\n") {
		name, value, ok, empty := splitLine(line)
		if empty {
			continue
		}
		if !ok {
			p.problem("some lines are not in the form \"name = value\"")
			continue
		}
		target := value
		if !strings.HasPrefix(target, "/") {
			target = strings.TrimRight(dir(path), "/") + "/" + target
		}
		switch name {
		case "include":
			p.file(target, depth+1, true)
		case "include_if_exists":
			p.file(target, depth+1, false)
		case "include_dir":
			names, _ := p.fs.Glob(target + "/*.conf")
			sort.Strings(names)
			for _, n := range names {
				if base := n[strings.LastIndexByte(n, '/')+1:]; !strings.HasPrefix(base, ".") {
					p.file(n, depth+1, true)
				}
			}
		default:
			p.settings = append(p.settings, Setting{Name: name, Value: value, File: path, Line: i + 1})
		}
	}
}

func isNameChar(c byte) bool {
	return c == '_' || c == '.' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// splitLine は、1 行を名前と値に分ける。空行とコメントだけの行は empty = true。
func splitLine(line string) (name, value string, ok, empty bool) {
	s := strings.TrimLeft(strings.TrimRight(line, "\r"), " \t")
	if s == "" || s[0] == '#' {
		return "", "", false, true
	}
	i := 0
	for i < len(s) && isNameChar(s[i]) {
		i++
	}
	if i == 0 || i > 128 {
		return "", "", false, false
	}
	name = strings.ToLower(s[:i])
	s = strings.TrimLeft(s[i:], " \t")
	if strings.HasPrefix(s, "=") {
		s = strings.TrimLeft(s[1:], " \t")
	}
	if s == "" || s[0] == '#' {
		return "", "", false, false // 値がない
	}
	rest := ""
	if s[0] == '\'' {
		var b strings.Builder
		j := 1
		closed := false
		for j < len(s) {
			c := s[j]
			switch {
			case c == '\'' && j+1 < len(s) && s[j+1] == '\'':
				b.WriteByte('\'')
				j += 2
			case c == '\\' && j+1 < len(s) && s[j+1] == '\'':
				b.WriteByte('\'')
				j += 2
			case c == '\\' && j+1 < len(s) && s[j+1] == '\\':
				b.WriteByte('\\')
				j += 2
			case c == '\'':
				closed = true
				j++
			default:
				b.WriteByte(c)
				j++
			}
			if closed {
				break
			}
		}
		if !closed {
			return "", "", false, false
		}
		value, rest = b.String(), s[j:]
	} else {
		j := 0
		for j < len(s) && s[j] != ' ' && s[j] != '\t' && s[j] != '#' {
			j++
		}
		value, rest = s[:j], s[j:]
	}
	rest = strings.TrimLeft(rest, " \t")
	if (rest != "" && rest[0] != '#') || len(value) > maxValueLen {
		return "", "", false, false
	}
	return name, value, true, false
}
