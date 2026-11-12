// Package apacheconf は Apache HTTP Server の設定ファイルを読む。
// セクション（<VirtualHost> など）の入れ子、Include / IncludeOptional、<IfModule> の条件を辿り、
// ディレクティブを現れる順に返す。値の解釈はしない。
package apacheconf

import (
	"sort"
	"strings"
)

// FS は設定ファイルの読み取り手段（呼び出し側が、安全なファイルアクセスを通して提供する）。
type FS interface {
	ReadFile(path string) ([]byte, error)
	Glob(pattern string) ([]string, error)
}

type Directive struct {
	Name     string // 小文字にした名前（Apache は大文字小文字を区別しない）
	Args     string
	File     string
	Line     int
	Sections []string // 属するセクション（外側から。例: "VirtualHost _default_:443"）
}

type Result struct {
	Directives []Directive
	Modules    []string // LoadModule で読み込まれるモジュールの識別子（例: ssl_module）
	ServerRoot string
	Problems   []string
}

const (
	maxDepth      = 16
	maxFiles      = 1024
	maxDirectives = 200_000
	maxNesting    = 64
)

type parser struct {
	fs     FS
	res    *Result
	loaded map[string]bool
	stack  map[string]bool
	files  int
}

// Parse は設定ファイルを読む。読めなかった・辿らなかった箇所は Problems に入れる（値そのものは含めない）。
func Parse(path string, fs FS) *Result {
	p := &parser{fs: fs, res: &Result{}, loaded: map[string]bool{}, stack: map[string]bool{}}
	// ServerRoot の指定がなければ、設定ファイルのあるディレクトリを基準にする
	p.res.ServerRoot = "/"
	if i := strings.LastIndexByte(path, '/'); i > 0 {
		p.res.ServerRoot = path[:i]
	}
	data, err := fs.ReadFile(path)
	if err != nil {
		p.problem("the configuration file could not be read")
		return p.res
	}
	p.load(path, data, nil, 0)
	return p.res
}

func (p *parser) problem(s string) {
	if len(p.res.Problems) < 32 {
		p.res.Problems = append(p.res.Problems, s)
	}
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// moduleID は、<IfModule> の2通りの書き方（mod_ssl.c と ssl_module）を識別子に揃える。
func moduleID(s string) string {
	if strings.HasPrefix(s, "mod_") && strings.HasSuffix(s, ".c") {
		return strings.TrimSuffix(strings.TrimPrefix(s, "mod_"), ".c") + "_module"
	}
	return s
}

func (p *parser) load(file string, data []byte, sections []string, depth int) {
	p.stack[file] = true
	defer delete(p.stack, file)
	p.files++
	base := len(sections)
	type frame struct {
		name string
		kept bool // セクション名を sections に積んだか（条件のセクションは積まない）
	}
	var open []frame
	skip := 0 // 条件が成り立たないセクションの中にいる間の入れ子の深さ

	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		if len(p.res.Directives) >= maxDirectives {
			p.problem("the configuration is too long; only the first part was read")
			return
		}
		lineNo := i + 1
		line := strings.TrimRight(lines[i], "\r")
		for strings.HasSuffix(line, "\\") && i+1 < len(lines) {
			i++
			line = strings.TrimSuffix(line, "\\") + strings.TrimRight(lines[i], "\r")
		}
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		if strings.HasPrefix(line, "</") {
			switch {
			case skip > 0:
				skip--
			case len(open) == 0:
				p.problem("unbalanced closing section")
			default:
				if open[len(open)-1].kept {
					sections = sections[:len(sections)-1]
				}
				open = open[:len(open)-1]
			}
			continue
		}
		if line[0] == '<' && strings.HasSuffix(line, ">") {
			if skip > 0 {
				skip++
				continue
			}
			inner := strings.TrimSpace(line[1 : len(line)-1])
			name, arg, _ := strings.Cut(inner, " ")
			arg = strings.TrimSpace(arg)
			switch strings.ToLower(name) {
			case "ifmodule":
				neg := strings.HasPrefix(arg, "!")
				if p.loaded[moduleID(strings.TrimPrefix(arg, "!"))] == neg {
					skip = 1
					continue
				}
				open = append(open, frame{name, false})
			case "ifdefine":
				// 起動時の指定（-D）は分からないので、定義されていないものとして扱う
				if !strings.HasPrefix(arg, "!") {
					skip = 1
					continue
				}
				open = append(open, frame{name, false})
			default:
				if len(sections) >= maxNesting {
					p.problem("sections are nested too deeply")
					return
				}
				sections = append(append([]string{}, sections...), inner)
				open = append(open, frame{name, true})
			}
			continue
		}
		if skip > 0 {
			continue
		}
		name, args, _ := strings.Cut(line, " ")
		if j := strings.IndexAny(line, " \t"); j >= 0 {
			name, args = line[:j], strings.TrimSpace(line[j:])
		}
		lower := strings.ToLower(name)
		switch lower {
		case "include", "includeoptional":
			p.include(unquote(args), lower == "include", sections, depth)
			continue
		case "serverroot":
			if r := unquote(args); strings.HasPrefix(r, "/") {
				p.res.ServerRoot = strings.TrimRight(r, "/")
				if p.res.ServerRoot == "" {
					p.res.ServerRoot = "/"
				}
			}
			continue // 取り込みの基準として使うだけで、ディレクティブとしては返さない
		case "loadmodule":
			if id, _, _ := strings.Cut(args, " "); id != "" && !p.loaded[id] {
				p.loaded[id] = true
				p.res.Modules = append(p.res.Modules, id)
			}
		}
		p.res.Directives = append(p.res.Directives, Directive{Name: lower, Args: args, File: file, Line: lineNo, Sections: sections})
	}
	if len(open) > 0 || skip > 0 || len(sections) != base {
		p.problem("the configuration ends inside a section")
	}
}

func (p *parser) include(target string, mandatory bool, sections []string, depth int) {
	if target == "" {
		return
	}
	if depth >= maxDepth {
		p.problem("too many nested Include directives")
		return
	}
	if !strings.HasPrefix(target, "/") {
		target = strings.TrimRight(p.res.ServerRoot, "/") + "/" + target // 相対パスは ServerRoot が基準
	}
	var files []string
	if strings.ContainsAny(target, "*?[") {
		files, _ = p.fs.Glob(target)
	} else if _, err := p.fs.ReadFile(target); err == nil {
		files = []string{target}
	} else {
		files, _ = p.fs.Glob(target + "/*") // ディレクトリの指定
	}
	sort.Strings(files)
	if len(files) == 0 {
		if mandatory && !strings.ContainsAny(target, "*?[") {
			p.problem("a file named by Include does not exist or could not be read")
		}
		return
	}
	for _, f := range files {
		if p.stack[f] {
			p.problem("an Include that forms a loop was not followed")
			continue
		}
		if p.files >= maxFiles {
			p.problem("too many included files")
			return
		}
		data, err := p.fs.ReadFile(f)
		if err != nil {
			continue
		}
		p.load(f, data, sections, depth+1)
	}
}
