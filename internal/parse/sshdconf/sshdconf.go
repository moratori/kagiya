// Package sshdconf は OpenSSH の設定ファイル（sshd_config / ssh_config の形式）を読む。
// Include を辿り、Match ブロックの範囲を区別して、ディレクティブを現れる順に返す。値の解釈はしない。
package sshdconf

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
	Keyword string // 小文字にしたキーワード（OpenSSH は大文字小文字を区別しない）
	Args    string
	File    string
	Line    int
	Match   string // Match ブロックの条件（ブロックの外なら空）
}

const (
	maxDepth      = 16
	maxDirectives = 100_000
	maxFiles      = 256
)

type parser struct {
	fs       FS
	dir      string
	out      []Directive
	problems []string
	stack    map[string]bool
	files    int
}

// Parse は設定ファイルを読む。読めなかった・辿らなかった箇所は problems に入れる（値そのものは含めない）。
func Parse(path string, fs FS) (directives []Directive, problems []string) {
	p := &parser{fs: fs, stack: map[string]bool{}}
	if i := strings.LastIndexByte(path, '/'); i > 0 {
		p.dir = path[:i]
	}
	data, err := fs.ReadFile(path)
	if err != nil {
		return nil, []string{"the configuration file could not be read"}
	}
	match := ""
	p.load(path, data, &match, 0)
	return p.out, p.problems
}

func (p *parser) problem(s string) {
	if len(p.problems) < 32 {
		p.problems = append(p.problems, s)
	}
}

func (p *parser) load(file string, data []byte, match *string, depth int) {
	p.stack[file] = true
	defer delete(p.stack, file)
	p.files++
	for i, line := range strings.Split(string(data), "\n") {
		if len(p.out) >= maxDirectives {
			p.problem("the configuration is too long; only the first part was read")
			return
		}
		line = strings.TrimSpace(stripComment(strings.TrimRight(line, "\r")))
		if line == "" {
			continue
		}
		// 「キーワード 値」または「キーワード=値」
		cut := strings.IndexAny(line, " \t=")
		kw, args := line, ""
		if cut >= 0 {
			kw, args = line[:cut], strings.TrimSpace(strings.TrimLeft(line[cut:], " \t="))
		}
		kw = strings.ToLower(kw)
		args = unquote(args)
		switch kw {
		case "match":
			if strings.EqualFold(args, "all") {
				*match = ""
			} else {
				*match = args
			}
		case "include":
			p.include(args, match, depth)
		default:
			p.out = append(p.out, Directive{Keyword: kw, Args: args, File: file, Line: i + 1, Match: *match})
		}
	}
}

func (p *parser) include(args string, match *string, depth int) {
	if depth >= maxDepth {
		p.problem("too many nested Include directives")
		return
	}
	for _, pattern := range strings.Fields(args) {
		pattern = unquote(pattern)
		if !strings.HasPrefix(pattern, "/") {
			pattern = p.dir + "/" + pattern // 相対パスは設定ファイルのあるディレクトリが基準
		}
		files, err := p.fs.Glob(pattern)
		if err != nil {
			continue
		}
		sort.Strings(files)
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
				continue // 存在しない・読めない取り込み先は、sshd と同じく無視する（読めない理由は別途記録される）
			}
			saved := *match
			p.load(f, data, match, depth+1)
			*match = saved
		}
	}
}

// stripComment は、行頭の # と、引用符の外で空白に続く # 以降を取り除く。
func stripComment(s string) string {
	quote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"':
			quote = c
		case c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t' || strings.TrimSpace(s[:i]) == ""):
			return s[:i]
		}
	}
	return s
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
