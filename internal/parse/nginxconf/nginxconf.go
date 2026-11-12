// Package nginxconf は nginx の設定ファイルを読む。
// ブロック（http、server、location など）の入れ子と include を辿り、ディレクティブを現れる順に返す。値の解釈はしない。
package nginxconf

import (
	"sort"
	"strconv"
	"strings"
)

// FS は設定ファイルの読み取り手段（呼び出し側が、安全なファイルアクセスを通して提供する）。
type FS interface {
	ReadFile(path string) ([]byte, error)
	Glob(pattern string) ([]string, error)
}

type Directive struct {
	Name    string
	Args    []string
	File    string
	Line    int
	Context string // 属するブロックの並び（例: "http/server#2/location"）。server には現れた順の番号が付く
}

const (
	maxDepth      = 16
	maxFiles      = 512
	maxDirectives = 200_000
	maxNesting    = 64
)

type token struct {
	text   string
	line   int
	quoted bool
}

type parser struct {
	fs       FS
	dir      string
	out      []Directive
	problems []string
	stack    map[string]bool
	files    int
	servers  int
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
	p.load(path, data, nil, 0)
	return p.out, p.problems
}

func (p *parser) problem(s string) {
	if len(p.problems) < 32 {
		p.problems = append(p.problems, s)
	}
}

// lex は設定を語に分ける。引用符の中の ; { } # は区切りにしない。変数の ${...} の波括弧はブロックとして扱わない。
func lex(data []byte) []token {
	var out []token
	var cur strings.Builder
	line, start, has, quoted := 1, 1, false, false
	flush := func() {
		if has {
			out = append(out, token{cur.String(), start, quoted})
		}
		cur.Reset()
		has, quoted = false, false
	}
	for i := 0; i < len(data); i++ {
		c := data[i]
		switch {
		case c == '\n':
			flush()
			line++
		case c == ' ' || c == '\t' || c == '\r':
			flush()
		case c == '#' && !has:
			for i < len(data) && data[i] != '\n' {
				i++
			}
			i--
		case c == '"' || c == '\'':
			if !has {
				start, has = line, true
			}
			quoted = true
			for i++; i < len(data) && data[i] != c; i++ {
				if data[i] == '\\' && i+1 < len(data) {
					i++
				}
				if data[i] == '\n' {
					line++
				}
				cur.WriteByte(data[i])
			}
		case c == '{' && has && strings.HasSuffix(cur.String(), "$"):
			for ; i < len(data) && data[i] != '}' && data[i] != '\n'; i++ {
				cur.WriteByte(data[i])
			}
			if i < len(data) && data[i] == '}' {
				cur.WriteByte('}')
			}
		case c == ';' || c == '{' || c == '}':
			flush()
			out = append(out, token{string(c), line, false})
		default:
			if !has {
				start, has = line, true
			}
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

func (p *parser) load(file string, data []byte, ctx []string, depth int) {
	p.stack[file] = true
	defer delete(p.stack, file)
	p.files++
	base := len(ctx)
	var words []token
	for _, t := range lex(data) {
		if len(p.out) >= maxDirectives {
			p.problem("the configuration is too long; only the first part was read")
			return
		}
		special := !t.quoted && (t.text == ";" || t.text == "{" || t.text == "}")
		if !special {
			words = append(words, t)
			continue
		}
		switch t.text {
		case ";":
			if len(words) > 0 {
				p.directive(file, words, ctx, depth)
			}
		case "{":
			if len(words) == 0 || len(ctx) >= maxNesting {
				p.problem("unexpected block")
				return
			}
			name := words[0].text
			if name == "server" {
				p.servers++
				name += "#" + strconv.Itoa(p.servers)
			}
			ctx = append(append([]string{}, ctx...), name)
		case "}":
			if len(ctx) <= base {
				p.problem("unbalanced closing brace")
				return
			}
			ctx = ctx[:len(ctx)-1]
		}
		words = nil
	}
	if len(words) > 0 || len(ctx) != base {
		p.problem("the configuration ends in the middle of a directive or block")
	}
}

func (p *parser) directive(file string, words []token, ctx []string, depth int) {
	name := words[0].text
	args := make([]string, 0, len(words)-1)
	for _, w := range words[1:] {
		args = append(args, w.text)
	}
	if name != "include" {
		p.out = append(p.out, Directive{Name: name, Args: args, File: file, Line: words[0].line, Context: strings.Join(ctx, "/")})
		return
	}
	if len(args) != 1 {
		return
	}
	if depth >= maxDepth {
		p.problem("too many nested include directives")
		return
	}
	pattern := args[0]
	if !strings.HasPrefix(pattern, "/") {
		pattern = p.dir + "/" + pattern // 相対パスは設定ファイルのあるディレクトリが基準
	}
	files := []string{pattern}
	if strings.ContainsAny(pattern, "*?[") {
		var err error
		if files, err = p.fs.Glob(pattern); err != nil {
			return
		}
		sort.Strings(files)
	}
	for _, f := range files {
		if p.stack[f] {
			p.problem("an include that forms a loop was not followed")
			continue
		}
		if p.files >= maxFiles {
			p.problem("too many included files")
			return
		}
		data, err := p.fs.ReadFile(f)
		if err != nil {
			continue // 取り込み先がない・読めない（読めない理由は別途記録される）
		}
		p.load(f, data, ctx, depth+1)
	}
}
