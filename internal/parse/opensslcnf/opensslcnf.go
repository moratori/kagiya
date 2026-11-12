// Package opensslcnf は OpenSSL の設定ファイル（openssl.cnf）から、システム既定の TLS 設定を読む。
//
// OpenSSL は「openssl_conf → その節の ssl_conf → その節の system_default → その節の各項目」という経路で
// 既定の TLS 設定を読み込む。RHEL 系ではこの最後の節が、システム全体の暗号ポリシーが生成したファイルを取り込む。
// 設定ファイルは別のファイルを取り込める（.include）ので、それも辿る。変数の展開は行わない。
package opensslcnf

import (
	"sort"
	"strings"
)

// FS は設定ファイルの読み取り手段（呼び出し側が、安全なファイルアクセスを通して提供する）。
type FS interface {
	ReadFile(path string) ([]byte, error)
	// ListDir はディレクトリ直下のファイルのパスを返す。ディレクトリでなければエラー。
	ListDir(path string) ([]string, error)
}

type Entry struct {
	Key, Value string
	File       string
	Line       int

	variable bool // 値に変数が含まれている（展開しないので、正しい値が分からない）
}

type Result struct {
	SystemDefault []Entry  // システム既定の TLS 設定（同じキーは後の値が有効）
	Sections      []string // 辿った節の名前
	Problems      []string // 読めなかった・解釈しなかった箇所（値そのものは含めない）
}

const (
	maxFiles = 64
	maxDepth = 8
	maxLines = 200_000
)

type parser struct {
	fs       FS
	sections map[string][]Entry
	cur      string
	seen     map[string]bool
	files    int
	problems []string
}

// SystemDefault は path の設定ファイルを読み、システム既定の TLS 設定を返す。
// 設定ファイル自体が読めない場合だけエラーを返す。取り込み先が読めないなどの問題は Problems に入れ、読めた範囲を返す。
func SystemDefault(path string, fs FS) (*Result, error) {
	data, err := fs.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := &parser{fs: fs, sections: map[string][]Entry{}, seen: map[string]bool{path: true}}
	p.files = 1
	p.parse(path, data, 0)

	r := &Result{Problems: p.problems}
	lookup := func(section, key string) (string, bool) {
		val, ok := "", false
		for _, e := range p.sections[section] {
			if e.Key == key {
				val, ok = e.Value, !e.variable
			}
		}
		return val, ok
	}
	section := ""
	for _, key := range []string{"openssl_conf", "ssl_conf", "system_default"} {
		next, ok := lookup(section, key)
		if !ok {
			return r, nil // この経路は設定されていない
		}
		if _, exists := p.sections[next]; !exists {
			r.Problems = append(r.Problems, "section referenced by "+key+" does not exist")
			return r, nil
		}
		r.Sections = append(r.Sections, next)
		section = next
	}
	// 同じキーは後の値が有効。順序は最初に現れた順。
	last := map[string]int{}
	for i, e := range p.sections[section] {
		last[e.Key] = i
	}
	idx := make([]int, 0, len(last))
	first := map[string]int{}
	for i, e := range p.sections[section] {
		if _, ok := first[e.Key]; !ok {
			first[e.Key] = i
		}
	}
	for k := range last {
		idx = append(idx, first[k])
	}
	sort.Ints(idx)
	for _, i := range idx {
		e := p.sections[section][last[p.sections[section][i].Key]]
		if e.variable {
			// 変数は展開しないので、正しい値が分からない。値としては採らない。
			r.Problems = append(r.Problems, "a value containing a variable was not interpreted")
			continue
		}
		r.SystemDefault = append(r.SystemDefault, e)
	}
	return r, nil
}

func (p *parser) problem(s string) {
	if len(p.problems) < 32 {
		p.problems = append(p.problems, s)
	}
}

func (p *parser) parse(file string, data []byte, depth int) {
	lines := strings.Split(string(data), "\n")
	if len(lines) > maxLines {
		lines = lines[:maxLines]
		p.problem("configuration file is too long; only the first part was read")
	}
	for i := 0; i < len(lines); i++ {
		lineNo := i + 1
		line := strings.TrimRight(lines[i], "\r")
		// 行末の \ は次の行へ続く
		for strings.HasSuffix(line, "\\") && i+1 < len(lines) {
			i++
			line = strings.TrimSuffix(line, "\\") + strings.TrimRight(lines[i], "\r")
		}
		line = strings.TrimSpace(stripComment(line))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			p.cur = strings.TrimSpace(line[1 : len(line)-1])
			if _, ok := p.sections[p.cur]; !ok {
				p.sections[p.cur] = nil
			}
			continue
		}
		if rest, ok := strings.CutPrefix(line, ".include"); ok && (rest == "" || rest[0] == ' ' || rest[0] == '\t' || rest[0] == '=') {
			p.include(unquote(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), "="))), depth)
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), unquote(strings.TrimSpace(val))
		if key == "" {
			continue
		}
		if _, ok := p.sections[p.cur]; !ok {
			p.sections[p.cur] = nil
		}
		p.sections[p.cur] = append(p.sections[p.cur], Entry{Key: key, Value: val, File: file, Line: lineNo, variable: strings.Contains(val, "$")})
	}
}

func (p *parser) include(target string, depth int) {
	if !strings.HasPrefix(target, "/") {
		p.problem("an .include with a relative path was not followed")
		return
	}
	if depth >= maxDepth {
		p.problem("too many nested .include directives")
		return
	}
	var files []string
	if list, err := p.fs.ListDir(target); err == nil {
		for _, f := range list {
			if strings.HasSuffix(f, ".cnf") || strings.HasSuffix(f, ".conf") {
				files = append(files, f)
			}
		}
		sort.Strings(files)
	} else {
		files = []string{target}
	}
	for _, f := range files {
		if p.seen[f] {
			p.problem("an .include that forms a loop was not followed")
			continue
		}
		if p.files >= maxFiles {
			p.problem("too many included files")
			return
		}
		data, err := p.fs.ReadFile(f)
		if err != nil {
			p.problem("an included file could not be read")
			continue
		}
		p.seen[f] = true
		p.files++
		p.parse(f, data, depth+1)
	}
}

// stripComment は、引用符の外にある # 以降（行頭の ; も）を取り除く。
func stripComment(s string) string {
	if t := strings.TrimSpace(s); strings.HasPrefix(t, ";") {
		return ""
	}
	quote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '#':
			return s[:i]
		}
	}
	return s
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}
