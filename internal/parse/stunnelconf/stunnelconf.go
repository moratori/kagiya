// Package stunnelconf は stunnel の設定ファイルを読む。
//
// 文法: 1行に「名前 = 値」。「;」か「#」で始まる行はコメント。「[名前]」の行からサービスの節が始まり、
// それより前は全体の設定（サービスの設定の既定にもなる）。項目の名前は大文字小文字を区別しない。
package stunnelconf

import (
	"strconv"
	"strings"
)

// Directive は設定の1項目。
type Directive struct {
	Service string // 属するサービスの名前。全体の設定なら空
	Key     string // 項目の名前（小文字にそろえたもの）
	Value   string
	File    string
	Line    int
}

const (
	maxSize  = 1 << 20
	maxLines = 100_000
	maxLine  = 16384
)

// Parse は設定ファイル1つを読む。読めなかった行は problems に報告し、残りを返す。
func Parse(file string, data []byte) (ds []Directive, problems []string) {
	if len(data) > maxSize {
		return nil, []string{"the configuration file is too large"}
	}
	service := ""
	for i, raw := range strings.Split(string(data), "\n") {
		n := i + 1
		if n > maxLines {
			problems = append(problems, "too many lines")
			break
		}
		bad := func(why string) { problems = append(problems, "line "+strconv.Itoa(n)+": "+why) }
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}
		if len(line) > maxLine || strings.ContainsFunc(line, func(r rune) bool { return r < 0x20 && r != '\t' || r == 0x7f }) {
			bad("not interpreted (too long or control character)")
			continue
		}
		if line[0] == '[' {
			if !strings.HasSuffix(line, "]") {
				bad("not interpreted (unterminated section name)")
				continue
			}
			service = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		if !ok || k == "" {
			bad("not interpreted (not a name = value line)")
			continue
		}
		ds = append(ds, Directive{Service: service, Key: k, Value: strings.TrimSpace(v), File: file, Line: n})
	}
	return ds, problems
}
