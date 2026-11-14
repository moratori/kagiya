// Package supervisorconf は、supervisord（プロセス管理ツール）の設定から、プログラムの起動のしかたを読む。
//
// 読むのは [program:名前] の節の command、directory、environment、autostart だけ。
// 読み方は、実物の supervisord（supervisor 4.2.5）にプログラムを起動させて確かめた:
//   - command は、シェルを通さずに語に分けられる（引用符は外れる。$HOME などは置き換わらない）
//   - 行の途中の「 ;」より後ろは注釈
//   - environment は「名前="値",名前=値」の並び
//   - %(ENV_名前)s、%(here)s などの置き換えは、ここでは解釈しない（supervisord 自身の環境に依存する）
package supervisorconf

import (
	"regexp"
	"strings"
)

const (
	maxPrograms = 256
	maxLine     = 8192
	maxArgs     = 256
)

// Program は、プログラム 1 つの起動のしかた。
type Program struct {
	Name      string
	Line      int      // 節の見出しの行
	Argv      []string // command を語に分けたもの
	Directory string   // 作業ディレクトリ（指定がなければ空。その場合は supervisord の作業ディレクトリになる）
	Env       map[string]string
	// 値に %(...)s の置き換えを含み、値を持たなかった環境変数
	EnvUnexpanded map[string]bool
	Autostart     bool // supervisord の起動時に、このプログラムも起動する（既定は true）
	Unexpanded    bool // command に %(...)s の置き換えが含まれる（語は、置き換え前のまま）
}

var (
	programName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	envName     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
)

// Parse は、設定ファイル 1 つからプログラムの定義を読む。
func Parse(data []byte) []Program {
	var out []Program
	var cur *Program
	flush := func() {
		if cur != nil && len(cur.Argv) > 0 && len(out) < maxPrograms {
			out = append(out, *cur)
		}
		cur = nil
	}
	for i, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if len(line) > maxLine {
			continue
		}
		t := strings.TrimSpace(line)
		if t == "" || t[0] == ';' || t[0] == '#' {
			continue
		}
		if t[0] == '[' {
			flush()
			if name, ok := strings.CutPrefix(t, "[program:"); ok {
				if name, ok = strings.CutSuffix(strings.TrimSpace(name), "]"); ok && programName.MatchString(name) {
					cur = &Program{Name: name, Line: i + 1, Env: map[string]string{}, EnvUnexpanded: map[string]bool{}, Autostart: true}
				}
			}
			continue
		}
		if cur == nil {
			continue
		}
		key, value, ok := strings.Cut(t, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		// 行の途中の「 ;」より後ろは注釈
		if j := strings.Index(value, " ;"); j >= 0 {
			value = value[:j]
		}
		value = strings.TrimSpace(value)
		switch key {
		case "command":
			cur.Unexpanded = strings.Contains(value, "%(")
			cur.Argv = split(value)
		case "directory":
			if strings.HasPrefix(value, "/") && !strings.Contains(value, "%(") {
				cur.Directory = value
			}
		case "autostart":
			cur.Autostart = !strings.EqualFold(value, "false")
		case "environment":
			for _, kv := range splitList(value) {
				k, v, ok := strings.Cut(kv, "=")
				k = strings.TrimSpace(k)
				if !ok || !envName.MatchString(k) {
					continue
				}
				v = strings.TrimSpace(v)
				if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
					v = v[1 : len(v)-1]
				}
				if strings.Contains(v, "%(") {
					cur.EnvUnexpanded[k] = true
					continue
				}
				cur.Env[k] = v
			}
		}
	}
	flush()
	return out
}

// split は、起動コマンドを語に分ける（空白で区切り、引用符の中は 1 語。シェルの置き換えはしない）。
// 引用符が閉じていない場合は、何も返さない。
func split(s string) []string {
	var out []string
	var cur strings.Builder
	in, quote := false, byte(0)
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			} else if ch == '\\' && quote == '"' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
				i++
				cur.WriteByte(s[i])
			} else {
				cur.WriteByte(ch)
			}
		case ch == '"' || ch == '\'':
			quote, in = ch, true
		case ch == ' ' || ch == '\t':
			if in {
				out = append(out, cur.String())
				cur.Reset()
				in = false
			}
		default:
			cur.WriteByte(ch)
			in = true
		}
	}
	if quote != 0 {
		return nil
	}
	if in {
		out = append(out, cur.String())
	}
	if len(out) > maxArgs {
		return nil
	}
	return out
}

// splitList は、「,」区切りの並びを分ける（引用符の中の「,」では分けない）。
func splitList(s string) []string {
	var out []string
	start, quote := 0, byte(0)
	for i := 0; i < len(s); i++ {
		switch ch := s[i]; {
		case quote != 0:
			if ch == quote {
				quote = 0
			}
		case ch == '"' || ch == '\'':
			quote = ch
		case ch == ',':
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if quote != 0 {
		return nil
	}
	return append(out, s[start:])
}
