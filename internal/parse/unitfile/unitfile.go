// Package unitfile は systemd のユニットファイルと、そこから読み込まれる環境ファイルを読む。
// サービスがどんな引数で起動されるか、起動時に有効かどうかを、systemctl を実行せずに知るために使う。
package unitfile

import (
	"regexp"
	"strings"
)

type entry struct{ section, key, value string }

type Unit struct{ entries []entry }

// Parse はユニットファイルを読む。
func Parse(data []byte) *Unit {
	u := &Unit{}
	section := ""
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], "\r")
		for strings.HasSuffix(line, "\\") && i+1 < len(lines) {
			i++
			line = strings.TrimRight(strings.TrimSuffix(line, "\\"), " \t") + " " + strings.TrimSpace(strings.TrimRight(lines[i], "\r"))
		}
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' && line[len(line)-1] == ']' {
			section = line[1 : len(line)-1]
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if len(u.entries) < 10_000 {
			u.entries = append(u.entries, entry{section, strings.TrimSpace(k), strings.TrimSpace(v)})
		}
	}
	return u
}

// Values は、指定した節・キーの値を現れた順に返す。空の代入は、それまでの値を取り消す（systemd の規則）。
func (u *Unit) Values(section, key string) []string {
	var out []string
	for _, e := range u.entries {
		if e.section != section || e.key != key {
			continue
		}
		if e.value == "" {
			out = nil
			continue
		}
		out = append(out, e.value)
	}
	return out
}

// EnvEntry は環境ファイルの1行。
type EnvEntry struct {
	Key, Value string
	Line       int
}

var envKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ParseEnv は「名前=値」形式の環境ファイルを読む。
func ParseEnv(data []byte) []EnvEntry {
	var out []EnvEntry
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || !envKey.MatchString(k) {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '\'' || v[0] == '"') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		if len(out) < 10_000 {
			out = append(out, EnvEntry{Key: k, Value: v, Line: i + 1})
		}
	}
	return out
}

// Word は、コマンド行の1語。
type Word struct {
	Text     string
	Variable string // 語全体が $NAME または ${NAME} の場合の変数名
	Braced   bool   // ${NAME} の形（展開しても1語のまま）
}

var wholeVar = regexp.MustCompile(`^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))$`)

// Words はコマンド行を語に分ける（引用符の中の空白は区切りにしない）。変数は展開しない。
func Words(cmd string) []Word {
	var out []Word
	var cur strings.Builder
	quote, has, quoted := byte(0), false, false
	flush := func() {
		if !has {
			return
		}
		w := Word{Text: cur.String()}
		if !quoted {
			if m := wholeVar.FindStringSubmatch(w.Text); m != nil {
				w.Variable, w.Braced = m[1]+m[2], m[1] != ""
			}
		}
		out = append(out, w)
		cur.Reset()
		has, quoted = false, false
	}
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote, has, quoted = c, true, true
		case c == ' ' || c == '\t':
			flush()
		default:
			cur.WriteByte(c)
			has = true
		}
	}
	flush()
	return out
}

// SplitCommand はコマンド行を語に分け、変数を展開する。
// 引用符のない $NAME は値を空白で分けて複数の語にし（空なら何も残らない）、${NAME} は1語のまま展開する。
func SplitCommand(cmd string, env map[string]string) []string {
	var out []string
	for _, w := range Words(cmd) {
		switch {
		case w.Variable == "":
			out = append(out, w.Text)
		case w.Braced:
			if v, ok := env[w.Variable]; ok && v != "" {
				out = append(out, v)
			}
		default:
			out = append(out, strings.Fields(env[w.Variable])...)
		}
	}
	return out
}
