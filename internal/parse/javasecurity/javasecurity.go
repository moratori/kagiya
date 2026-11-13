// Package javasecurity は、JDK のセキュリティの設定ファイル（java.security と、そこから取り込まれるファイル）を読む。
//
// 読み方は、検証ラボで、この読み方で組み立てた値が JDK 自身の報告（Security.getProperty）と一致することを確かめたもの
// （8 つのディストリの OpenJDK 8 / 11 / 17 / 21 / 25）。
//
//	名前=値     区切りは「=」「:」または空白。行末の「\」で次の行に続く（次の行の先頭の空白は捨てる）。
//	            「#」「!」で始まる行はコメント。同じ名前は、後に読まれたものが効く。
//	include パス  その位置でファイルを取り込む（JDK 24 以降。RHEL 系の JDK 25 が、暗号ポリシーにつなぐのに使っている）。
//	            パスの ${名前} はシステムプロパティで、指定がなければ空になる。相対パスは、書かれているファイルのあるディレクトリから。
//
// ファイルは読むだけで、値の意味は解釈しない（解釈は internal/jsse）。
package javasecurity

import (
	"path"
	"strings"
)

// FS は、設定ファイルを読む手段。
type FS interface {
	ReadFile(path string) ([]byte, error)
}

// Entry は、設定の 1 項目（効いている記載）。
type Entry struct {
	Name  string
	Value string
	File  string
	Line  int // 記載の始まりの行
}

// File は、読み取った結果。
type File struct {
	Files    []string // 読んだファイル（読んだ順）
	Included bool     // include での取り込みがあった
	Problems []string // 読めなかったもの、捨てた記載

	entries map[string]Entry
}

// Get は、名前に対して効いている記載を返す。
func (f *File) Get(name string) (Entry, bool) {
	e, ok := f.entries[name]
	return e, ok
}

const (
	maxDepth = 8       // 取り込みの入れ子
	maxFiles = 32      // 読むファイルの数
	maxLines = 20000   // 1 ファイルの行数
	maxEntry = 1 << 16 // 1 項目の長さ（継続行を含む）
)

// Load は、java.security を読む。vars は、include のパスに書かれた ${名前} の値（ないものは空になる）。
func Load(file string, fs FS, vars map[string]string) *File {
	f := &File{entries: map[string]Entry{}}
	f.load(file, fs, vars, 0)
	return f
}

func (f *File) problem(s string) {
	if len(f.Problems) < 64 {
		f.Problems = append(f.Problems, s)
	}
}

func (f *File) load(file string, fs FS, vars map[string]string, depth int) {
	if depth > maxDepth {
		f.problem(file + ": includes are nested too deep")
		return
	}
	if len(f.Files) >= maxFiles {
		f.problem(file + ": too many included files")
		return
	}
	data, err := fs.ReadFile(file)
	if err != nil {
		f.problem(file + ": cannot be read")
		return
	}
	f.Files = append(f.Files, file)
	lines := strings.Split(string(data), "\n")
	if len(lines) > maxLines {
		f.problem(file + ": too many lines")
		lines = lines[:maxLines]
	}
	for i := 0; i < len(lines); {
		start := i + 1
		l := strings.TrimLeft(strings.TrimRight(lines[i], "\r"), " \t\f")
		i++
		if l == "" || l[0] == '#' || l[0] == '!' {
			continue
		}
		tooLong := false
		for continues(l) && i < len(lines) {
			l = l[:len(l)-1] + strings.TrimLeft(strings.TrimRight(lines[i], "\r"), " \t\f")
			i++
			if len(l) > maxEntry {
				tooLong = true
				l = l[:maxEntry] // 残りの継続行は読み進めるが、中身は捨てる
			}
		}
		name, value := split(l)
		if tooLong || len(l) > maxEntry {
			f.problem(file + ": an entry is too long: " + clip(name))
			continue
		}
		if hasControl(l) {
			f.problem(file + ": an entry contains a control character")
			continue
		}
		if name == "include" {
			f.Included = true
			target := expand(value, vars)
			if target == "" {
				f.problem(file + ": include without a path")
				continue
			}
			if !strings.HasPrefix(target, "/") {
				target = path.Dir(file) + "/" + target
			}
			f.load(path.Clean(target), fs, vars, depth+1)
			continue
		}
		f.entries[name] = Entry{Name: name, Value: value, File: file, Line: start}
	}
}

// continues は、行が「\」で次の行に続くかを返す（末尾の「\」が奇数個）。
func continues(l string) bool {
	n := 0
	for n < len(l) && l[len(l)-1-n] == '\\' {
		n++
	}
	return n%2 == 1
}

// split は、1 項目を名前と値に分ける（区切りは「=」「:」または空白。区切りの前後の空白は捨てる）。
func split(l string) (name, value string) {
	i := strings.IndexAny(l, "=: \t\f")
	if i < 0 {
		return l, ""
	}
	name = l[:i]
	rest := strings.TrimLeft(l[i:], " \t\f")
	if rest != "" && (rest[0] == '=' || rest[0] == ':') && (l[i] == ' ' || l[i] == '\t' || l[i] == '\f') {
		rest = rest[1:] // 「名前 = 値」のように、空白の後に区切りがある書き方
	} else if l[i] == '=' || l[i] == ':' {
		rest = l[i+1:]
	}
	return name, strings.TrimSpace(rest)
}

// expand は、パスの ${名前} を置き換える。値のないものは空になる。
func expand(s string, vars map[string]string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, "${")
		if i < 0 {
			break
		}
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			break
		}
		b.WriteString(s[:i])
		b.WriteString(vars[s[i+2:i+j]])
		s = s[i+j+1:]
	}
	b.WriteString(s)
	return b.String()
}

func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 && s[i] != '\t' || s[i] == 0x7f {
			return true
		}
	}
	return false
}

func clip(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}
