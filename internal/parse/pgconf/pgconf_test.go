package pgconf

import (
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// memFS は、メモリ上のファイル。
type memFS map[string]string

func (m memFS) ReadFile(p string) ([]byte, error) {
	if v, ok := m[p]; ok {
		return []byte(v), nil
	}
	return nil, errors.New("not found")
}

func (m memFS) Glob(pattern string) ([]string, error) {
	var out []string
	for p := range m {
		if ok, _ := filepath.Match(pattern, p); ok {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

func last(ss []Setting) map[string]Setting {
	m := map[string]Setting{}
	for _, s := range ss {
		m[s.Name] = s
	}
	return m
}

// 以下の設定は、検証ラボで PostgreSQL（10〜17）を実際に起動したときのもの。期待値は、サーバー自身の答え
// （pg_settings の setting、sourcefile、sourceline）。同じ項目は後に書かれたものが効き、include した先も、その位置で読まれる。
// include_dir は、名前が「.conf」で終わるファイルを名前の順に読む。
func TestParseIncludesAndLastWins(t *testing.T) {
	const main = "/etc/postgresql/17/main/postgresql.conf"
	fs := memFS{
		main: "# comment\n#ssl = off\nlisten_addresses = '127.0.0.1'\nport = 5432\nssl = on\n" +
			"ssl_cert_file = '/etc/lab/pg/rsa.crt'\nssl_key_file = '/etc/lab/pg/rsa.key'\n" +
			"ssl_ciphers = 'HIGH:!aNULL'\nssl_ciphers = 'HIGH:!aNULL:!kRSA' # later wins\n" +
			"include 'lab-extra.conf'\ninclude_dir 'lab.d'\ninclude_if_exists 'missing.conf'\n",
		"/etc/postgresql/17/main/lab-extra.conf":      "ssl_prefer_server_ciphers = off\n",
		"/etc/postgresql/17/main/lab.d/10-curve.conf": "ssl_ecdh_curve = 'secp521r1'\n",
		"/etc/postgresql/17/main/lab.d/20-curve.conf": "ssl_ecdh_curve = 'secp384r1'\n",
		"/etc/postgresql/17/main/lab.d/README.txt":    "ssl_ciphers = 'ignored'\n",
		"/etc/postgresql/17/main/lab.d/.hidden.conf":  "ssl_ciphers = 'ignored'\n",
	}
	ss, problems := Parse(main, fs)
	if len(problems) != 0 {
		t.Errorf("problems = %v", problems)
	}
	got := last(ss)
	for name, want := range map[string]string{
		"ssl": "on", "port": "5432", "listen_addresses": "127.0.0.1", "ssl_cert_file": "/etc/lab/pg/rsa.crt",
		"ssl_ciphers": "HIGH:!aNULL:!kRSA", "ssl_ecdh_curve": "secp384r1", "ssl_prefer_server_ciphers": "off",
	} {
		if got[name].Value != want {
			t.Errorf("%s = %q, want %q", name, got[name].Value, want)
		}
	}
	if s := got["ssl_ciphers"]; s.File != main || s.Line != 9 {
		t.Errorf("ssl_ciphers at %s:%d", s.File, s.Line)
	}
	if s := got["ssl_ecdh_curve"]; s.File != "/etc/postgresql/17/main/lab.d/20-curve.conf" || s.Line != 1 {
		t.Errorf("ssl_ecdh_curve at %s:%d", s.File, s.Line)
	}
	if s := got["ssl_prefer_server_ciphers"]; s.File != "/etc/postgresql/17/main/lab-extra.conf" {
		t.Errorf("ssl_prefer_server_ciphers at %s", s.File)
	}
	// 効かない記載も、順に返す
	n := 0
	for _, s := range ss {
		if s.Name == "ssl_ciphers" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("ssl_ciphers appears %d times", n)
	}
}

// 書き方: 「=」は省略できる。名前は大文字小文字を区別しない。値の引用符の中では、引用符を 2 つ重ねるか「\'」で書く。
// 引用符のない値は、空白か「#」まで。
func TestSyntax(t *testing.T) {
	fs := memFS{"/c": "SSL on\nssl_ciphers 'HIGH'   # c\nssl_cert_file='/a''b.crt'\nssl_key_file = '/a\\'b.key'\nport=5433#x\n" +
		"ssl_ecdh_curve = prime256v1 # unquoted\n\tssl_dh_params_file\t=\t'/etc/dh.pem'\n"}
	ss, problems := Parse("/c", fs)
	if len(problems) != 0 {
		t.Errorf("problems = %v", problems)
	}
	got := last(ss)
	for name, want := range map[string]string{"ssl": "on", "ssl_ciphers": "HIGH", "ssl_cert_file": "/a'b.crt", "ssl_key_file": "/a'b.key",
		"port": "5433", "ssl_ecdh_curve": "prime256v1", "ssl_dh_params_file": "/etc/dh.pem"} {
		if got[name].Value != want {
			t.Errorf("%s = %q, want %q", name, got[name].Value, want)
		}
	}
}

// 壊れた入力、読めない include、循環する include でも、止まらずに問題として報告する。
func TestMalformed(t *testing.T) {
	fs := memFS{
		"/c":         "ssl = 'unterminated\nok = 1\n= 2\ninclude 'missing.conf'\ninclude 'loop.conf'\n",
		"/loop.conf": "include 'loop.conf'\nssl_ciphers = 'X'\n",
	}
	ss, problems := Parse("/c", fs)
	got := last(ss)
	if got["ok"].Value != "1" || got["ssl_ciphers"].Value != "X" || len(problems) < 3 {
		t.Errorf("settings = %+v problems = %v", ss, problems)
	}
	if _, problems := Parse("/missing", fs); len(problems) == 0 {
		t.Error("a missing file must be reported")
	}
	big := memFS{"/c": strings.Repeat("a = 1\n", 2_000_000)}
	if _, problems := Parse("/c", big); len(problems) == 0 {
		t.Error("an oversized file must be reported")
	}
}
