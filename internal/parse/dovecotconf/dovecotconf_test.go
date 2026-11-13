package dovecotconf

import (
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

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

// value は、指定した入れ子（空なら最上位）での、項目の最後の記載を返す。
func value(ds []Directive, section, key string) (Directive, bool) {
	var found Directive
	ok := false
	for _, d := range ds {
		if d.Key == key && strings.Join(d.Sections, " > ") == section {
			found, ok = d, true
		}
	}
	return found, ok
}

// 以下は、検証ラボで Dovecot（2.3.16、2.4.1）を実際に起動したときの設定と同じ形。期待値は、Dovecot 自身の出力
// （doveconf -n、doveconf -f protocol=imap）: 取り込んだファイルは名前の順に読まれ、後に読まれた記載が効く。
// protocol imap { } の中の記載は、imap にだけ効く。
func TestParse(t *testing.T) {
	fs := memFS{
		"/etc/dovecot/dovecot.conf": "# comment\nprotocols = imap pop3\n!include_try /usr/share/dovecot/protocols.d/*.protocol\n" +
			"dict {\n  #quota = mysql:/etc/dovecot/dovecot-dict-sql.conf.ext\n}\n!include conf.d/*.conf\n!include_try local.conf\n",
		"/etc/dovecot/conf.d/10-ssl.conf": "ssl = required\nssl_cert = </etc/pki/dovecot/certs/dovecot.pem\nssl_key = </etc/pki/dovecot/private/dovecot.pem\n" +
			"#ssl_dh = </etc/dovecot/dh.pem\nssl_cipher_list = PROFILE=SYSTEM\n",
		"/etc/dovecot/conf.d/10-master.conf": "service imap-login {\n  inet_listener imap {\n    #port = 143\n  }\n  inet_listener imaps {\n    port = 993\n    ssl = yes\n  }\n  chroot =\n}\n",
		"/etc/dovecot/conf.d/zz-lab.conf": "listen = 127.0.0.1\nssl = yes\nssl_cert = </etc/lab/rsa.crt\nssl_key = </etc/lab/rsa.key\n" +
			"ssl_cipher_list = HIGH:!aNULL:!kRSA\nprotocol imap {\n  ssl_cipher_list = ECDHE+AESGCM\n}\n",
		"/etc/dovecot/conf.d/README": "ssl = no\n",
	}
	ds, problems := Parse("/etc/dovecot/dovecot.conf", fs)
	if len(problems) != 0 {
		t.Errorf("problems = %v", problems)
	}
	for _, c := range []struct{ section, key, want, file string }{
		{"", "protocols", "imap pop3", "/etc/dovecot/dovecot.conf"},
		{"", "ssl", "yes", "/etc/dovecot/conf.d/zz-lab.conf"}, // 10-ssl.conf の required より後に読まれる
		{"", "ssl_cert", "</etc/lab/rsa.crt", "/etc/dovecot/conf.d/zz-lab.conf"},
		{"", "ssl_cipher_list", "HIGH:!aNULL:!kRSA", "/etc/dovecot/conf.d/zz-lab.conf"},
		{"protocol imap", "ssl_cipher_list", "ECDHE+AESGCM", "/etc/dovecot/conf.d/zz-lab.conf"},
		{"service imap-login", "chroot", "", "/etc/dovecot/conf.d/10-master.conf"},
		{"service imap-login > inet_listener imaps", "port", "993", "/etc/dovecot/conf.d/10-master.conf"},
		{"service imap-login > inet_listener imaps", "ssl", "yes", "/etc/dovecot/conf.d/10-master.conf"},
	} {
		d, ok := value(ds, c.section, c.key)
		if !ok || d.Value != c.want || d.File != c.file {
			t.Errorf("[%s] %s = %q (%s) ok=%v, want %q (%s)", c.section, c.key, d.Value, d.File, ok, c.want, c.file)
		}
	}
	if d, _ := value(ds, "protocol imap", "ssl_cipher_list"); d.Line != 7 {
		t.Errorf("line = %d", d.Line)
	}
	// コメントの行と、「.conf」で終わらないファイルは読まない
	if _, ok := value(ds, "", "ssl_dh"); ok {
		t.Error("a commented-out setting was read")
	}
	if _, ok := value(ds, "dict", "quota"); ok {
		t.Error("a commented-out setting inside a section was read")
	}
}

// 2.4 の書き方（値は、ファイルの名前をそのまま書く）と、値の後ろのコメント、引用符。
func TestSyntax(t *testing.T) {
	fs := memFS{"/c": "dovecot_config_version = 2.4.0\nssl_server_cert_file = /etc/dovecot/private/dovecot.pem\nssl_min_protocol = TLSv1.2 # comment\n" +
		"ssl_cipher_list = \"HIGH:!aNULL\"\nssl_server {\n  dh_file = /etc/dh.pem\n}\nlocal_name mail.example.jp {\n  ssl_server_cert_file = /etc/other.pem\n}\n"}
	ds, problems := Parse("/c", fs)
	if len(problems) != 0 {
		t.Errorf("problems = %v", problems)
	}
	for _, c := range [][3]string{{"", "ssl_server_cert_file", "/etc/dovecot/private/dovecot.pem"}, {"", "ssl_min_protocol", "TLSv1.2"}, {"", "ssl_cipher_list", "HIGH:!aNULL"},
		{"ssl_server", "dh_file", "/etc/dh.pem"}, {"local_name mail.example.jp", "ssl_server_cert_file", "/etc/other.pem"}} {
		if d, ok := value(ds, c[0], c[1]); !ok || d.Value != c[2] {
			t.Errorf("[%s] %s = %q ok=%v, want %q", c[0], c[1], d.Value, ok, c[2])
		}
	}
}

// 壊れた入力、読めない取り込み先、循環する取り込みでも、止まらずに問題として報告する。
func TestMalformed(t *testing.T) {
	fs := memFS{"/c": "ssl = yes\n}\nprotocol imap {\n  ssl = no\n!include missing.conf\n!include loop.conf\nnot a setting\n", "/loop.conf": "!include loop.conf\nx = 1\n"}
	ds, problems := Parse("/c", fs)
	if d, ok := value(ds, "", "ssl"); !ok || d.Value != "yes" || len(problems) < 3 {
		t.Errorf("directives = %+v problems = %v", ds, problems)
	}
	if _, problems := Parse("/missing", fs); len(problems) == 0 {
		t.Error("a missing file must be reported")
	}
	if _, problems := Parse("/c", memFS{"/c": strings.Repeat("a = 1\n", 2_000_000)}); len(problems) == 0 {
		t.Error("an oversized file must be reported")
	}
}
