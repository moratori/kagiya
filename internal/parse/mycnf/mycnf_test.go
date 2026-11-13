package mycnf

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

// 以下は、検証ラボで MariaDB（10.5）を実際に起動したときの設定。期待値は、同じファイルを MariaDB 自身の読み取り
// （my_print_defaults mysqld server mariadb mariadbd）に通した結果: グループの順ではなく、書かれた順に読まれ、
// 項目名の「-」と「_」は同じものとして扱われる。値を囲む引用符と、後ろのコメントは値に含まれない。
func TestParse(t *testing.T) {
	fs := memFS{
		"/etc/my.cnf":                            "# comment\n[client-server]\n!includedir /etc/my.cnf.d\n",
		"/etc/my.cnf.d/mariadb-server.cnf":       "[server]\n[mysqld]\ndatadir=/var/lib/mysql\nsocket=/var/lib/mysql/mysql.sock\nlog-error=/var/log/mariadb/mariadb.log\n",
		"/etc/my.cnf.d/enable_encryption.preset": "[mariadb]\nssl_cipher = IGNORED\n",
		"/etc/my.cnf.d/zz-lab.cnf": "[mysqld]\nbind-address = 127.0.0.1\nport = 3306\nskip-name-resolve\nssl_cert = /etc/lab/db/rsa.crt\nssl_key = /etc/lab/db/rsa.key\n" +
			"ssl-cipher = HIGH:!aNULL\nssl_cipher = \"HIGH:!aNULL:!kRSA\"   # later wins\n[mysqldump]\nssl_cipher = IGNORED\n[server]\nssl-cert=/etc/lab/db/ec.crt\nssl-key = /etc/lab/db/ec.key\n",
	}
	opts, problems := Parse("/etc/my.cnf", fs)
	if len(problems) != 0 {
		t.Errorf("problems = %v", problems)
	}
	var got []string
	for _, o := range opts {
		if o.Group == "mysqld" || o.Group == "server" || o.Group == "mariadb" || o.Group == "mariadbd" {
			got = append(got, o.Name+"="+o.Value)
		}
	}
	want := "datadir=/var/lib/mysql socket=/var/lib/mysql/mysql.sock log_error=/var/log/mariadb/mariadb.log bind_address=127.0.0.1 port=3306 skip_name_resolve= " +
		"ssl_cert=/etc/lab/db/rsa.crt ssl_key=/etc/lab/db/rsa.key ssl_cipher=HIGH:!aNULL ssl_cipher=HIGH:!aNULL:!kRSA ssl_cert=/etc/lab/db/ec.crt ssl_key=/etc/lab/db/ec.key"
	if strings.Join(got, " ") != want {
		t.Errorf("options =\n %s\nwant\n %s", strings.Join(got, " "), want)
	}
	// 場所
	for _, o := range opts {
		if o.Name == "ssl_cipher" && o.Value == "HIGH:!aNULL:!kRSA" && (o.File != "/etc/my.cnf.d/zz-lab.cnf" || o.Line != 8 || o.Group != "mysqld") {
			t.Errorf("location = %+v", o)
		}
	}
}

// 壊れた入力、読めない取り込み先、循環する取り込みでも、止まらずに問題として報告する。
func TestMalformed(t *testing.T) {
	fs := memFS{"/c": "ssl_cert = /before/any/group\n[mysqld\nssl_cipher = X\n[mysqld]\n= novalue\nok = 1\n!include /missing.cnf\n!include /loop.cnf\n", "/loop.cnf": "!include /loop.cnf\n[mysqld]\nx = 1\n"}
	opts, problems := Parse("/c", fs)
	names := map[string]string{}
	for _, o := range opts {
		names[o.Group+"."+o.Name] = o.Value
	}
	if names["mysqld.ok"] != "1" || names["mysqld.x"] != "1" || len(problems) < 3 {
		t.Errorf("options = %+v problems = %v", opts, problems)
	}
	if _, problems := Parse("/missing", fs); len(problems) == 0 {
		t.Error("a missing file must be reported")
	}
	if _, problems := Parse("/c", memFS{"/c": strings.Repeat("[mysqld]\na = 1\n", 1_000_000)}); len(problems) == 0 {
		t.Error("an oversized file must be reported")
	}
}
