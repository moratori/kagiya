package nginxconf

import (
	"io/fs"
	"path"
	"sort"
	"strings"
	"testing"
)

type mapFS map[string]string

func (m mapFS) ReadFile(p string) ([]byte, error) {
	if s, ok := m[p]; ok {
		return []byte(s), nil
	}
	return nil, fs.ErrNotExist
}

func (m mapFS) Glob(pattern string) ([]string, error) {
	var out []string
	for p := range m {
		if ok, _ := path.Match(pattern, p); ok {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

func render(ds []Directive) string {
	var out []string
	for _, d := range ds {
		out = append(out, d.Name+" ["+strings.Join(d.Args, "|")+"] "+d.Context+" "+path.Base(d.File)+":"+itoa(d.Line))
	}
	return strings.Join(out, "\n")
}

func itoa(n int) string {
	s := ""
	for ; n > 0; n /= 10 {
		s = string(rune('0'+n%10)) + s
	}
	return s
}

func TestParseBlocksIncludesAndQuoting(t *testing.T) {
	m := mapFS{
		"/etc/nginx/nginx.conf":      "user nginx;\n# comment\nhttp {\n    log_format main '$remote_addr \"$request\" ; { }';\n    ssl_protocols TLSv1.2 TLSv1.3; # trailing comment\n    include /etc/nginx/conf.d/*.conf;\n    include mime.types;\n    server {\n        listen 80;\n        location ~ \\.php$ { fastcgi_pass unix:/run/php.sock; }\n    }\n}\nstream { server { listen 993 ssl; ssl_certificate \"/etc/pki/tls/certs/a b.pem\"; } }\n",
		"/etc/nginx/conf.d/tls.conf": "server {\n  listen 443 ssl;\n  server_name www.example.jp;\n  ssl_ciphers HIGH:!aNULL;\n  set $x \"${host}y\";\n}\n",
		"/etc/nginx/conf.d/z.txt":    "ssl_ciphers LOW;\n",
		"/etc/nginx/mime.types":      "types { text/html html; }\n",
	}
	ds, problems := Parse("/etc/nginx/nginx.conf", m)
	if len(problems) != 0 {
		t.Errorf("problems = %v", problems)
	}
	want := strings.Join([]string{
		"user [nginx]  nginx.conf:1",
		`log_format [main|$remote_addr "$request" ; { }] http nginx.conf:4`, // 引用符の中の ; { } は区切りではない
		"ssl_protocols [TLSv1.2|TLSv1.3] http nginx.conf:5",
		// 取り込まれたファイルは、include のあった位置（http の中）に入る。server は現れた順に番号が付く
		"listen [443|ssl] http/server#1 tls.conf:2",
		"server_name [www.example.jp] http/server#1 tls.conf:3",
		"ssl_ciphers [HIGH:!aNULL] http/server#1 tls.conf:4",
		"set [$x|${host}y] http/server#1 tls.conf:5", // ${...} の波括弧はブロックではない
		"text/html [html] http/types mime.types:1",
		"listen [80] http/server#2 nginx.conf:9",
		"fastcgi_pass [unix:/run/php.sock] http/server#2/location nginx.conf:10",
		"listen [993|ssl] stream/server#3 nginx.conf:13",
		"ssl_certificate [/etc/pki/tls/certs/a b.pem] stream/server#3 nginx.conf:13",
	}, "\n")
	if got := render(ds); got != want {
		t.Errorf("directives:\n%s\nwant:\n%s", got, want)
	}
}

func TestParseProblems(t *testing.T) {
	for name, m := range map[string]mapFS{
		"unbalanced close": {"/n.conf": "http { } }\nuser x;\n"},
		"unterminated":     {"/n.conf": "http { ssl_protocols TLSv1.2\n"},
		"include loop":     {"/n.conf": "include /n.conf;\n"},
		"missing main":     {},
	} {
		if _, problems := Parse("/n.conf", m); len(problems) == 0 {
			t.Errorf("%s: no problem reported", name)
		}
	}
	// 取り込み先がないのは問題ではない
	if ds, problems := Parse("/n.conf", mapFS{"/n.conf": "include /nope/*.conf;\nuser x;\n"}); len(problems) != 0 || len(ds) != 1 {
		t.Errorf("missing include: %v %v", ds, problems)
	}
}

func FuzzParse(f *testing.F) {
	f.Add("http { server { listen 443 ssl; include /b; } }\n'\"${x}")
	f.Fuzz(func(t *testing.T, s string) { Parse("/a", mapFS{"/a": s, "/b": s}) })
}
