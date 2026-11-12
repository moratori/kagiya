package haproxyconf

import (
	"strings"
	"testing"
)

func find(ds []Directive, section, keyword string) []Directive {
	var out []Directive
	for _, d := range ds {
		if d.Section == section && d.Keyword == keyword {
			out = append(out, d)
		}
	}
	return out
}

func TestParse(t *testing.T) {
	conf := `# HAProxy の設定
global
    maxconn 100   # 行末のコメント
    ssl-default-bind-ciphers PROFILE=SYSTEM
	tune.ssl.default-dh-param 2048

defaults
    mode http
    timeout connect 5s

frontend  fe_web
    bind 127.0.0.1:8443 ssl crt /etc/lab/rsa.pem crt "/etc/lab/with space.pem" ciphers ECDHE+AESGCM:AES128-SHA
    bind :80
    acl is_api path_beg /api\ v1 '#not-a-comment'
    default_backend be_app
listen stats
    bind "${STATS_ADDR}":8404 ssl crt $CRT_DIR/stats.pem
backend be_app
    server app1 10.0.0.1:8443 ssl verify required ca-file /etc/lab/ca.pem ciphers HIGH
`
	ds, problems := Parse("/etc/haproxy/haproxy.cfg", []byte(conf))
	if len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	g := find(ds, "global", "ssl-default-bind-ciphers")
	if len(g) != 1 || strings.Join(g[0].Args, "|") != "PROFILE=SYSTEM" || g[0].Line != 4 || g[0].File != "/etc/haproxy/haproxy.cfg" || g[0].Name != "" {
		t.Errorf("global = %+v", g)
	}
	if d := find(ds, "global", "maxconn"); len(d) != 1 || strings.Join(d[0].Args, "|") != "100" {
		t.Errorf("a trailing comment must be dropped: %+v", d)
	}
	if d := find(ds, "global", "tune.ssl.default-dh-param"); len(d) != 1 || d[0].Args[0] != "2048" {
		t.Errorf("tab-indented line: %+v", d)
	}
	b := find(ds, "frontend", "bind")
	if len(b) != 2 || b[0].Name != "fe_web" || b[0].Line != 12 {
		t.Fatalf("bind = %+v", b)
	}
	if strings.Join(b[0].Args, "|") != "127.0.0.1:8443|ssl|crt|/etc/lab/rsa.pem|crt|/etc/lab/with space.pem|ciphers|ECDHE+AESGCM:AES128-SHA" {
		t.Errorf("bind args = %q", b[0].Args)
	}
	// 引用符の中の # と、バックスラッシュで逃がした空白は、そのまま値になる
	if a := find(ds, "frontend", "acl"); len(a) != 1 || strings.Join(a[0].Args, "|") != "is_api|path_beg|/api v1|#not-a-comment" {
		t.Errorf("acl = %+v", a)
	}
	// 環境変数を含む値は展開しない。含んでいることを印として残す
	l := find(ds, "listen", "bind")
	if len(l) != 1 || l[0].Name != "stats" || !l[0].HasVariable || l[0].Args[0] != "${STATS_ADDR}:8404" {
		t.Errorf("listen bind = %+v", l)
	}
	if b[0].HasVariable {
		t.Error("a line without variables must not be marked")
	}
	if s := find(ds, "backend", "server"); len(s) != 1 || s[0].Name != "be_app" || s[0].Args[len(s[0].Args)-1] != "HIGH" {
		t.Errorf("server = %+v", s)
	}
	// 節の始まりの行そのものは、項目としては返さない
	for _, d := range ds {
		if d.Keyword == "global" || d.Keyword == "frontend" || d.Keyword == "defaults" {
			t.Errorf("a section line was returned as a directive: %+v", d)
		}
	}
}

func TestParseProblems(t *testing.T) {
	// 閉じていない引用符は、その行を捨てて問題として報告する（後の行は読む）
	ds, problems := Parse("/x.cfg", []byte("global\n    log \"unterminated\n    maxconn 5\n"))
	if len(problems) != 1 || !strings.Contains(problems[0], "line 2") {
		t.Errorf("problems = %v", problems)
	}
	if d := find(ds, "global", "maxconn"); len(d) != 1 {
		t.Errorf("the following line must still be read: %+v", ds)
	}
	// 節の外に書かれた項目は、節の名前が空になる
	ds, _ = Parse("/x.cfg", []byte("maxconn 5\nglobal\n"))
	if len(ds) != 1 || ds[0].Section != "" {
		t.Errorf("directive before any section = %+v", ds)
	}
	// 大きすぎる入力は読まない
	if _, problems := Parse("/x.cfg", []byte(strings.Repeat("a b\n", 400_000))); len(problems) == 0 {
		t.Error("an oversized file must be reported")
	}
	// 名前や値に制御文字が入った行は捨てる
	ds, problems = Parse("/x.cfg", []byte("global\n    log a\x00b\n"))
	if len(ds) != 0 || len(problems) != 1 {
		t.Errorf("control characters: %+v %v", ds, problems)
	}
}
