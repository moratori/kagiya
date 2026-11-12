package apacheconf

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
		out = append(out, d.Name+" ["+d.Args+"] {"+strings.Join(d.Sections, " > ")+"} "+path.Base(d.File)+":"+itoa(d.Line))
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

// RHEL 9.9 の実物の形: ServerRoot からの相対パスで取り込み、モジュールは conf.modules.d で読み込む。
func TestRHELLayout(t *testing.T) {
	m := mapFS{
		"/etc/httpd/conf/httpd.conf":            "ServerRoot \"/etc/httpd\"\nListen 80\nInclude conf.modules.d/*.conf\nIncludeOptional conf.d/*.conf\n",
		"/etc/httpd/conf.modules.d/00-ssl.conf": "LoadModule ssl_module modules/mod_ssl.so\n",
		"/etc/httpd/conf.d/ssl.conf":            "Listen 443 https\n<VirtualHost _default_:443>\nSSLEngine on\n  SSLCipherSuite PROFILE=SYSTEM\nSSLCertificateFile /etc/pki/tls/certs/localhost.crt\n<Directory \"/var/www/cgi-bin\">\n    SSLOptions +StdEnvVars\n</Directory>\nCustomLog logs/ssl_request_log \\\n          \"%t %h\"\n</VirtualHost>\n",
	}
	r := Parse("/etc/httpd/conf/httpd.conf", m)
	if len(r.Problems) != 0 {
		t.Errorf("problems = %v", r.Problems)
	}
	if r.ServerRoot != "/etc/httpd" || strings.Join(r.Modules, ",") != "ssl_module" {
		t.Errorf("ServerRoot=%q Modules=%v", r.ServerRoot, r.Modules)
	}
	want := strings.Join([]string{
		"listen [80] {} httpd.conf:2",
		"loadmodule [ssl_module modules/mod_ssl.so] {} 00-ssl.conf:1",
		"listen [443 https] {} ssl.conf:1",
		"sslengine [on] {VirtualHost _default_:443} ssl.conf:3",
		"sslciphersuite [PROFILE=SYSTEM] {VirtualHost _default_:443} ssl.conf:4",
		"sslcertificatefile [/etc/pki/tls/certs/localhost.crt] {VirtualHost _default_:443} ssl.conf:5",
		"ssloptions [+StdEnvVars] {VirtualHost _default_:443 > Directory \"/var/www/cgi-bin\"} ssl.conf:7",
		"customlog [logs/ssl_request_log           \"%t %h\"] {VirtualHost _default_:443} ssl.conf:9", // 行末の \ は次の行へ続く
	}, "\n")
	if got := render(r.Directives); got != want {
		t.Errorf("directives:\n%s\nwant:\n%s", got, want)
	}
}

// Debian / Ubuntu の実物の形: <IfModule> の中身は、そのモジュールが読み込まれているときだけ有効。
func TestIfModule(t *testing.T) {
	ports := "Listen 80\n<IfModule ssl_module>\n\tListen 443\n</IfModule>\n<IfModule mod_gnutls.c>\n\tListen 8443\n</IfModule>\n<IfModule !mod_ssl.c>\n\tListen 8080\n</IfModule>\n"
	without := Parse("/etc/apache2/apache2.conf", mapFS{"/etc/apache2/apache2.conf": "IncludeOptional mods-enabled/*.load\nInclude ports.conf\n", "/etc/apache2/ports.conf": ports})
	if got := render(without.Directives); got != "listen [80] {} ports.conf:1\nlisten [8080] {} ports.conf:9" {
		t.Errorf("without ssl_module:\n%s", got)
	}
	if without.ServerRoot != "/etc/apache2" {
		t.Errorf("default ServerRoot = %q", without.ServerRoot)
	}
	with := Parse("/etc/apache2/apache2.conf", mapFS{
		"/etc/apache2/apache2.conf":          "IncludeOptional mods-enabled/*.load\nInclude ports.conf\n",
		"/etc/apache2/mods-enabled/ssl.load": "LoadModule ssl_module /usr/lib/apache2/modules/mod_ssl.so\n",
		"/etc/apache2/ports.conf":            ports,
	})
	// mod_ssl.c と ssl_module は同じモジュールの2通りの書き方
	if got := render(with.Directives); !strings.Contains(got, "listen [443] {} ports.conf:3") || strings.Contains(got, "8080") || strings.Contains(got, "8443") {
		t.Errorf("with ssl_module:\n%s", got)
	}
}

func TestProblemsAndEdgeCases(t *testing.T) {
	if r := Parse("/missing.conf", mapFS{}); len(r.Problems) != 1 || len(r.Directives) != 0 {
		t.Errorf("missing main: %+v", r)
	}
	r := Parse("/a.conf", mapFS{"/a.conf": "Include /a.conf\n<VirtualHost *:443>\nSSLEngine on\n"})
	if len(r.Problems) != 2 { // 循環する Include と、閉じられていないセクション
		t.Errorf("problems = %v", r.Problems)
	}
	// Include は必須。IncludeOptional と違い、取り込み先がなければ問題として報告する（Apache は起動に失敗する）
	if r := Parse("/a.conf", mapFS{"/a.conf": "Include /nope.conf\nIncludeOptional /nope2.conf\nIncludeOptional /d/*.conf\n"}); len(r.Problems) != 1 {
		t.Errorf("problems = %v", r.Problems)
	}
	// <IfDefine> は起動時の指定が分からないので中身を採らない（否定形は採る）
	r = Parse("/a.conf", mapFS{"/a.conf": "<IfDefine SSL>\nListen 443\n</IfDefine>\n<IfDefine !NOSSL>\nListen 8443\n</IfDefine>\n# comment\nlisten 80\n"})
	if got := render(r.Directives); got != "listen [8443] {} a.conf:5\nlisten [80] {} a.conf:8" {
		t.Errorf("IfDefine:\n%s", got)
	}
}

func FuzzParse(f *testing.F) {
	f.Add("ServerRoot /x\n<IfModule !a>\nInclude /b\n</IfModule>\n<VirtualHost *>\nX y \\\n z\n")
	f.Fuzz(func(t *testing.T, s string) { Parse("/a", mapFS{"/a": s, "/b": s}) })
}
