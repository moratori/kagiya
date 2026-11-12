package stunnelconf

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	conf := `; stunnel の設定
pid = /run/stunnel.pid
Ciphers = HIGH:!aNULL:!MD5
# これもコメント

[imaps]
accept  = 993
connect = 127.0.0.1:143
cert = /etc/stunnel/mail.pem
ciphers = ECDHE+AESGCM
sslVersionMin = TLSv1.2

[ out going ]
client = yes
accept = 127.0.0.1:8025
connect = mail.example.jp:465
`
	ds, problems := Parse("/etc/stunnel/stunnel.conf", []byte(conf))
	if len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	get := func(service, key string) []Directive {
		var out []Directive
		for _, d := range ds {
			if d.Service == service && d.Key == key {
				out = append(out, d)
			}
		}
		return out
	}
	// 項目の名前は大文字小文字を区別しない（小文字にそろえる）。値はそのまま
	if g := get("", "ciphers"); len(g) != 1 || g[0].Value != "HIGH:!aNULL:!MD5" || g[0].Line != 3 || g[0].File != "/etc/stunnel/stunnel.conf" {
		t.Errorf("global ciphers = %+v", g)
	}
	if s := get("imaps", "ciphers"); len(s) != 1 || s[0].Value != "ECDHE+AESGCM" || s[0].Line != 10 {
		t.Errorf("service ciphers = %+v", s)
	}
	if s := get("imaps", "sslversionmin"); len(s) != 1 || s[0].Value != "TLSv1.2" {
		t.Errorf("sslVersionMin = %+v", s)
	}
	if s := get("imaps", "accept"); len(s) != 1 || s[0].Value != "993" {
		t.Errorf("accept = %+v", s)
	}
	// サービスの名前の前後の空白は落とす
	if s := get("out going", "client"); len(s) != 1 || s[0].Value != "yes" {
		t.Errorf("client service = %+v", ds)
	}
	for _, d := range ds {
		if strings.HasPrefix(d.Key, ";") || strings.HasPrefix(d.Key, "#") || strings.HasPrefix(d.Key, "[") {
			t.Errorf("a comment or a section line was returned: %+v", d)
		}
	}
}

func TestParseProblems(t *testing.T) {
	// 「名前 = 値」でも節の始まりでもない行は、捨てて問題として報告する（後の行は読む）
	ds, problems := Parse("/x.conf", []byte("garbage line\nciphers = HIGH\n[unterminated\ncert = /a\n"))
	if len(problems) != 2 || !strings.Contains(problems[0], "line 1") || !strings.Contains(problems[1], "line 3") {
		t.Errorf("problems = %v", problems)
	}
	if len(ds) != 2 || ds[0].Key != "ciphers" || ds[1].Key != "cert" {
		t.Errorf("directives = %+v", ds)
	}
	// 制御文字を含む行は捨てる。大きすぎる入力は読まない
	if ds, problems := Parse("/x.conf", []byte("ciphers = a\x00b\n")); len(ds) != 0 || len(problems) != 1 {
		t.Errorf("control characters: %+v %v", ds, problems)
	}
	if _, problems := Parse("/x.conf", []byte(strings.Repeat("a = b\n", 300_000))); len(problems) == 0 {
		t.Error("an oversized file must be reported")
	}
}
