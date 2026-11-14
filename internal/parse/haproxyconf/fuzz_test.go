package haproxyconf

import "testing"

// 独立したレビュー（2026-11-14）の指摘 A-4: ファズテストのなかったパーサに追加する。どんな入力でも、止まらず、panic しないこと。

func FuzzParse(f *testing.F) {
	f.Add("global\n  ssl-default-bind-ciphers A:B\nfrontend f\n  bind :443 ssl crt /etc/a.pem \"x y\" \\# z\n")
	f.Fuzz(func(t *testing.T, s string) { Parse("/etc/haproxy/haproxy.cfg", []byte(s)) })
}
