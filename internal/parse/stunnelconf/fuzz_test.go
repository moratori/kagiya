package stunnelconf

import "testing"

// 独立したレビュー（2026-11-14）の指摘 A-4: ファズテストのなかったパーサに追加する。どんな入力でも、止まらず、panic しないこと。

func FuzzParse(f *testing.F) {
	f.Add("ciphers = HIGH\n[https]\naccept = 443\ncert = /etc/a.pem\n; c\n")
	f.Fuzz(func(t *testing.T, s string) { Parse("/etc/stunnel/stunnel.conf", []byte(s)) })
}
