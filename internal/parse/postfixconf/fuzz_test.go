package postfixconf

import "testing"

// 独立したレビュー（2026-11-14）の指摘 A-4: ファズテストのなかったパーサに追加する。どんな入力でも、止まらず、panic しないこと。

func FuzzParse(f *testing.F) {
	f.Add("smtpd_tls_protocols = >=TLSv1.2\n  , !SSLv3\nx = ${y:${z}} $(a) ${b?c:d}\n", "smtp inet n - y - - smtpd\n  -o smtpd_tls_security_level=encrypt\n")
	f.Fuzz(func(t *testing.T, main, master string) {
		params, _ := ParseMain("/etc/postfix/main.cf", []byte(main))
		values := map[string]string{}
		for _, p := range params {
			values[p.Name] = p.Value
		}
		for _, p := range params {
			Expand(p.Value, func(name string) (string, bool) { v, ok := values[name]; return v, ok })
		}
		ParseMaster("/etc/postfix/master.cf", []byte(master))
	})
}
