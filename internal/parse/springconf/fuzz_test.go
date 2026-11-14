package springconf

import "testing"

// 独立したレビュー（2026-11-14）の指摘 A-4: ファズテストのなかったパーサに追加する。どんな入力でも、止まらず、panic しないこと。

func FuzzLoad(f *testing.F) {
	f.Add("server.port=8443\nserver.ssl.key-store=/etc/k.p12\nspring.profiles.active=prod\n", "server:\n  ssl:\n    ciphers:\n      - A\n      - B\n---\nspring:\n  config:\n    activate:\n      on-profile: prod\n")
	f.Add("a\\\n b = c\n", "a: &x [1, 2]\nb: *x\n")
	f.Fuzz(func(t *testing.T, props, yaml string) {
		c := LoadWith(func(name string) ([]byte, bool) {
			switch name {
			case "application.properties", "application-prod.properties":
				return []byte(props), true
			case "application.yml":
				return []byte(yaml), true
			}
			return nil, false
		}, Options{})
		for _, k := range c.Keys() {
			c.Get(k)
			c.List(k)
		}
	})
}
