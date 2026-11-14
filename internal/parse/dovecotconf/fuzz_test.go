package dovecotconf

import (
	"errors"
	"path"
	"testing"
)

// 独立したレビュー（2026-11-14）の指摘 A-4: ファズテストのなかったパーサに追加する。どんな入力でも、止まらず、panic しないこと。

type fuzzFS map[string]string

func (m fuzzFS) ReadFile(p string) ([]byte, error) {
	if s, ok := m[p]; ok {
		return []byte(s), nil
	}
	return nil, errors.New("not found")
}

func (m fuzzFS) Glob(pattern string) ([]string, error) {
	var out []string
	for p := range m {
		if ok, _ := path.Match(pattern, p); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

func FuzzParse(f *testing.F) {
	f.Add("ssl = required\n!include /b\n!include_try /d/*.conf\nlocal_name x {\n  ssl_cert = </etc/a.pem\n}\n", "ssl_min_protocol = TLSv1.2\n")
	f.Fuzz(func(t *testing.T, a, b string) { Parse("/a", fuzzFS{"/a": a, "/b": b, "/d/x.conf": b}) })
}
