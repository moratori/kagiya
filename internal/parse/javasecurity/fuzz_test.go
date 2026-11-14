package javasecurity

import (
	"errors"
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

func FuzzLoad(f *testing.F) {
	f.Add("jdk.tls.disabledAlgorithms=SSLv3, TLSv1, \\\n  RC4\ninclude /b\n", "security.provider.1=SUN\ninclude ${java.home}/c\n")
	f.Fuzz(func(t *testing.T, a, b string) {
		Load("/a", fuzzFS{"/a": a, "/b": b, "/jdk/c": a}, map[string]string{"java.home": "/jdk"})
	})
}
