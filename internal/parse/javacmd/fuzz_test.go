package javacmd

import (
	"strings"
	"testing"
)

// 独立したレビュー（2026-11-14）の指摘 A-4: ファズテストのなかったパーサに追加する。どんな入力でも、止まらず、panic しないこと。

func FuzzParse(f *testing.F) {
	f.Add("/usr/bin/java -Xmx1g -Dspring.profiles.active=a,b -jar /opt/a.jar --server.ssl.key-store-password=s3cret")
	f.Fuzz(func(t *testing.T, s string) {
		c, ok := Parse(strings.Fields(s))
		// 引数の値は持たない（決まった名前の先頭部分だけ）
		if ok && strings.Contains(c.Risky, "=") {
			t.Fatalf("Risky keeps a value: %q", c.Risky)
		}
	})
}
