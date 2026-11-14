package shellconf

import "testing"

// 独立したレビュー（2026-11-14）の指摘 A-4: ファズテストのなかったパーサに追加する。どんな入力でも、止まらず、panic しないこと。

func FuzzParse(f *testing.F) {
	f.Add("JAVA_HOME=/opt/jdk\nJAVA_OPTS=\"-Xmx1g $X\"\nexport RUN_ARGS='a b'\nA=$(b (c) d)\nB=`x`\n")
	f.Fuzz(func(t *testing.T, s string) {
		r := Parse([]byte(s), "JAVA_HOME", "JAVA_OPTS", "RUN_ARGS")
		for name := range r.Values {
			if name != "JAVA_HOME" && name != "JAVA_OPTS" && name != "RUN_ARGS" {
				t.Fatalf("a value is kept for %q, which was not requested", name)
			}
		}
	})
}
