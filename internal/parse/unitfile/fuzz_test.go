package unitfile

import "testing"

// 独立したレビュー（2026-11-14）の指摘 A-4: ファズテストのなかったパーサに追加する。どんな入力でも、止まらず、panic しないこと。

func FuzzParse(f *testing.F) {
	f.Add("[Service]\nExecStart=/usr/bin/java -jar \\\n  /opt/a.jar $OPTS ${X}\nEnvironment=\"A=b c\" D=e\n")
	f.Add("A='x y'\nexport B=\"z\"\n# c\n")
	f.Fuzz(func(t *testing.T, s string) {
		u := Parse([]byte(s))
		for _, v := range u.Values("Service", "ExecStart") {
			Words(v)
			SplitCommand(v, map[string]string{"OPTS": "-Xmx1g -Da=b", "X": s})
		}
		ParseEnv([]byte(s))
	})
}
