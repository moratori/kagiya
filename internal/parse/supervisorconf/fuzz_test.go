package supervisorconf

import "testing"

// 独立したレビュー（2026-11-14）の指摘 A-4: ファズテストのなかったパーサに追加する。どんな入力でも、止まらず、panic しないこと。

func FuzzParse(f *testing.F) {
	f.Add("[program:a]\ncommand=/usr/bin/java \"-Da=b c\" -jar '/opt/a.jar' ; x\nenvironment=A=\"1\",B=%(ENV_X)s\ndirectory=/opt\n")
	f.Fuzz(func(t *testing.T, s string) { Parse([]byte(s)) })
}
