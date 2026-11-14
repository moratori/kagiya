package supervisorconf

import (
	"strings"
	"testing"
)

// 以下の読み方は、検証ラボで実物の supervisord（Ubuntu 24.04 の supervisor 4.2.5-1ubuntu0.1）にプログラムを起動させ、
// プロセスに渡った引数・環境変数・作業ディレクトリを見て確かめたもの。

const sample = `; comment
[supervisord]
logfile=/var/log/supervisor/supervisord.log ; (main log file)

[program:plain]
command=/opt/fake/bin/java -Xmx256m -jar /opt/app/app.jar --spring.profiles.active=prod
directory=/opt/app
environment=SPRING_PROFILES_ACTIVE="web",APP_HOME="/opt/app",JAVA_OPTS="-Da=1 -Db=2"

[program:quoted]
command=/opt/fake/bin/java "-Dname=a b" -jar '/opt/app/app.jar' --x="y z"
environment=SERVER_SSL_ENABLED_PROTOCOLS=TLSv1.3
autostart=false

[program:expand]
command=/opt/fake/bin/java -jar %(ENV_APP_JAR)s --here=%(here)s
environment=APP_X=%(ENV_APP_JAR)s,SPRING_PROFILES_ACTIVE=prod

[program:shellish]
command=/opt/fake/bin/java -jar /opt/app/app.jar $HOME ; echo not-a-comment && true

[group:web]
programs=plain
`

func TestPrograms(t *testing.T) {
	ps := Parse([]byte(sample))
	if len(ps) != 4 {
		t.Fatalf("programs = %d: %+v", len(ps), ps)
	}
	by := map[string]Program{}
	for _, p := range ps {
		by[p.Name] = p
	}
	p := by["plain"]
	if strings.Join(p.Argv, "|") != "/opt/fake/bin/java|-Xmx256m|-jar|/opt/app/app.jar|--spring.profiles.active=prod" || p.Directory != "/opt/app" || !p.Autostart || p.Unexpanded {
		t.Errorf("plain = %+v", p)
	}
	if p.Env["SPRING_PROFILES_ACTIVE"] != "web" || p.Env["APP_HOME"] != "/opt/app" || p.Env["JAVA_OPTS"] != "-Da=1 -Db=2" || p.Line != 5 {
		t.Errorf("plain env = %+v line=%d", p.Env, p.Line)
	}
	// 引用符は外れ、空白を含む語は 1 つのまま
	q := by["quoted"]
	if strings.Join(q.Argv, "|") != "/opt/fake/bin/java|-Dname=a b|-jar|/opt/app/app.jar|--x=y z" || q.Autostart || q.Env["SERVER_SSL_ENABLED_PROTOCOLS"] != "TLSv1.3" {
		t.Errorf("quoted = %+v", q)
	}
	// %(...)s の置き換えは解釈しない（置き換えがあったことだけ分かる）。置き換えを含む環境変数は、値を持たない
	e := by["expand"]
	if !e.Unexpanded || e.Env["SPRING_PROFILES_ACTIVE"] != "prod" || !e.EnvUnexpanded["APP_X"] {
		t.Errorf("expand = %+v", e)
	}
	if _, ok := e.Env["APP_X"]; ok {
		t.Error("a value with an expansion must not be kept")
	}
	// シェルは通らない: $HOME はそのままの文字列。「 ;」より後ろは注釈
	s := by["shellish"]
	if strings.Join(s.Argv, "|") != "/opt/fake/bin/java|-jar|/opt/app/app.jar|$HOME" {
		t.Errorf("shellish = %+v", s)
	}
}

// 壊れた内容や大きすぎる内容でも止まらない。
func TestRobust(t *testing.T) {
	for _, in := range []string{"", "[program:", "[program:x]\ncommand=\"unterminated\n", "command=/no/section\n", "[program:x]\nenvironment=A=\"1,B=2\n",
		strings.Repeat("[program:p]\ncommand=/bin/true\n", 5000)} {
		ps := Parse([]byte(in))
		if len(ps) > 256 {
			t.Errorf("too many programs kept: %d", len(ps))
		}
	}
	// 名前に使えない文字を含むプログラムは読まない
	if ps := Parse([]byte("[program:a b]\ncommand=/bin/true\n[program:ok-1]\ncommand=/bin/true\n")); len(ps) != 1 || ps[0].Name != "ok-1" {
		t.Errorf("programs = %+v", ps)
	}
}
