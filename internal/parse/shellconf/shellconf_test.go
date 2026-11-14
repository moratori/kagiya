package shellconf

import (
	"fmt"
	"strings"
	"testing"
)

// シェルが取り込む（source する）設定ファイルのうち、「名前=値」だけが並ぶ単純なものを読む。
// Spring Boot の実行できる JAR の起動スクリプトが取り込む <JAR の名前>.conf が対象（検証ラボで、Spring Boot 2.7.18 と 3.5.16 の
// 実物の起動スクリプトを取り出して、取り込み方を確かめた）。シェルとしては実行しない。

var names = []string{"JAVA_HOME", "JAVA_OPTS", "RUN_ARGS"}

func TestSimpleAssignments(t *testing.T) {
	r := Parse([]byte(`# settings of the portal
JAVA_HOME=/usr/lib/jvm/java-21
JAVA_OPTS="-Xmx1g -Dfile.encoding=UTF-8"   # heap
export RUN_ARGS='--server.port=9443 --logging.file.name=/var/log/portal.log'

LOG_FOLDER=/var/log/portal
DB_PASSWORD=s3cret-shell
EMPTY=
`), names...)
	if r.Opaque != 0 {
		t.Fatalf("opaque at line %d", r.Opaque)
	}
	if r.Values["JAVA_HOME"] != "/usr/lib/jvm/java-21" || r.Values["JAVA_OPTS"] != "-Xmx1g -Dfile.encoding=UTF-8" ||
		r.Values["RUN_ARGS"] != "--server.port=9443 --logging.file.name=/var/log/portal.log" {
		t.Errorf("values = %+v", r.Values)
	}
	// 指定した名前以外は、値を持たない（代入があったことだけ分かる）。パスワードが書かれていても、取り込まない
	if len(r.Values) != 3 {
		t.Errorf("only the requested names may have values: %+v", r.Values)
	}
	for _, n := range []string{"JAVA_HOME", "JAVA_OPTS", "RUN_ARGS", "LOG_FOLDER", "DB_PASSWORD", "EMPTY"} {
		if !r.Assigned[n] {
			t.Errorf("%s must be recorded as assigned", n)
		}
	}
	if strings.Contains(fmt.Sprintf("%+v", r), "s3cret") {
		t.Error("the value of a name that was not requested is kept")
	}
}

func TestLaterAssignmentWinsAndEmptyValue(t *testing.T) {
	r := Parse([]byte("JAVA_HOME=/opt/jdk-17\nJAVA_HOME=/opt/jdk-21\r\nJAVA_OPTS=\nRUN_ARGS=\"\"\n"), names...)
	if r.Values["JAVA_HOME"] != "/opt/jdk-21" {
		t.Errorf("JAVA_HOME = %q", r.Values["JAVA_HOME"])
	}
	for _, n := range []string{"JAVA_OPTS", "RUN_ARGS"} {
		if v, ok := r.Values[n]; !ok || v != "" {
			t.Errorf("%s: an empty value must be kept as empty: %q %v", n, v, ok)
		}
	}
}

// シェルの展開（変数、コマンドの置き換え、エスケープ）を含む値は、求めない。「値が決まらない」ことだけ分かる。
func TestUnknownValues(t *testing.T) {
	for _, line := range []string{
		`JAVA_OPTS="$JAVA_OPTS -Xmx1g"`,
		"JAVA_OPTS=${EXTRA_OPTS}",
		"JAVA_OPTS=`cat /etc/portal/opts`",
		"JAVA_OPTS=$(cat /etc/portal/opts)",
		`JAVA_OPTS="-Dname=a\"b"`,
		`JAVA_OPTS=-Dname=a\ b`,
		`JAVA_OPTS="-Xmx1g"'-Xms1g'`,
		"JAVA_OPTS=~/opts",
		"JAVA_OPTS=/opt/*/lib",
	} {
		r := Parse([]byte("JAVA_OPTS=-Xmx512m\n"+line+"\n"), names...)
		if r.Opaque != 0 {
			t.Errorf("%s: must be an assignment with an unknown value, not opaque", line)
		}
		if _, has := r.Values["JAVA_OPTS"]; has || !r.Unknown["JAVA_OPTS"] || !r.Assigned["JAVA_OPTS"] {
			t.Errorf("%s: values=%+v unknown=%+v", line, r.Values, r.Unknown)
		}
	}
	// 後から単純な値で代入し直せば、その値に決まる
	r := Parse([]byte("JAVA_OPTS=$X\nJAVA_OPTS=-Xmx1g\n"), names...)
	if r.Values["JAVA_OPTS"] != "-Xmx1g" || r.Unknown["JAVA_OPTS"] {
		t.Errorf("reassigned: %+v %+v", r.Values, r.Unknown)
	}
}

// 代入でない行（コマンド、制御構文、ほかのファイルの取り込みなど）があれば、全体として読めないものとして扱う。その行の番号を返す。
func TestOpaque(t *testing.T) {
	for _, line := range []string{
		"source /etc/default/portal",
		". /etc/default/portal",
		"if [ -d /opt/jdk-21 ]; then",
		"unset JAVA_HOME",
		"JAVA_HOME=/opt/jdk-21 /usr/local/bin/prepare",
		"JAVA_HOME=/opt/jdk-17; JAVA_HOME=/opt/jdk-21",
		"JAVA_HOME=/opt/jdk-17 && true",
		"JAVA_HOME=$(ls /opt | head -1)",
		"JAVA_OPTS+=-Xmx1g",
		"export JAVA_HOME",
		"declare -x JAVA_HOME=/opt/jdk-21",
		`JAVA_OPTS="-Xmx1g`,
		"JAVA_OPTS='-Xmx1g",
		"ulimit -n 65536",
	} {
		r := Parse([]byte("# c\nJAVA_HOME=/opt/jdk-17\n"+line+"\n"), names...)
		if r.Opaque != 3 {
			t.Errorf("%s: opaque = %d, want line 3", line, r.Opaque)
		}
	}
}

// 大きすぎるファイル、長すぎる行、テキストでないものは、読まない。
func TestLimits(t *testing.T) {
	if r := Parse([]byte(strings.Repeat("A=1\n", MaxSize/4+1)), names...); r.Opaque == 0 {
		t.Error("a file over the size limit must be opaque")
	}
	if r := Parse([]byte("JAVA_OPTS="+strings.Repeat("x", MaxLine+1)+"\n"), names...); r.Opaque != 1 {
		t.Errorf("a line over the limit: opaque = %d", r.Opaque)
	}
	if r := Parse([]byte("JAVA_HOME=/opt/jdk\x00-21\n"), names...); r.Opaque != 1 {
		t.Errorf("a NUL byte: opaque = %d", r.Opaque)
	}
	if r := Parse(nil, names...); r.Opaque != 0 || len(r.Assigned) != 0 {
		t.Errorf("empty input: %+v", r)
	}
}
