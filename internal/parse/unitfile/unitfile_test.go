package unitfile

import (
	"strings"
	"testing"
)

func TestParseUnit(t *testing.T) {
	// RHEL 8.10 の sshd.service（実物）
	u := Parse([]byte("[Unit]\nDescription=OpenSSH server daemon\n\n[Service]\nType=notify\nEnvironmentFile=-/etc/crypto-policies/back-ends/opensshserver.config\nEnvironmentFile=-/etc/sysconfig/sshd\nExecStart=/usr/sbin/sshd -D $OPTIONS $CRYPTO_POLICY\nExecReload=/bin/kill -HUP $MAINPID\n# comment\n; comment\n\n[Install]\nWantedBy=multi-user.target\n"))
	if got := strings.Join(u.Values("Service", "EnvironmentFile"), "|"); got != "-/etc/crypto-policies/back-ends/opensshserver.config|-/etc/sysconfig/sshd" {
		t.Errorf("EnvironmentFile = %q", got)
	}
	if got := u.Values("Service", "ExecStart"); len(got) != 1 || got[0] != "/usr/sbin/sshd -D $OPTIONS $CRYPTO_POLICY" {
		t.Errorf("ExecStart = %q", got)
	}
	if got := u.Values("Install", "WantedBy"); len(got) != 1 || got[0] != "multi-user.target" {
		t.Errorf("WantedBy = %q", got)
	}
	if u.Values("Service", "Nope") != nil {
		t.Error("missing key must return nil")
	}
	// 行末の \ は次の行へ続く。空の代入はそれまでの値を消す。
	u = Parse([]byte("[Service]\nExecStart=/bin/a \\\n  -x\nEnvironment=A=1\nEnvironment=\nEnvironment=B=2\n"))
	if got := u.Values("Service", "ExecStart"); len(got) != 1 || got[0] != "/bin/a   -x" && got[0] != "/bin/a -x" {
		t.Errorf("continuation = %q", got)
	}
	if got := u.Values("Service", "Environment"); len(got) != 1 || got[0] != "B=2" {
		t.Errorf("reset = %q", got)
	}
}

func TestParseEnvFile(t *testing.T) {
	// RHEL 8.10 の /etc/sysconfig/sshd と opensshserver.config の形（実物）
	env := ParseEnv([]byte("# comment\nSSH_USE_STRONG_RNG=0\n# CRYPTO_POLICY=\n\nCRYPTO_POLICY='-oCiphers=aes256-ctr,aes128-ctr -oMACs=hmac-sha2-256'\nQUOTED=\"a b\"\nexport X=1\nnot a line\n"))
	got := map[string]string{}
	line := map[string]int{}
	for _, e := range env {
		got[e.Key], line[e.Key] = e.Value, e.Line
	}
	if got["SSH_USE_STRONG_RNG"] != "0" || got["CRYPTO_POLICY"] != "-oCiphers=aes256-ctr,aes128-ctr -oMACs=hmac-sha2-256" || got["QUOTED"] != "a b" || line["CRYPTO_POLICY"] != 5 {
		t.Errorf("env = %v lines = %v", got, line)
	}
	if _, ok := got["not a line"]; ok || len(got) != 3 {
		t.Errorf("unexpected entries: %v", got)
	}
}

func TestSplitCommand(t *testing.T) {
	env := map[string]string{"OPTIONS": "", "CRYPTO_POLICY": "-oCiphers=a,b -oMACs=c", "ONE": "x y"}
	// 引用符のない $VAR は空白で分かれ、${VAR} は1語のまま（systemd の規則）
	got := SplitCommand("/usr/sbin/sshd -D $OPTIONS $CRYPTO_POLICY ${ONE} -o 'Kex Algorithms=z' $UNSET", env)
	want := []string{"/usr/sbin/sshd", "-D", "-oCiphers=a,b", "-oMACs=c", "x y", "-o", "Kex Algorithms=z"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("got %q, want %q", got, want)
	}
}
