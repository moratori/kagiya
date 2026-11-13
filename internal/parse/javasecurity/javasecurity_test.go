package javasecurity

import (
	"errors"
	"strings"
	"testing"
)

type mapFS map[string]string

func (m mapFS) ReadFile(p string) ([]byte, error) {
	if v, ok := m[p]; ok {
		return []byte(v), nil
	}
	return nil, errors.New("not found")
}

const home = "/usr/lib/jvm/java-25-openjdk"

// プロパティファイルの書き方: コメント、行の継続、区切り（= : 空白）、同じ名前は後に書かれたものが効く。
func TestLoadSyntax(t *testing.T) {
	sec := home + "/conf/security/java.security"
	f := Load(sec, mapFS{sec: "# comment\n! comment\n\n" +
		"security.provider.1=SUN\n" +
		"jdk.tls.disabledAlgorithms=SSLv3, TLSv1, \\\n    RC4, DH keySize < 1024, \\\n    TLS_RSA_*\n" +
		"jdk.disabled.namedCurves = secp112r1, \\\n\tsecp256k1\n" +
		"keystore.type : pkcs12\n" +
		"spaced value\n" +
		"empty=\n" +
		"twice=first\n" +
		"twice=second\n"}, nil)
	if len(f.Problems) != 0 {
		t.Fatalf("problems: %v", f.Problems)
	}
	for name, want := range map[string]string{
		"security.provider.1":        "SUN",
		"jdk.tls.disabledAlgorithms": "SSLv3, TLSv1, RC4, DH keySize < 1024, TLS_RSA_*",
		"jdk.disabled.namedCurves":   "secp112r1, secp256k1",
		"keystore.type":              "pkcs12",
		"spaced":                     "value",
		"empty":                      "",
		"twice":                      "second",
	} {
		e, ok := f.Get(name)
		if !ok || e.Value != want {
			t.Errorf("%s = %q (found %v), want %q", name, e.Value, ok, want)
		}
	}
	if e, _ := f.Get("jdk.tls.disabledAlgorithms"); e.File != sec || e.Line != 5 {
		t.Errorf("location = %s:%d", e.File, e.Line)
	}
	if e, _ := f.Get("twice"); e.Line != 13 {
		t.Errorf("the later line must win: line %d", e.Line)
	}
	if _, ok := f.Get("no.such"); ok {
		t.Error("unknown name must not be found")
	}
	if f.Included {
		t.Error("no include in this file")
	}
}

// include（RHEL 系の JDK 25 で、暗号ポリシーにつなぐのに使われている）: パスの ${名前} は渡された値で置き換え、
// 値のないものは空になる。相対パスは、取り込む側のファイルのあるディレクトリから。後に読まれた値が効く。
// 検証ラボで、この読み方で組み立てた値が JDK 自身の報告と一致することを確かめている。
func TestLoadInclude(t *testing.T) {
	dir := home + "/conf/security"
	fs := mapFS{
		dir + "/java.security": "jdk.tls.disabledAlgorithms=SSLv3, TLSv1\njdk.tls.legacyAlgorithms=NULL\n" +
			"include redhat/${redhat.crypto-policies}/crypto-policies.properties\n",
		dir + "/redhat/crypto-policies.properties":      "include true/crypto-policies.properties\n",
		dir + "/redhat/true/crypto-policies.properties": "include /etc/crypto-policies/back-ends/java.config\ninclude ../${__redhat_fips__}/fips.properties\n",
		dir + "/redhat/false/fips.properties":           "",
		"/etc/crypto-policies/back-ends/java.config":    "jdk.tls.disabledAlgorithms=TLSv1.1, TLSv1, SSLv3, include jdk.disabled.namedCurves\njdk.disabled.namedCurves=secp256k1\n",
	}
	f := Load(dir+"/java.security", fs, map[string]string{"__redhat_fips__": "false", "java.home": home})
	if len(f.Problems) != 0 {
		t.Fatalf("problems: %v", f.Problems)
	}
	if !f.Included {
		t.Error("Included must be set")
	}
	e, _ := f.Get("jdk.tls.disabledAlgorithms")
	if e.Value != "TLSv1.1, TLSv1, SSLv3, include jdk.disabled.namedCurves" || e.File != "/etc/crypto-policies/back-ends/java.config" || e.Line != 1 {
		t.Errorf("disabledAlgorithms = %+v", e)
	}
	if e, _ := f.Get("jdk.tls.legacyAlgorithms"); e.Value != "NULL" {
		t.Errorf("a value not overridden must stay: %+v", e)
	}
	if _, ok := f.Get("include"); ok {
		t.Error("include must not be recorded as a property")
	}
	want := []string{dir + "/java.security", dir + "/redhat/crypto-policies.properties", dir + "/redhat/true/crypto-policies.properties",
		"/etc/crypto-policies/back-ends/java.config", dir + "/redhat/false/fips.properties"}
	if strings.Join(f.Files, "|") != strings.Join(want, "|") {
		t.Errorf("files = %v", f.Files)
	}
	// 取り込みの後に書かれた値は、取り込まれた値より優先される
	fs[dir+"/java.security"] += "jdk.tls.disabledAlgorithms=after\n"
	if e, _ := Load(dir+"/java.security", fs, map[string]string{"__redhat_fips__": "false"}).Get("jdk.tls.disabledAlgorithms"); e.Value != "after" {
		t.Errorf("a later definition must override the included one: %+v", e)
	}
	// ${java.home} の置き換え
	fs2 := mapFS{dir + "/java.security": "include ${java.home}/conf/security/extra.security\n", dir + "/extra.security": "a=b\n"}
	if e, ok := Load(dir+"/java.security", fs2, map[string]string{"java.home": home}).Get("a"); !ok || e.Value != "b" {
		t.Errorf("include with ${java.home}: %+v", e)
	}
}

// 読めない取り込み先、深すぎる入れ子、多すぎるファイルは、止まらずに問題として返す（値は、読めた範囲のもの）。
func TestLoadProblems(t *testing.T) {
	sec := "/j/conf/security/java.security"
	for name, fs := range map[string]mapFS{
		"missing include":        {sec: "a=1\ninclude nowhere.properties\n"},
		"include loop":           {sec: "a=1\ninclude java.security\n"},
		"mutual loop":            {sec: "a=1\ninclude x.properties\n", "/j/conf/security/x.properties": "include java.security\n"},
		"include without a path": {sec: "a=1\ninclude\n"},
	} {
		f := Load(sec, fs, nil)
		if len(f.Problems) == 0 {
			t.Errorf("%s: expected a problem", name)
		}
		if e, ok := f.Get("a"); !ok || e.Value != "1" {
			t.Errorf("%s: values read before the problem must be kept", name)
		}
		if len(f.Files) > 20 {
			t.Errorf("%s: too many files read: %d", name, len(f.Files))
		}
	}
	if f := Load("/nowhere/java.security", mapFS{}, nil); len(f.Problems) == 0 {
		t.Error("an unreadable file must be reported")
	}
	// 多すぎる取り込み
	many := mapFS{sec: ""}
	for i := 0; i < 100; i++ {
		n := "/j/conf/security/f" + strings.Repeat("x", i) + ".properties"
		many[sec] += "include " + n + "\n"
		many[n] = "k=v\n"
	}
	if f := Load(sec, many, nil); len(f.Problems) == 0 || len(f.Files) > 40 {
		t.Errorf("too many includes: problems=%v files=%d", f.Problems, len(f.Files))
	}
	// 長すぎる行、制御文字を含む値は、その記載を捨てて問題にする（ほかの記載は読む）
	f := Load(sec, mapFS{sec: "big=" + strings.Repeat("x", 70000) + "\nbad=a\x00b\nok=1\n"}, nil)
	if _, ok := f.Get("big"); ok {
		t.Error("an oversized value must be dropped")
	}
	if _, ok := f.Get("bad"); ok {
		t.Error("a value with a control character must be dropped")
	}
	if e, ok := f.Get("ok"); !ok || e.Value != "1" || len(f.Problems) != 2 {
		t.Errorf("ok=%+v problems=%v", e, f.Problems)
	}
}
