package jsse

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"kagiya/internal/ruleset"
)

func table(t *testing.T, pkg, version string) *ruleset.JDKTable {
	t.Helper()
	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	tb, _, exact, ok := rs.JDKTableFor("openjdk", pkg, version)
	if !ok || !exact {
		t.Fatalf("no JDK table for %s %s", pkg, version)
	}
	return tb
}

// 並びを含めた要約（正解データと同じ作り方）。
func digest(names []string) string {
	h := sha256.Sum256([]byte(strings.Join(names, ",")))
	return fmt.Sprintf("%d:%x", len(names), h[:8])
}

func sorted(names []string) string {
	if len(names) == 0 {
		return "-"
	}
	s := append([]string{}, names...)
	sort.Strings(s)
	return strings.Join(s, ",")
}

func joined(names []string) string {
	if len(names) == 0 {
		return "-"
	}
	return strings.Join(names, ",")
}

func dash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// 実物（各パッケージ版の JDK）の報告と、ハンドシェイクで確かめたグループに、すべて一致する。
// 正解データは検証ラボで採取したもの（testdata/corpus.tsv）。
func TestResolveMatchesRealJDK(t *testing.T) {
	data, err := os.ReadFile("testdata/corpus.tsv")
	if err != nil {
		t.Fatal(err)
	}
	n, withGroups := 0, 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 11 {
			t.Fatalf("bad line: %q", line)
		}
		n++
		name := f[0] + " " + f[1] + " " + f[2]
		in := Input{Disabled: dash(f[3]), NamedGroups: dash(f[5]), Properties: map[string]string{}}
		if f[4] != "-" {
			in.Properties["jdk.disabled.namedCurves"] = f[4]
		}
		r := Resolve(table(t, f[0], f[1]), in)
		if got := joined(r.Protocols); got != f[6] {
			t.Errorf("%s: protocols = %s, real JDK: %s", name, got, f[6])
		}
		if got := digest(r.Suites); got != f[7] {
			t.Errorf("%s: enabled suites = %s (%v), real JDK: %s", name, got, r.Suites, f[7])
		}
		if got := digest(r.Supported); got != f[8] {
			t.Errorf("%s: supported suites = %s, real JDK: %s", name, got, f[8])
		}
		if f[9] == "?" {
			continue // グループを測っていない場面
		}
		withGroups++
		if r.GroupsBlocker != "" {
			t.Errorf("%s: groups not resolved: %s", name, r.GroupsBlocker)
			continue
		}
		if got := sorted(r.Groups13); got != f[9] {
			t.Errorf("%s: TLS 1.3 groups = %s, real JDK: %s", name, got, f[9])
		}
		if got := sorted(r.Groups12); got != f[10] {
			t.Errorf("%s: TLS 1.2 groups = %s, real JDK: %s", name, got, f[10])
		}
	}
	if n < 250 || withGroups < 150 {
		t.Fatalf("too few vectors: %d (%d with groups)", n, withGroups)
	}
}

// 耐量子のハイブリッド（X25519MLKEM768）を既定で受け入れるのは JDK 25 から。
func TestHybridGroupByVersion(t *testing.T) {
	has := func(pkg, version string) bool {
		r := Resolve(table(t, pkg, version), Input{})
		for _, g := range r.Groups13 {
			if g == "X25519MLKEM768" {
				return true
			}
		}
		return false
	}
	if !has("openjdk-25-jre-headless", "25.0.5+8-1~deb13u1") {
		t.Error("JDK 25 accepts X25519MLKEM768 by default")
	}
	if has("openjdk-21-jre-headless", "21.0.13+9-1~deb13u2") {
		t.Error("JDK 21 does not accept X25519MLKEM768")
	}
}

// 実測で確かめていない書き方は、推測で当てはめず、グループを「求められない」とする（理由を返す）。
// スイートとプロトコルは、名前だけの項目で決まるので、そのまま求める。
func TestUnmeasuredFormsBlockGroups(t *testing.T) {
	tb := table(t, "openjdk-21-jre-headless", "21.0.13+9-1~deb13u2")
	base := Resolve(tb, Input{})
	if base.GroupsBlocker != "" || len(base.Groups13) == 0 || len(base.Suites) == 0 {
		t.Fatalf("unrestricted: %+v", base)
	}
	for name, in := range map[string]Input{
		"keySize with <=":               {Disabled: "EC keySize <= 384"},
		"keySize with ==":               {Disabled: "DH keySize == 2048"},
		"keySize with >":                {Disabled: "EC keySize > 384"},
		"named group not in table":      {NamedGroups: "secp256r1, brainpoolP256r1"},
		"include of a missing property": {Disabled: "include jdk.no.such.property"},
		"include nested too deep":       {Disabled: "include a", Properties: map[string]string{"a": "include a"}},
	} {
		r := Resolve(tb, in)
		if r.GroupsBlocker == "" {
			t.Errorf("%s: groups must not be resolved (got %v)", name, r.Groups13)
		}
		if len(r.Groups13) != 0 || len(r.Groups12) != 0 {
			t.Errorf("%s: no groups must be returned with a blocker", name)
		}
		if strings.Join(r.Suites, ",") != strings.Join(base.Suites, ",") || strings.Join(r.Protocols, ",") != strings.Join(base.Protocols, ",") {
			t.Errorf("%s: suites and protocols must be unaffected", name)
		}
	}
	// 条件つきの項目（用途の条件など）は、一覧に影響しない（既定の設定に含まれており、実測と一致している）
	r := Resolve(tb, Input{Disabled: "rsa_pkcs1_sha1 usage HandshakeSignature, SHA1 jdkCA & usage TLSServer, RSA keySize < 2048, X9.62 c2tnb191v1"})
	if r.GroupsBlocker != "" || sorted(r.Groups13) != sorted(base.Groups13) || digest(r.Suites) != digest(base.Suites) {
		t.Errorf("conditional items must not change the lists: %+v", r)
	}
}

// 無効にされたかどうかを、スイート 1 つずつ確かめられる（アプリの設定に書かれたスイートを絞り込むのに使う）。
func TestAllowed(t *testing.T) {
	tb := table(t, "openjdk-21-jre-headless", "21.0.13+9-1~deb13u2")
	c := Parse(tb, "SSLv3, TLSv1, TLSv1.1, 3DES_EDE_CBC, anon, NULL, TLS_RSA_*", nil)
	for suite, want := range map[string]bool{
		"TLS_AES_256_GCM_SHA384":                true,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": true,
		"TLS_RSA_WITH_AES_128_GCM_SHA256":       false, // 名前のパターン
		"SSL_RSA_WITH_3DES_EDE_CBC_SHA":         false, // 暗号
		"TLS_DH_anon_WITH_AES_128_GCM_SHA256":   false, // 鍵交換（大文字小文字を区別しない）
		"TLS_ECDHE_RSA_WITH_NULL_SHA":           false,
		"TLS_NO_SUCH_SUITE":                     false, // その版が知らないスイート
	} {
		if got := c.SuiteAllowed(suite); got != want {
			t.Errorf("SuiteAllowed(%s) = %v, want %v", suite, got, want)
		}
	}
	if c.ProtocolAllowed("TLSv1.1") || !c.ProtocolAllowed("TLSv1.2") {
		t.Error("ProtocolAllowed")
	}
	// ワイルドカードを解釈しない版では、その項目は何も無効にしない
	old := Parse(table(t, "openjdk-8-jre-headless", "8u452-ga~us1-0ubuntu1~20.04"), "TLS_RSA_*", nil)
	if !old.SuiteAllowed("TLS_RSA_WITH_AES_128_GCM_SHA256") {
		t.Error("a JDK without wildcard support must ignore TLS_RSA_*")
	}
}
