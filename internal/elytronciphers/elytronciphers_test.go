package elytronciphers

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"kagiya/internal/ruleset"
)

// 以下の期待値は、検証ラボで、WildFly の部品（Elytron）自身に式を解釈させた結果（lab/phase2/ElytronProbe.java、wildfly-elytron.sh）。
// WildFly 24.0.1 / 26.1.3 / 35.0.1 / 42.0.0 の Elytron で、3,221 通りの式の結果がすべて同じだった。
// 解釈の規則は、上流のソース（wildfly-elytron の CipherSuiteSelector.java。1.16.1.Final と 2.9.4.Final で同一）による。
// 「対応しているスイート」として渡したのは、表にある名前すべて（名前の順）。期待値は、選ばれた数と、名前を空白でつないだものの SHA-256 の先頭。

func table(t testing.TB) *ruleset.WildFlyTable {
	t.Helper()
	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	tb, _, ok := rs.WildFlyFor("42.0.0.Final")
	if !ok {
		t.Fatal("no WildFly table")
	}
	return tb
}

// allNames は、表にある名前すべて（TLS 1.2 以前のスイートの標準の名前と、別名）を、名前の順で返す。
func allNames(tb *ruleset.WildFlyTable) []string {
	var names []string
	for _, s := range tb.Suites {
		names = append(names, s.Name)
	}
	for _, a := range tb.Aliases {
		names = append(names, a.Name)
	}
	sort.Strings(names)
	return names
}

func digest(names []string) string {
	h := sha256.Sum256([]byte(strings.Join(names, " ")))
	return hex.EncodeToString(h[:8])
}

func TestEvaluate(t *testing.T) {
	tb := table(t)
	supported := allNames(tb)
	if len(supported) != 305 {
		t.Fatalf("names in the table = %d, want 305", len(supported))
	}
	for _, c := range []struct {
		expr string
		n    int
		hash string
	}{
		{"DEFAULT", 227, "95c7e24ee8fc219c"},
		{"ALL", 280, "96eaedcaafafefa4"},
		{"HIGH", 225, "80deef5bfecbebe1"},
		{"HIGH:!aNULL:!MD5", 202, "2df173ff1f05ec15"},
		{"ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL", 32, "1bcdeaff66df0358"},
		{"kRSA", 38, "afbe523edcddd040"},
		{"DEFAULT:!DHE", 189, "1088c0eb7c6eae0a"},
		{"ALL:!aNULL:!eNULL:@STRENGTH", 253, "de7060dd76ed565d"},
		{"COMPLEMENTOFDEFAULT", 20, "a5a2fe3cb1931b12"},
		{"COMPLEMENTOFALL", 23, "0d16fdcd377d7997"},
		{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_128_CBC_SHA", 2, "e45d8edd86c2db20"},
		{"ECDHE-RSA-AES256-GCM-SHA384,AES128-SHA", 2, "91cb6418ab2f70ec"},
		{"ECDHE-RSA-AES256-GCM-SHA384 AES128-SHA", 2, "91cb6418ab2f70ec"},
		{"SSL_RSA_WITH_3DES_EDE_CBC_SHA:TLS_RSA_WITH_AES_128_CBC_SHA", 2, "4dd2cbb691e51f54"},
		{"TLS_RSA_FIPS_WITH_3DES_EDE_CBC_SHA", 1, "9185bbb1d826c67b"},
		{"ALL:+ECDHE-RSA-AES128-GCM-SHA256:+AES", 280, "c00345126fea1fae"},
		{"HIGH:@STRENGTH:+AES128", 225, "3b5938e8bbc9eb79"},
		{"-ALL:+HIGH", 0, "e3b0c44298fc1c14"},
		{"!ALL:HIGH", 225, "80deef5bfecbebe1"},
		{"!DEFAULT:ALL", 280, "96eaedcaafafefa4"},
		{"!nosuch:ALL", 280, "96eaedcaafafefa4"},
		{"ECDHE+nosuch", 32, "cb02a2b3005950d8"},
		{"ECDHE++AES", 12, "5019e721d92e22f9"},
		{"AES+DEFAULT", 90, "50f5b7249ded4bf6"},
		{"HIGH : ! aNULL", 232, "c3ac03656a924739"},
		{"HIGH:!", 225, "80deef5bfecbebe1"},
		{"ALL:-ECDHE+AES:+kRSA+AES", 268, "be0deed39a8a61d3"},
		{"kEECDH+ECDSA+AESGCM:kEECDH+AESGCM:kEECDH+AES:kEDH+AESGCM:!aNULL:!eNULL:!MD5:!DSS", 14, "886aa9c417c385cf"},
		{"DEFAULT:-AES256:+SHA1", 190, "4134de052eb7b3e2"},
		{"ALL:!TLSv1.2", 125, "1126b7009f9bbd51"},
		{"EDH", 44, "87fec92ca35f28a1"},
		{"kEDH", 64, "4bbda438455cfe31"},
		{"PSK", 67, "1603420fa471f7f6"},
		{"RSA", 81, "834b27de9026f291"},
		{"DH", 91, "74cfa9ca0ad5519e"},
		{"ECDH", 67, "b1366e82d269784d"},
		{"", 0, "e3b0c44298fc1c14"},
	} {
		got, err := Evaluate(tb, c.expr, supported)
		if err != nil || len(got) != c.n || digest(got) != c.hash {
			t.Errorf("%q: %d suites (%s) err=%v, want %d (%s)", c.expr, len(got), digest(got), err, c.n, c.hash)
		}
	}
}

// Elytron が受け付けない式は、エラーにする（値を求めない）。小文字、知らない語、「+」でつなげない語、TLS 1.3 のスイートの名前など。
func TestEvaluateErrors(t *testing.T) {
	tb := table(t)
	supported := allNames(tb)
	for _, expr := range []string{"nosuch", "high", "DEFAULT+AES", "ALL+AES", "nosuch+ECDHE", "@SECLEVEL=2", "@STRENGTH=1", "HIGH:=x", "HIGH:@", "HIGH;!aNULL", "EECDH", "TLS_AES_128_GCM_SHA256", "CHACHA20", "TLSv1.3", "FIPS"} {
		if got, err := Evaluate(tb, expr, supported); err == nil {
			t.Errorf("%q: must be an error, got %d suites", expr, len(got))
		}
	}
	if _, err := Evaluate(tb, strings.Repeat("HIGH:", 2000), supported); err == nil {
		t.Error("an over-long expression must be rejected")
	}
}

// 結果は、JDK が対応しているスイートの並びから選ばれる（並びは JDK の順。対応していないものは入らない）。
func TestEvaluateFollowsSupportedOrder(t *testing.T) {
	tb := table(t)
	supported := []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_256_CBC_SHA", "SSL_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "UNKNOWN_SUITE"}
	got, err := Evaluate(tb, "DEFAULT", supported)
	if err != nil || strings.Join(got, ",") != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,SSL_RSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" {
		t.Errorf("DEFAULT = %v %v", got, err)
	}
	got, _ = Evaluate(tb, "AES256:kRSA", supported)
	if strings.Join(got, ",") != "TLS_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,SSL_RSA_WITH_3DES_EDE_CBC_SHA" {
		t.Errorf("AES256:kRSA = %v", got)
	}
}

// TLS 1.3 用の指定（cipher-suite-names）は、TLS 1.3 のスイートの名前を「:」で区切って並べる。知らない名前があればエラー。
func TestEvaluateNames(t *testing.T) {
	tb := table(t)
	supported := []string{"TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}
	got, err := EvaluateNames(tb, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384", supported)
	if err != nil || strings.Join(got, ",") != "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384" {
		t.Errorf("names = %v %v", got, err)
	}
	for _, bad := range []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "HIGH", "nosuch", "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384"} {
		if got, err := EvaluateNames(tb, bad, supported); err == nil {
			t.Errorf("%q: must be an error, got %v", bad, got)
		}
	}
}

// 検証ラボの結果（Elytron 自身の解釈。lab/out/tlsapp/wildfly-elytron/<版>/）があれば、全部の式を突き合わせる:
//
//	KAGIYA_ELYTRON_PROBE=$PWD/lab/out/tlsapp/wildfly-elytron/42.0.0.Final go test ./internal/elytronciphers -run TestAgainstElytron -v
func TestAgainstElytron(t *testing.T) {
	dir := os.Getenv("KAGIYA_ELYTRON_PROBE")
	if dir == "" {
		t.Skip("KAGIYA_ELYTRON_PROBE is not set")
	}
	tb := table(t)
	raw, err := os.ReadFile(filepath.Join(dir, "names.txt"))
	if err != nil {
		t.Fatal(err)
	}
	supported := strings.Fields(string(raw))
	f, err := os.Open(filepath.Join(dir, "probe-exprs.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	match, mismatch := 0, 0
	for sc.Scan() {
		fields := strings.Split(sc.Text(), "\t")
		if len(fields) < 2 || (fields[0] != "expr" && fields[0] != "error") {
			continue
		}
		got, err := Evaluate(tb, fields[1], supported)
		ok := false
		if fields[0] == "error" {
			ok = err != nil
		} else {
			want := ""
			if len(fields) > 3 {
				want = fields[3]
			}
			ok = err == nil && strings.Join(got, " ") == want
		}
		if ok {
			match++
		} else if mismatch++; mismatch <= 20 {
			t.Errorf("%q: kagiya %d suites err=%v, Elytron: %s", fields[1], len(got), err, fields[0])
		}
	}
	if match == 0 {
		t.Error("nothing was compared")
	}
	t.Logf("%d expressions match, %d differ", match, mismatch)
}
