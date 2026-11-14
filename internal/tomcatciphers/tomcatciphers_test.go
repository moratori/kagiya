package tomcatciphers

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"kagiya/internal/ruleset"
)

func tableFor(t *testing.T, upstream string) *ruleset.TomcatTable {
	t.Helper()
	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	for _, tb := range rs.TomcatTables {
		if tb.Upstream == upstream {
			return tb
		}
	}
	t.Fatalf("no Tomcat table for %s", upstream)
	return nil
}

func sortedJoin(names []string) string {
	s := append([]string{}, names...)
	sort.Strings(s)
	return strings.Join(s, ",")
}

// Tomcat 自身の解釈結果（検証ラボで、版ごとに採取したもの）に、集合としてすべて一致する。
func TestExpandMatchesRealTomcat(t *testing.T) {
	data, err := os.ReadFile("testdata/corpus.tsv")
	if err != nil {
		t.Fatal(err)
	}
	tables := map[string]*ruleset.TomcatTable{}
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 4 {
			t.Fatalf("bad line: %q", line)
		}
		tb := tables[f[0]]
		if tb == nil {
			tb = tableFor(t, f[0])
			tables[f[0]] = tb
		}
		got := Expand(tb, f[1])
		seen := map[string]bool{}
		for _, g := range got {
			if seen[g] {
				t.Errorf("Tomcat %s %q: %s appears twice", f[0], f[1], g)
			}
			seen[g] = true
		}
		h := sha256.Sum256([]byte(sortedJoin(got)))
		if strconv.Itoa(len(got)) != f[2] || fmt.Sprintf("%x", h[:8]) != f[3] {
			t.Errorf("Tomcat %s %q: got %d names (%x), want %s (%s)", f[0], f[1], len(got), h[:8], f[2], f[3])
		}
		n++
	}
	if n < 1000 || len(tables) < 4 {
		t.Errorf("corpus too small: %d expressions, %d tables", n, len(tables))
	}
}

// 式の書き方ごとの意味（Tomcat 10.1.60 の表で）。
func TestExpandSyntax(t *testing.T) {
	tb := tableFor(t, "10.1.60")
	has := func(names []string, n string) bool {
		for _, x := range names {
			if x == n {
				return true
			}
		}
		return false
	}
	const rsaGCM, ecdheGCM, tls13 = "TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256"
	// 既定の暗号指定: RSA 鍵交換は入らず、ECDHE は入る。この表は TLS 1.3 のスイートも持つ
	def := Expand(tb, tb.DefaultCiphers)
	if has(def, rsaGCM) || !has(def, ecdheGCM) || !has(def, tls13) {
		t.Errorf("default: rsa=%v ecdhe=%v tls13=%v", has(def, rsaGCM), has(def, ecdheGCM), has(def, tls13))
	}
	for _, c := range []struct {
		expr string
		want string
	}{
		{"AES128-GCM-SHA256", rsaGCM},                                              // OpenSSL での名前
		{"TLS_RSA_WITH_AES_128_GCM_SHA256", rsaGCM},                                // 標準名
		{"AES128-GCM-SHA256,ECDHE-RSA-AES128-GCM-SHA256", ecdheGCM + "," + rsaGCM}, // 「,」でも区切れる
		{"AES128-GCM-SHA256 ECDHE-RSA-AES128-GCM-SHA256", ecdheGCM + "," + rsaGCM}, // 空白でも区切れる
		{"AES128-GCM-SHA256:!kRSA", ""},                                            // ! は、後から足しても戻らない
		{"!kRSA:AES128-GCM-SHA256", ""},
		{"AES128-GCM-SHA256:-kRSA:AES128-GCM-SHA256", rsaGCM}, // - は、後から足せば戻る
		{"AES128-GCM-SHA256:NOSUCHWORD", rsaGCM},              // 知らない語は読み飛ばす
		{"aes128-gcm-sha256", ""},                             // 大文字小文字を区別する
		{"AES128-GCM-SHA256;ECDHE-RSA-AES128-GCM-SHA256", ""}, // 「;」は区切りではない
		{"kRSA+AESGCM+AES128", rsaGCM},                        // + は、どちらにも当てはまるもの
		{"", ""},
	} {
		if got := sortedJoin(Expand(tb, c.expr)); got != c.want {
			t.Errorf("%q: got %q, want %q", c.expr, got, c.want)
		}
	}
	// Java での名前が 2 つあるスイート（SSL_ と TLS_）は、両方を返す
	if got := sortedJoin(Expand(tb, "DES-CBC3-SHA")); got != "SSL_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA" {
		t.Errorf("DES-CBC3-SHA: %q", got)
	}
}

// @STRENGTH の後ろの要素を読むかどうかは、版によって違う（表の strength_ends）。
func TestExpandAfterStrength(t *testing.T) {
	const expr = "AES128-GCM-SHA256:@STRENGTH:AES256-GCM-SHA384"
	if got := Expand(tableFor(t, "10.1.60"), expr); len(got) != 2 {
		t.Errorf("10.1.60 reads the elements after @STRENGTH: %v", got)
	}
	if got := Expand(tableFor(t, "11.0.22"), expr); len(got) != 1 {
		t.Errorf("11.0.22 stops at @STRENGTH: %v", got)
	}
}

// 長すぎる式や、要素の多すぎる式でも止まらない（結果は空でよい）。
func TestExpandLimits(t *testing.T) {
	tb := tableFor(t, "10.1.60")
	long := strings.Repeat("HIGH:", 100000)
	if got := Expand(tb, long); len(got) != 0 {
		t.Errorf("an oversized expression must not be interpreted: %d names", len(got))
	}
}
