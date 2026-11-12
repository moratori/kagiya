package tlseffective

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"kagiya/internal/ruleset"
	"kagiya/internal/tlsciphers"
)

func table(t *testing.T, pkg, version string) *ruleset.CipherTable {
	t.Helper()
	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	tb, _, exact, ok := rs.CipherTableFor("openssl", pkg, version)
	if !ok || !exact {
		t.Fatalf("no cipher table for %s %s", pkg, version)
	}
	return tb
}

func setDigest(names []string) string {
	if len(names) == 0 {
		return "-"
	}
	s := append([]string{}, names...)
	sort.Strings(s)
	h := sha256.Sum256([]byte(strings.Join(s, ":")))
	return hex.EncodeToString(h[:])[:16]
}

func sorted(names []string) string {
	s := append([]string{}, names...)
	sort.Strings(s)
	return strings.Join(s, ",")
}

// 実際に起動した nginx と Apache httpd が受け入れたスイート（検証ラボでハンドシェイクにより数え上げたもの）と、すべて一致する。
func TestResolveMatchesRealServers(t *testing.T) {
	// servers.tsv は nginx と Apache httpd、servers-<アプリ>.tsv はそれ以外のアプリ
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	var data []byte
	files := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "servers") && strings.HasSuffix(e.Name(), ".tsv") {
			b, err := os.ReadFile("testdata/" + e.Name())
			if err != nil {
				t.Fatal(err)
			}
			data = append(append(data, b...), '\n')
			files++
		}
	}
	if files < 2 {
		t.Fatalf("only %d vector files were found", files)
	}
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 12 && len(f) != 13 {
			t.Fatalf("bad line: %q", line)
		}
		n++
		name := f[0] + " " + f[1] + " " + f[2] + " [" + f[3] + "]"
		in := Input{Table: table(t, f[0], f[1]), CipherString: f[3], SystemLevel: -1, CertsKnown: true, DHEKnown: true, DHE: f[8] == "yes"}
		if f[4] != "-" {
			p := f[4]
			in.Profile = &p
		}
		if in.SystemLevel, err = strconv.Atoi(f[5]); err != nil {
			t.Fatal(err)
		}
		if f[6] != "-" {
			in.SystemTLS13 = strings.Split(f[6], ":")
		}
		if len(f) == 13 && f[12] != "-" { // アプリの設定が指定した TLS 1.3 のスイート
			in.AppTLS13 = strings.Split(f[12], ":")
		}
		for _, c := range strings.Split(f[7], ",") {
			ks := strings.Split(c, "/")
			in.Certs = append(in.Certs, Cert{Key: ks[0], Signature: ks[1]})
		}
		out, err := Resolve(in)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if strconv.Itoa(len(out.Suites)) != f[9] || setDigest(out.Suites) != f[10] {
			t.Errorf("%s: got %d suites (%s), the real server accepted %s (%s)", name, len(out.Suites), setDigest(out.Suites), f[9], f[10])
		}
		if len(out.Unfiltered) != 0 {
			t.Errorf("%s: unfiltered = %v", name, out.Unfiltered)
		}
		if f[11] != "-" && sorted(out.TLS13) != f[11] {
			t.Errorf("%s: TLS 1.3 suites = %s, the real server accepted %s", name, sorted(out.TLS13), f[11])
		}
	}
	if n < 100 {
		t.Fatalf("only %d vectors were checked", n)
	}
}

// 人が読んで確かめられる例（RHEL 9 の OpenSSL 3.5）。
func TestResolveExamples(t *testing.T) {
	tb := table(t, "openssl-libs", "3.5.9-1.el9_9")
	rsa := []Cert{{Key: "RSA", Signature: "RSA"}}
	both := []Cert{{Key: "RSA", Signature: "RSA"}, {Key: "EC", Signature: "ECDSA"}}
	rule := "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-DSS-AES256-GCM-SHA384:AES256-GCM-SHA384:PSK-AES256-GCM-SHA384:AES128-SHA"

	// 証明書が RSA だけなら ECDSA と DSA の認証のスイートは使えない。DH パラメータがなければ DHE も使えない。PSK はアプリ側の設定がないと使えない。
	out, err := Resolve(Input{Table: tb, CipherString: rule, SystemLevel: -1, Certs: rsa, CertsKnown: true, DHEKnown: true})
	if err != nil || strings.Join(out.Suites, " ") != "ECDHE-RSA-AES256-GCM-SHA384 AES256-GCM-SHA384 AES128-SHA" {
		t.Errorf("RSA only, no DH: %+v %v", out, err)
	}
	if out.Level != 1 || out.LevelSource != "library-default" || len(out.Unfiltered) != 0 {
		t.Errorf("level = %d (%s), unfiltered = %v", out.Level, out.LevelSource, out.Unfiltered)
	}
	// 既定で有効な TLS 1.3 のスイート
	if strings.Join(out.TLS13, " ") != "TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_GCM_SHA256" {
		t.Errorf("TLS 1.3 = %v", out.TLS13)
	}
	// 証明書が両方あり、DH パラメータもある場合。優先順は暗号文字列の順のまま。
	out, err = Resolve(Input{Table: tb, CipherString: rule, SystemLevel: -1, Certs: both, CertsKnown: true, DHEKnown: true, DHE: true})
	if err != nil || strings.Join(out.Suites, " ") != "ECDHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-AES256-GCM-SHA384 DHE-RSA-AES256-GCM-SHA384 AES256-GCM-SHA384 AES128-SHA" {
		t.Errorf("both certificates, DH: %+v %v", out, err)
	}

	// セキュリティレベルの決まり方: 暗号文字列の指定 > システムの設定 > ライブラリの既定
	out, _ = Resolve(Input{Table: tb, CipherString: rule, SystemLevel: 4, Certs: both, CertsKnown: true, DHEKnown: true, DHE: true})
	if out.Level != 4 || out.LevelSource != "system" || strings.Join(out.Suites, " ") != "ECDHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-AES256-GCM-SHA384 DHE-RSA-AES256-GCM-SHA384" {
		t.Errorf("system level 4: %+v", out)
	}
	if strings.Join(out.TLS13, " ") != "TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256" {
		t.Errorf("TLS 1.3 at level 4 = %v", out.TLS13)
	}
	out, _ = Resolve(Input{Table: tb, CipherString: rule + ":@SECLEVEL=0", SystemLevel: 4, Certs: both, CertsKnown: true, DHEKnown: true, DHE: true})
	if out.Level != 0 || out.LevelSource != "cipher-string" || len(out.Suites) != 5 {
		t.Errorf("level from the cipher string: %+v", out)
	}

	// システムの設定が TLS 1.3 のスイートを決めている場合（RHEL の暗号ポリシー）。この版が知らない名前は無視して報告する。
	out, _ = Resolve(Input{Table: tb, CipherString: rule, SystemLevel: 2, SystemTLS13: []string{"TLS_AES_128_CCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_NO_SUCH_SUITE"}, Certs: both, CertsKnown: true, DHEKnown: true})
	if strings.Join(out.TLS13, " ") != "TLS_AES_128_CCM_SHA256 TLS_AES_256_GCM_SHA384" || strings.Join(out.Ignored, " ") != "TLS_NO_SUCH_SUITE" {
		t.Errorf("system TLS 1.3 suites: %v, ignored %v", out.TLS13, out.Ignored)
	}

	// アプリの設定が TLS 1.3 のスイートを指定していれば、システムの設定より優先される。
	out, _ = Resolve(Input{Table: tb, CipherString: rule, SystemLevel: 2, SystemTLS13: []string{"TLS_AES_128_CCM_SHA256", "TLS_AES_256_GCM_SHA384"},
		AppTLS13: []string{"TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256"}, Certs: both, CertsKnown: true, DHEKnown: true})
	if strings.Join(out.TLS13, " ") != "TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_GCM_SHA256" || out.TLS13Source != "app" {
		t.Errorf("application TLS 1.3 suites: %v (%s)", out.TLS13, out.TLS13Source)
	}
	if out, _ := Resolve(Input{Table: tb, CipherString: rule, SystemLevel: 2, SystemTLS13: []string{"TLS_AES_256_GCM_SHA384"}}); out.TLS13Source != "system" {
		t.Errorf("TLS 1.3 source = %s", out.TLS13Source)
	}
	if out, _ := Resolve(Input{Table: tb, CipherString: rule, SystemLevel: 2}); out.TLS13Source != "library-default" {
		t.Errorf("TLS 1.3 source = %s", out.TLS13Source)
	}

	// 証明書や DH パラメータの状況が分からないときは、その絞り込みをせず、していないことを報告する。
	out, err = Resolve(Input{Table: tb, CipherString: rule, SystemLevel: -1})
	if err != nil || len(out.Suites) != 6 || strings.Join(out.Unfiltered, " ") != "certificates dh-parameters" {
		t.Errorf("unknown certificates and DH: %+v %v", out, err)
	}

	// 展開できない暗号文字列は、そのままエラーにする。
	if _, err := Resolve(Input{Table: tb, CipherString: "PROFILE=SYSTEM", SystemLevel: -1}); !errors.Is(err, tlsciphers.ErrProfileNeeded) {
		t.Errorf("PROFILE=SYSTEM without the policy: %v", err)
	}
	if _, err := Resolve(Input{Table: tb, CipherString: "NOSUCHWORD", SystemLevel: -1}); !errors.Is(err, tlsciphers.ErrNoCipherMatch) {
		t.Errorf("no match: %v", err)
	}
	// 絞り込んだ結果が空になる場合（RSA の証明書しかないのに ECDSA のスイートだけを指定）は、エラーではなく空の結果になる。
	out, err = Resolve(Input{Table: tb, CipherString: "ECDHE-ECDSA-AES256-GCM-SHA384", SystemLevel: -1, Certs: rsa, CertsKnown: true, DHEKnown: true})
	if err != nil || len(out.Suites) != 0 {
		t.Errorf("nothing usable: %+v %v", out, err)
	}
}

// セキュリティレベルのない古い版（OpenSSL 1.0.2）。
func TestResolveWithoutSecurityLevels(t *testing.T) {
	tb := table(t, "libssl1.0.0", "1.0.2g-1ubuntu4.20")
	out, err := Resolve(Input{Table: tb, CipherString: "ECDHE-RSA-AES256-GCM-SHA384:PSK-AES256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:ECDH-RSA-AES256-GCM-SHA384:ECDH-ECDSA-AES256-GCM-SHA384:AES256-SHA",
		SystemLevel: -1, Certs: []Cert{{Key: "RSA", Signature: "RSA"}, {Key: "EC", Signature: "ECDSA"}}, CertsKnown: true, DHEKnown: true, DHE: true})
	// PSK と SRP はアプリ側の設定がないと使えない。固定の ECDH は、署名の種類が合う EC の証明書があるものだけ。
	if err != nil || strings.Join(out.Suites, " ") != "ECDHE-RSA-AES256-GCM-SHA384 ECDH-ECDSA-AES256-GCM-SHA384 AES256-SHA" {
		t.Errorf("1.0.2: %+v %v", out, err)
	}
	if out.Level != -1 || out.LevelSource != "" || len(out.TLS13) != 0 {
		t.Errorf("1.0.2 level: %+v", out)
	}
}
