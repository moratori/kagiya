package ruleset

import (
	"strings"
	"testing"
)

// ライブラリの版から、耐量子のアルゴリズムに対応しているかを引く。「どの版から対応したか」は、検証ラボで各版の実物に尋ねた結果と、
// 開発元の資料（リリースノート）から（出典はルールに書く）。

func TestCompareVersions(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.79", "1.79", 0}, {"1.80", "1.79", 1}, {"1.78.1", "1.79", -1}, {"1.78.1", "1.78", 1}, {"1.9", "1.10", -1},
		{"2.0.70.Final", "2.0.68.Final", 1}, {"2.0.68.Final", "2.0.68", 0}, {"2.0.67.Final-linux-x86_64", "2.0.68.Final", -1},
		{"2.0.70.Final-linux-aarch_64", "2.0.68.Final", 1}, {"6.2.1.RELEASE", "6.2", 1},
		{"3.5.9", "3.5.0", 1}, {"1.1.1k", "3.5.0", -1}, {"3.0.13", "3.5.0", -1}, {"1.0.2.4", "1.0.2", 1},
	} {
		got, ok := CompareVersions(tc.a, tc.b)
		if !ok || got != tc.want {
			t.Errorf("CompareVersions(%q, %q) = %d %v, want %d", tc.a, tc.b, got, ok, tc.want)
		}
	}
	// 正式版でないもの、数字で始まらないものは、比べない（推測で前後を決めない）
	for _, v := range []string{"2.6-alpha3", "1.0.0.RC10", "1.80-SNAPSHOT", "2.7.0-beta1", "", "latest", "1..2", "3.5.0-dev"} {
		if _, ok := CompareVersions(v, "1.0"); ok {
			t.Errorf("%q must not be comparable", v)
		}
	}
}

func TestPQCFor(t *testing.T) {
	rule := &PQCRule{Features: []PQCFeature{
		{Name: "ML-KEM", Artifacts: []string{"bcprov-*"}, Since: "1.79", Checked: VersionRange{From: "1.71", To: "1.87"}},
		{Name: "ML-DSA", Artifacts: []string{"bcprov-*"}, Since: "1.79", Checked: VersionRange{From: "1.71", To: "1.87"}},
		{Name: "TLS-MLKEM-hybrid", Artifacts: []string{"bctls-*"}, Since: "1.81", Checked: VersionRange{From: "1.71", To: "1.87"}, Unmeasured: []string{"1.85.2"}},
		{Name: "ML-KEM", Artifacts: []string{"bc-fips"}, Checked: VersionRange{From: "1.0.0", To: "2.1.3"}},
		{Name: "SLH-DSA", Artifacts: []string{"documented-only"}, Since: "2.0", Evidence: "documented", Checked: VersionRange{From: "2.0", To: "3.0"}},
	}}
	for _, tc := range []struct {
		artifact, version                       string
		supported, notSupported, unknown, basis string
	}{
		{"bcprov-jdk18on", "1.79", "ML-KEM,ML-DSA", "", "", "measured"},
		{"bcprov-jdk18on", "1.87", "ML-KEM,ML-DSA", "", "", "measured"},
		{"bcprov-jdk18on", "1.78.1", "", "ML-KEM,ML-DSA", "", "measured"},
		// 確かめた範囲の外: 新しい版は「対応が続いている」、古い版は「対応していない」と見なす（推定）
		{"bcprov-jdk18on", "1.90", "ML-KEM,ML-DSA", "", "", "extrapolated"},
		{"bcprov-jdk15on", "1.70", "", "ML-KEM,ML-DSA", "", "extrapolated"},
		{"bctls-jdk18on", "1.80", "", "TLS-MLKEM-hybrid", "", "measured"},
		{"bctls-jdk18on", "1.81", "TLS-MLKEM-hybrid", "", "", "measured"},
		// 測れなかった版、比べられない版は「不明」
		{"bctls-jdk18on", "1.85.2", "", "", "TLS-MLKEM-hybrid", "measured"},
		{"bcprov-jdk18on", "1.80-SNAPSHOT", "", "", "ML-KEM,ML-DSA", "measured"},
		{"bcprov-jdk18on", "", "", "", "ML-KEM,ML-DSA", "measured"},
		// 「確かめた範囲では対応していない」ライブラリ: 範囲より新しい版は、分からない
		{"bc-fips", "2.1.3", "", "ML-KEM", "", "measured"},
		{"bc-fips", "1.0.2.4", "", "ML-KEM", "", "measured"},
		{"bc-fips", "2.2.0", "", "", "ML-KEM", "measured"},
		// 開発元の資料だけが根拠のもの
		{"documented-only", "2.5", "SLH-DSA", "", "", "documented"},
	} {
		r, ok := rule.For(tc.artifact, tc.version)
		if !ok || strings.Join(r.Supported, ",") != tc.supported || strings.Join(r.NotSupported, ",") != tc.notSupported ||
			strings.Join(r.Unknown, ",") != tc.unknown || r.Basis != tc.basis {
			t.Errorf("%s %s: %+v ok=%v, want supported=%q not=%q unknown=%q basis=%q", tc.artifact, tc.version, r, ok, tc.supported, tc.notSupported, tc.unknown, tc.basis)
		}
	}
	// 対象でない成果物（PQC の事実を持たないもの）と、事実のないライブラリ
	if _, ok := rule.For("bcpkix-jdk18on", "1.80"); ok {
		t.Error("an artifact without facts must not get a result")
	}
	var none *PQCRule
	if _, ok := none.For("x", "1.0"); ok {
		t.Error("a library without facts must not get a result")
	}
}

// 内包のルールにある事実（測定の結果）。
func TestBuiltinPQCFacts(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	java := func(file string) (PQCResult, bool) {
		rule, artifact, version, ok := rs.JavaLibraryForFile(file)
		if !ok {
			t.Fatalf("%s: not a known library", file)
		}
		return rule.PQC.For(artifact, version)
	}
	for _, tc := range []struct{ file, supported, notSupported, unknown string }{
		{"bcprov-jdk18on-1.78.1.jar", "", "ML-KEM,ML-DSA,SLH-DSA", ""},
		{"bcprov-jdk18on-1.79.jar", "ML-KEM,ML-DSA,SLH-DSA", "", ""},
		{"bcprov-jdk15on-1.70.jar", "", "ML-KEM,ML-DSA,SLH-DSA", ""},
		{"bctls-jdk18on-1.79.jar", "", "TLS-MLKEM,TLS-MLKEM-hybrid", ""},
		{"bctls-jdk18on-1.80.jar", "TLS-MLKEM", "TLS-MLKEM-hybrid", ""},
		{"bctls-jdk18on-1.81.jar", "TLS-MLKEM,TLS-MLKEM-hybrid", "", ""},
		{"bc-fips-2.1.3.jar", "", "ML-KEM,ML-DSA,SLH-DSA", ""},
		{"bc-fips-2.2.0.jar", "", "", "ML-KEM,ML-DSA,SLH-DSA"},
		{"conscrypt-openjdk-uber-2.5.2.jar", "", "ML-KEM,ML-DSA,SLH-DSA,TLS-MLKEM-hybrid", ""},
		{"conscrypt-openjdk-uber-2.6.0.jar", "ML-KEM,ML-DSA,SLH-DSA,TLS-MLKEM-hybrid", "", ""},
		{"netty-tcnative-boringssl-static-2.0.66.Final.jar", "", "TLS-MLKEM-hybrid", ""},
		{"netty-tcnative-boringssl-static-2.0.67.Final.jar", "", "", "TLS-MLKEM-hybrid"},
		{"netty-tcnative-boringssl-static-2.0.68.Final-linux-x86_64.jar", "TLS-MLKEM-hybrid", "", ""},
	} {
		r, ok := java(tc.file)
		if !ok || strings.Join(r.Supported, ",") != tc.supported || strings.Join(r.NotSupported, ",") != tc.notSupported || strings.Join(r.Unknown, ",") != tc.unknown {
			t.Errorf("%s: %+v ok=%v", tc.file, r, ok)
		}
	}
	// PQC の事実を持たない成果物
	for _, file := range []string{"bcpkix-jdk18on-1.80.jar", "netty-tcnative-classes-2.0.70.Final.jar", "tomcat-embed-core-10.1.55.jar"} {
		if r, ok := java(file); ok {
			t.Errorf("%s: no facts are expected: %+v", file, r)
		}
	}
	// OpenSSL（ライブラリ本体の版から）
	var openssl *LibraryRule
	for i := range rs.Libraries {
		if rs.Libraries[i].ID == "openssl" {
			openssl = &rs.Libraries[i]
		}
	}
	if openssl == nil {
		t.Fatal("no openssl rule")
	}
	for version, want := range map[string]bool{"3.5.0": true, "3.5.9": true, "3.4.1": false, "3.0.13": false, "1.1.1k": false} {
		r, ok := openssl.PQC.For("", version)
		if !ok || (len(r.Supported) == 5) != want || (len(r.NotSupported) == 5) == want {
			t.Errorf("openssl %s: %+v ok=%v", version, r, ok)
		}
	}
}

// 事実には出典が要る。名前や版の形も確かめる。
func TestPQCRuleValidation(t *testing.T) {
	src := []Source{{Image: "maven@sha256:851ccd76d49d5646915645e5fb51e9b00ef53ad3dc68b0e9a2a9846b9c56bde3", OS: "Ubuntu 26.04.1 LTS", Note: "measured"}}
	ok := PQCRule{Sources: src, Features: []PQCFeature{{Name: "ML-KEM", Since: "1.79", Checked: VersionRange{From: "1.71", To: "1.87"}}}}
	if err := checkPQC(&ok); err != nil {
		t.Errorf("a valid rule is rejected: %v", err)
	}
	for name, bad := range map[string]PQCRule{
		"no sources":        {Features: ok.Features},
		"no features":       {Sources: src},
		"bad name":          {Sources: src, Features: []PQCFeature{{Name: "ML KEM<script>", Since: "1.79", Checked: VersionRange{From: "1.71", To: "1.87"}}}},
		"bad since":         {Sources: src, Features: []PQCFeature{{Name: "ML-KEM", Since: "1.80-SNAPSHOT", Checked: VersionRange{From: "1.71", To: "1.87"}}}},
		"no checked range":  {Sources: src, Features: []PQCFeature{{Name: "ML-KEM", Since: "1.79"}}},
		"range upside down": {Sources: src, Features: []PQCFeature{{Name: "ML-KEM", Since: "1.79", Checked: VersionRange{From: "1.87", To: "1.71"}}}},
		"bad evidence":      {Sources: src, Features: []PQCFeature{{Name: "ML-KEM", Since: "1.79", Evidence: "memory", Checked: VersionRange{From: "1.71", To: "1.87"}}}},
	} {
		if err := checkPQC(&bad); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}
