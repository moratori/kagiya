package ruleset

import "testing"

// WildFly の対応表（検証ラボで、19.0.0.Final〜42.0.0.Final の 54 版の配布物を展開して採取し、場面ごとに起動して確かめたもの）。
func TestWildFlyTable(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	tb, v, ok := rs.WildFlyFor("42.0.0.Final")
	if !ok || v.LegacyRealm || len(v.SHA256) != 64 || tb.DefaultCipherSuiteFilter != "DEFAULT" || !tb.TLS13RequiresCipherSuiteNames {
		t.Fatalf("42.0.0.Final: %+v ok=%v", v, ok)
	}
	if len(tb.Suites) != 303 || len(tb.TLS13) != 5 || len(tb.Aliases) != 2 || len(tb.Versions) != 54 {
		t.Errorf("suites=%d tls13=%d aliases=%d versions=%d", len(tb.Suites), len(tb.TLS13), len(tb.Aliases), len(tb.Versions))
	}
	// 24 までは、古い形式の設定（security-realm）がある
	if _, v, ok := rs.WildFlyFor("24.0.1.Final"); !ok || !v.LegacyRealm {
		t.Errorf("24.0.1.Final: %+v ok=%v", v, ok)
	}
	if _, v, ok := rs.WildFlyFor("25.0.0.Final"); !ok || v.LegacyRealm {
		t.Errorf("25.0.0.Final: %+v ok=%v", v, ok)
	}
	// 測っていない版は、返さない（補間しない）
	for _, version := range []string{"18.0.1.Final", "42.0.1.Final", "43.0.0.Final", "42.0.0", ""} {
		if _, _, ok := rs.WildFlyFor(version); ok {
			t.Errorf("%q must not be found", version)
		}
	}
}

func TestWildFlyTableValidation(t *testing.T) {
	src := Source{Image: "ubuntu@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5", OS: "Ubuntu 24.04.5 LTS"}
	sha := "105ab8b96d86feb1d11da4006ef318e37205ddf748f71e60ac6971adee0244dc"
	suite := ElytronSuite{Name: "TLS_RSA_WITH_AES_128_CBC_SHA", OpenSSL: []string{"AES128-SHA"}, Kx: "RSA", Auth: "RSA", Enc: "AES128", Mac: "SHA1", Protocol: "TLSv1", Level: "HIGH", Bits: 128}
	good := func() *WildFlyTable {
		return &WildFlyTable{Source: src, ElytronTableSHA256: sha, DefaultCipherSuiteFilter: "DEFAULT", DefaultProtocols: []string{"TLSv1.2"}, LegacyDefaultProtocols: []string{"TLSv1.2"},
			Versions: []WildFlyVersion{{Version: "42.0.0.Final", SHA256: sha}}, Suites: []ElytronSuite{suite},
			TLS13: []ElytronSuite{{Name: "TLS_AES_128_GCM_SHA256", OpenSSL: []string{"TLS_AES_128_GCM_SHA256"}, Kx: "ANY", Auth: "ANY", Enc: "AES128GCM", Mac: "AEAD", Protocol: "TLSv1.3", Level: "HIGH", Bits: 128}}}
	}
	if err := (&RuleSet{}).addWildFlyTable(good(), map[string]bool{}); err != nil {
		t.Fatalf("a valid table is rejected: %v", err)
	}
	for name, change := range map[string]func(*WildFlyTable){
		"no source":            func(t *WildFlyTable) { t.Source = Source{} },
		"no versions":          func(t *WildFlyTable) { t.Versions = nil },
		"bad version":          func(t *WildFlyTable) { t.Versions[0].Version = "42.0.0<x>" },
		"bad checksum":         func(t *WildFlyTable) { t.Versions[0].SHA256 = "abc" },
		"duplicate version":    func(t *WildFlyTable) { t.Versions = append(t.Versions, t.Versions[0]) },
		"no suites":            func(t *WildFlyTable) { t.Suites = nil },
		"bad suite name":       func(t *WildFlyTable) { t.Suites[0].Name = "TLS RSA" },
		"duplicate suite":      func(t *WildFlyTable) { t.Suites = append(t.Suites, t.Suites[0]) },
		"alias to nothing":     func(t *WildFlyTable) { t.Aliases = []ElytronAlias{{Name: "TLS_X", Target: "TLS_NOSUCH"}} },
		"bad protocol":         func(t *WildFlyTable) { t.DefaultProtocols = []string{"TLS 1.2"} },
		"empty default filter": func(t *WildFlyTable) { t.DefaultCipherSuiteFilter = "" },
	} {
		tb := good()
		change(tb)
		if err := (&RuleSet{}).addWildFlyTable(tb, map[string]bool{}); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}
