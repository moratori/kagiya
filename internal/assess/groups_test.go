package assess

import (
	"testing"

	"kagiya/internal/model"
	"kagiya/internal/ruleset"
)

// TLS の鍵交換のグループの判定。現行の楕円曲線・有限体 DH は量子計算機に弱く、ML-KEM との組み合わせはハイブリッド。
func TestGroups(t *testing.T) {
	e := evaluator(t)
	for _, c := range []struct{ name, quantum, classical, rule string }{
		{"X25519", "vulnerable", "ok", "tls-group-classical"},
		{"P-256", "vulnerable", "ok", "tls-group-classical"},
		{"P-521", "vulnerable", "ok", "tls-group-classical"},
		{"ffdhe2048", "vulnerable", "legacy", "tls-group-ffdhe2048"},
		{"ffdhe3072", "vulnerable", "ok", "tls-group-classical"},
		{"brainpoolP384r1tls13", "vulnerable", "ok", "tls-group-other-curves"},
		{"secp256k1", "vulnerable", "ok", "tls-group-other-curves"},
		{"K-283", "vulnerable", "ok", "tls-group-other-curves"},
		{"P-224", "vulnerable", "legacy", "tls-group-p224"},
		{"X25519MLKEM768", "hybrid", "ok", "tls-group-hybrid-mlkem"},
		{"SecP256r1MLKEM768", "hybrid", "ok", "tls-group-hybrid-mlkem"},
		{"SecP384r1MLKEM1024", "hybrid", "ok", "tls-group-hybrid-mlkem"},
		{"MLKEM768", "resistant", "ok", "tls-group-mlkem"},
		{"MLKEM1024", "resistant", "ok", "tls-group-mlkem"},
		{"MLKEM512", "resistant", "ok", "tls-group-mlkem512"},
	} {
		v, ok := e.Value("tls-group", c.name)
		if !ok || v.Quantum != c.quantum || v.Classical != c.classical || !has(v, c.rule) {
			t.Errorf("%s: got %+v ok=%v, want %s / %s (rule %s)", c.name, v, ok, c.quantum, c.classical, c.rule)
		}
	}
	if v, ok := e.Value("tls-group", "NoSuchGroup"); ok {
		t.Errorf("no rule should match an unknown group, got %+v", v)
	}
}

// 対応表にあるグループは、すべて判定できる。
func TestEveryMeasuredGroupHasVerdict(t *testing.T) {
	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	e := evaluator(t)
	n := 0
	for _, tb := range rs.GroupTables {
		for _, g := range tb.Groups {
			n++
			if _, ok := e.Value("tls-group", g.Name); !ok {
				t.Errorf("group %s has no rule", g.Name)
			}
		}
	}
	if n == 0 {
		t.Fatal("no group table")
	}
}

// 結果全体の評価に、鍵交換のグループが含まれる。
func TestAssessGroups(t *testing.T) {
	if SchemeFor(model.ParamTLSGroups) != "tls-group" {
		t.Fatalf("scheme for %s = %q", model.ParamTLSGroups, SchemeFor(model.ParamTLSGroups))
	}
	inv := &model.Inventory{EffectiveValues: []model.EffectiveValue{
		{ID: "eff:1", Service: "svc:nginx", Parameter: model.ParamTLSGroups, Status: model.StatusResolved, Values: []string{"X25519MLKEM768", "X25519"}},
		{ID: "eff:2", Service: "svc:nginx", Parameter: model.ParamTLSGroups, Status: model.StatusUnresolved, Values: []string{"P-384"}},
	}}
	a := evaluator(t).Assess(inv)
	if v := a.Values["tls-group:X25519MLKEM768"]; v.Quantum != "hybrid" {
		t.Errorf("hybrid: %+v", v)
	}
	if v := a.Values["tls-group:X25519"]; v.Quantum != "vulnerable" {
		t.Errorf("classical: %+v", v)
	}
	if _, ok := a.Values["tls-group:P-384"]; ok {
		t.Error("an unresolved value must not be assessed")
	}
}
