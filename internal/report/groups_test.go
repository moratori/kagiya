package report

import (
	"regexp"
	"testing"

	"kagiya/internal/model"
)

// 受け入れる鍵交換のグループは、項目名と判定つきで示す（耐量子のハイブリッドを受け入れるかどうかが分かる）。
func TestReportGroups(t *testing.T) {
	inv := sample()
	inv.EffectiveValues = append(inv.EffectiveValues, model.EffectiveValue{ID: "eff:9", Service: "svc:nginx", Parameter: model.ParamTLSGroups,
		Direction: "inbound", Scope: "server www.example.jp", Status: "resolved", Confidence: "high", Values: []string{"X25519MLKEM768", "ffdhe2048"},
		Steps: []model.ResolutionStep{{Layer: "library", Op: "default"}}})
	html := render(t, inv)
	mustContain(t, html, "鍵交換のグループ", "X25519MLKEM768", "ffdhe2048",
		"ML-KEM（FIPS 203）と ECDH を組み合わせた鍵交換のグループ") // 当たった規則の説明
	if regexp.MustCompile(`>tls\.groups<`).MatchString(html) {
		t.Error("the parameter must be shown with its label, not its internal name")
	}
}
