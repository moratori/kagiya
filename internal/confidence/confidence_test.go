package confidence

import "testing"

// 確度の決め方は、docs/confidence.md の 6.3 節（1 つのルールについて）と 6.4 節（複数のルールを使った場合）による。
// 材料は 2 つだけ: ルールを完全一致で見つけたか・補ったか、開発者がそのルールを数え上げで裏付けたか。
func TestOf(t *testing.T) {
	for _, c := range []struct {
		match    Match
		verified bool
		want     string
	}{
		{Exact, true, High},
		{Exact, false, Medium},
		{Filled, true, Medium},
		{Filled, false, Low},
	} {
		if got := Of(Rule{Match: c.match, VerifiedByHandshake: c.verified}); got != c.want {
			t.Errorf("match=%v verified=%v: %s, want %s", c.match, c.verified, got, c.want)
		}
	}
}

// 複数のルールを使った実効値は、ルールごとの確度のうち、最も低いものになる。
func TestOfSeveralRules(t *testing.T) {
	exactVerified := Rule{Match: Exact, VerifiedByHandshake: true}
	exactUnverified := Rule{Match: Exact, VerifiedByHandshake: false}
	filledVerified := Rule{Match: Filled, VerifiedByHandshake: true}
	filledUnverified := Rule{Match: Filled, VerifiedByHandshake: false}
	for _, c := range []struct {
		rules []Rule
		want  string
	}{
		{[]Rule{exactVerified, exactVerified}, High},
		{[]Rule{exactVerified, filledVerified}, Medium},
		{[]Rule{exactUnverified, exactVerified}, Medium},
		// 「補った」ルールと「裏付けのない」ルールが別々でも、それぞれは中なので、中
		{[]Rule{exactUnverified, filledVerified}, Medium},
		{[]Rule{exactVerified, filledUnverified}, Low},
		{[]Rule{filledUnverified, exactVerified, filledVerified}, Low},
	} {
		if got := Of(c.rules...); got != c.want {
			t.Errorf("%+v: %s, want %s", c.rules, got, c.want)
		}
	}
	// ルールを 1 つも渡さない呼び出しは、プログラムの誤り。高にはしない
	if got := Of(); got != Low {
		t.Errorf("no rules: %s, want %s", got, Low)
	}
}

// Lowest は、確度の並び（高 > 中 > 低）で、最も低いものを返す（JDK を 1 つに決められない場合などに使う）。
func TestLowest(t *testing.T) {
	for _, c := range []struct {
		levels []string
		want   string
	}{
		{[]string{High}, High},
		{[]string{High, Medium}, Medium},
		{[]string{Medium, High, Low}, Low},
		{[]string{High, High}, High},
		{[]string{High, "unknown-value"}, Low},
		{nil, Low},
	} {
		if got := Lowest(c.levels...); got != c.want {
			t.Errorf("%v: %s, want %s", c.levels, got, c.want)
		}
	}
}

// 結果に書く値は、決まった 3 つだけ。
func TestValues(t *testing.T) {
	if High != "high" || Medium != "medium" || Low != "low" {
		t.Errorf("values = %q %q %q", High, Medium, Low)
	}
}
