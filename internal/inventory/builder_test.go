package inventory

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"kagiya/internal/logx"
	"kagiya/internal/model"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

// Guard は、1 つのファイル（やアプリ）の処理の中で起きた panic を、そこで止める。スキャン全体は止めず、読めなかったものとして記録する。
// panic の値は、入力の断片を含みうるので、記録しない（実行時エラーの種類だけを残す）。
func TestGuard(t *testing.T) {
	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	b := NewBuilder(rs, logx.New(&log, time.Now))

	ran := false
	b.Guard("/etc/app/ok.pem", "parsing a file", func() { ran = true })
	if !ran || b.SkipTotal() != 0 {
		t.Fatalf("a function that does not panic must simply run: ran=%v skips=%d", ran, b.SkipTotal())
	}

	// 実行時エラー（範囲外の参照）
	b.Guard("/etc/app/broken.p12", "parsing a file", func() {
		var data []byte
		i := 5
		_ = data[i]
	})
	// 値つきの panic（入力の断片を含みうる）
	b.Guard("/etc/app/odd.conf", "reading the settings of nginx", func() { panic("unexpected token s3cret-panic-value") })
	b.Guard("", "collecting packages", func() { panic(struct{ secret string }{"s3cret-panic-value"}) })

	inv := b.Inventory()
	if len(inv.Skipped) != 3 || b.ProblemSkips() != 3 {
		t.Fatalf("skipped = %+v (problem skips %d)", inv.Skipped, b.ProblemSkips())
	}
	s := inv.Skipped[0]
	if s.Path != "/etc/app/broken.p12" || s.Reason != "internal-error" || !strings.Contains(s.Detail, "parsing a file") || !strings.Contains(s.Detail, "index out of range") {
		t.Errorf("runtime error: %+v", s)
	}
	if s := inv.Skipped[1]; s.Path != "/etc/app/odd.conf" || s.Reason != "internal-error" || !strings.Contains(s.Detail, "reading the settings of nginx") {
		t.Errorf("panic with a value: %+v", s)
	}
	if s := inv.Skipped[2]; s.Path != "" || s.Reason != "internal-error" || !strings.Contains(s.Detail, "collecting packages") {
		t.Errorf("panic without a path: %+v", s)
	}
	out, _ := json.Marshal(inv)
	if strings.Contains(string(out), "s3cret") || strings.Contains(log.String(), "s3cret") {
		t.Error("the value of a panic appears in the result or the log")
	}
	if !strings.Contains(log.String(), "internal-error") {
		t.Errorf("the log must record the internal error: %s", log.String())
	}
}

// 止める合図が出た後は、次の処理を始めない（処理の途中では止めないので、中途半端な結果は残らない）。
func TestGuardDoesNotStartAfterStop(t *testing.T) {
	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	b := NewBuilder(rs, logx.New(&bytes.Buffer{}, time.Now))
	stopped := false
	b.SetStop(func() bool { return stopped })
	ran := 0
	b.Guard("/a", "reading a file", func() { ran++ })
	stopped = true
	b.Guard("/b", "reading a file", func() { ran++ })
	if ran != 1 || !b.Stopped() || b.SkipTotal() != 0 {
		t.Errorf("ran = %d stopped = %v skips = %d", ran, b.Stopped(), b.SkipTotal())
	}
}

// 以下は、独立したレビュー（2026-11-14）の指摘 A-5・A-7・B-4 への対応。

// 読み飛ばしのログは、理由ごとに先頭の決まった件数まで。残りは数えて、最後に理由ごとの総数を 1 行で出す
// （除外したファイルが何百万もあるときに、ログがディスクを埋めないように）。
func TestSkipLogIsBounded(t *testing.T) {
	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	b := NewBuilder(rs, logx.New(&log, time.Now))
	for i := 0; i < maxLoggedSkipsPerReason+500; i++ {
		b.Skip(safefs.Skip{Path: "/srv/www/f" + strconv.Itoa(i) + ".key", Reason: "parse-error"})
	}
	// 除外の指定で外したものは、名前を残さない（結果にも、ログにも）。件数だけ
	for i := 0; i < 3; i++ {
		b.Skip(safefs.Skip{Path: "/srv/private/secret-name-" + strconv.Itoa(i), Reason: "excluded"})
	}
	inv := b.Inventory()
	if n := strings.Count(log.String(), `"event":"skip"`); n != maxLoggedSkipsPerReason {
		t.Errorf("logged skips = %d, want %d", n, maxLoggedSkipsPerReason)
	}
	if !strings.Contains(log.String(), `"event":"skip-summary"`) || !strings.Contains(log.String(), `"parse-error":`+strconv.Itoa(maxLoggedSkipsPerReason+500)) ||
		!strings.Contains(log.String(), `"excluded":3`) {
		t.Errorf("the summary line is missing or wrong: %s", log.String()[max(0, log.Len()-400):])
	}
	out, _ := json.Marshal(inv)
	if strings.Contains(log.String(), "secret-name") || strings.Contains(string(out), "secret-name") {
		t.Error("the name of an excluded path is recorded")
	}
	if inv.Coverage.SkippedByReason["excluded"] != 3 || b.ProblemSkips() != maxLoggedSkipsPerReason+500 {
		t.Errorf("counts: %v, problem skips %d", inv.Coverage.SkippedByReason, b.ProblemSkips())
	}
}

// 資産と出現の数には上限がある。超えた分は記録せず、打ち切ったことが分かるようにする。
func TestRecordLimits(t *testing.T) {
	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	b := NewBuilder(rs, logx.New(&bytes.Buffer{}, time.Now))
	b.MaxAssets, b.MaxOccurrences = 2, 3
	for i := 0; i < 5; i++ {
		id := "cert:sha256:" + strconv.Itoa(i)
		a := b.Asset(id, func() model.Asset { return model.Asset{Type: "certificate"} })
		if a == nil {
			t.Fatal("Asset must always return something to fill in")
		}
		b.Occur(id, "fscrawl", model.Location{Kind: "file", Path: "/etc/c" + strconv.Itoa(i) + ".pem"}, nil)
	}
	inv := b.Inventory()
	if len(inv.Assets) != 2 || len(inv.Occurrences) > 3 || !b.Overflowed() {
		t.Errorf("assets = %d occurrences = %d overflowed = %v", len(inv.Assets), len(inv.Occurrences), b.Overflowed())
	}
	// 記録しなかった資産への出現は、残さない（参照先のない出現を作らない）
	for _, o := range inv.Occurrences {
		if o.Asset != "cert:sha256:0" && o.Asset != "cert:sha256:1" {
			t.Errorf("an occurrence refers to an asset that was not recorded: %+v", o)
		}
	}
	if inv.Coverage.SkippedByReason["limit"] == 0 {
		t.Errorf("the cut must be recorded: %v", inv.Coverage.SkippedByReason)
	}
}

// 処理の区切りごとに、流量制限の休止を入れる（探索の後のフェーズにも、CPU の上限が効くように）。
func TestGuardYields(t *testing.T) {
	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	b := NewBuilder(rs, logx.New(&bytes.Buffer{}, time.Now))
	n := 0
	b.SetYield(func() { n++ })
	for i := 0; i < 3; i++ {
		b.Guard("", "reading a file", func() {})
	}
	if n != 3 {
		t.Errorf("yield was called %d times, want 3", n)
	}
}
