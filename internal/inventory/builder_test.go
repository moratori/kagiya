package inventory

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"kagiya/internal/logx"
	"kagiya/internal/ruleset"
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
