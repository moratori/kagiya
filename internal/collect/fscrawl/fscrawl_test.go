package fscrawl

import (
	"io"
	"testing"
	"time"

	"kagiya/internal/inventory"
	"kagiya/internal/logx"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

// 1 つのファイルの処理で panic が起きても、探索は止まらない（そのファイルを、読めなかったものとして記録する）。
func TestVisitSurvivesPanic(t *testing.T) {
	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	b := inventory.NewBuilder(rs, logx.New(io.Discard, time.Now))
	c := New(b)
	// 探索を通さずに作った項目は、読もうとすると panic する（パーサの中での panic の代わり）
	if err := c.Visit(&safefs.Entry{Path: "/etc/app/server.pem", Name: "server.pem", Size: 100}); err != nil {
		t.Errorf("Visit must not stop the walk: %v", err)
	}
	inv := b.Inventory()
	if len(inv.Skipped) != 1 || inv.Skipped[0].Reason != "internal-error" || inv.Skipped[0].Path != "/etc/app/server.pem" {
		t.Errorf("skipped = %+v", inv.Skipped)
	}
}
