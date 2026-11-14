package logx

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLoggerWritesJSONLines(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, func() time.Time { return time.Date(2026, 11, 12, 3, 4, 5, 0, time.UTC) })
	l.Info("scan-start", "roots", 2)
	l.Warn("skip", "path", "/mnt/share", "reason", "network-fs")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines: %q", len(lines), buf.String())
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["time"] != "2026-11-12T03:04:05Z" || rec["level"] != "warn" || rec["event"] != "skip" ||
		rec["path"] != "/mnt/share" || rec["reason"] != "network-fs" {
		t.Errorf("unexpected record: %v", rec)
	}
}

// ファイル由来の文字列に改行や制御文字が含まれても、1レコード1行が保たれる（ログ偽装対策）。
func TestLoggerEscapesControlCharacters(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, time.Now)
	l.Info("skip", "path", "/tmp/evil\n{\"level\":\"info\",\"event\":\"forged\"}\x1b[31m")
	out := buf.String()
	if strings.Count(out, "\n") != 1 {
		t.Errorf("record must be exactly one line: %q", out)
	}
	if strings.ContainsRune(strings.TrimSuffix(out, "\n"), '\x1b') {
		t.Errorf("raw control character in log: %q", out)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(out), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["event"] != "skip" {
		t.Errorf("event = %v", rec["event"])
	}
}

func TestLoggerReservedKeysCannotBeOverridden(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, time.Now)
	l.Info("real", "event", "fake", "level", "fake")
	var rec map[string]any
	json.Unmarshal(buf.Bytes(), &rec)
	if rec["event"] != "real" || rec["level"] != "info" {
		t.Errorf("reserved keys overridden: %v", rec)
	}
}

func TestLoggerCountsByLevel(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, time.Now)
	l.Info("a")
	l.Warn("b")
	l.Warn("c")
	l.Error("d")
	if w, e := l.Counts(); w != 2 || e != 1 {
		t.Errorf("Counts() = %d, %d; want 2, 1", w, e)
	}
}

// ログ全体の大きさには上限がある。超えたら「以降は省略」と 1 行書いて、それ以上は書かない（指摘 A-7）。
func TestLoggerStopsAtLimit(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, func() time.Time { return time.Unix(0, 0) })
	l.MaxBytes = 2000
	for i := 0; i < 1000; i++ {
		l.Warn("skip", "path", "/srv/www/some/long/path/to/a/file.key", "reason", "parse-error")
	}
	l.Error("scan-finished")
	if buf.Len() > 2000+300 {
		t.Errorf("the log grew to %d bytes", buf.Len())
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if last := lines[len(lines)-1]; !strings.Contains(last, `"event":"log-truncated"`) {
		t.Errorf("last line = %s", last)
	}
	if strings.Count(buf.String(), "log-truncated") != 1 || l.Err() != nil {
		t.Errorf("the notice must be written once: %v", l.Err())
	}
	// 件数は、書かなかった分も数える
	if w, e := l.Counts(); w != 1000 || e != 1 {
		t.Errorf("counts = %d, %d", w, e)
	}
}
