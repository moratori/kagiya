// Package logx は実行ログを JSON Lines で書き出す。
// 値は JSON としてエスケープされるため、ファイル由来の文字列に改行や制御文字があっても1レコード1行が保たれる。
// 秘密情報を渡さない責任は呼び出し側にある（設計書 4.5）。
package logx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

type Logger struct {
	mu           sync.Mutex
	w            io.Writer
	now          func() time.Time
	warns, errs  int
	writeFailure error

	// MaxBytes は、ログ全体の大きさの上限（0 なら上限なし）。
	MaxBytes int64
}

func New(w io.Writer, now func() time.Time) *Logger {
	return &Logger{w: w, now: now}
}

func (l *Logger) Info(event string, kv ...any)  { l.log("info", event, kv) }
func (l *Logger) Warn(event string, kv ...any)  { l.log("warn", event, kv) }
func (l *Logger) Error(event string, kv ...any) { l.log("error", event, kv) }

// Counts は警告とエラーの件数を返す。
func (l *Logger) Counts() (warns, errs int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.warns, l.errs
}

// Err は書き込みに失敗していればその最初のエラーを返す。
func (l *Logger) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.writeFailure
}

func (l *Logger) log(level, event string, kv []any) {
	var b bytes.Buffer
	b.WriteByte('{')
	field := func(k string, v any) {
		if b.Len() > 1 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		vb, err := json.Marshal(v)
		if err != nil {
			vb, _ = json.Marshal(fmt.Sprint(v))
		}
		b.Write(kb)
		b.WriteByte(':')
		b.Write(vb)
	}
	field("time", l.now().UTC().Format(time.RFC3339))
	field("level", level)
	field("event", event)
	for i := 0; i+1 < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok || k == "time" || k == "level" || k == "event" {
			continue
		}
		field(k, kv[i+1])
	}
	b.WriteString("}\n")

	l.mu.Lock()
	defer l.mu.Unlock()
	switch level {
	case "warn":
		l.warns++
	case "error":
		l.errs++
	}
	if _, err := l.w.Write(b.Bytes()); err != nil && l.writeFailure == nil {
		l.writeFailure = err
	}
}
