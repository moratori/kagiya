package cli

import (
	"os"
	"time"
)

// 「安全に停止」を始めてから、強制的に終わるまでの猶予。
const stopGrace = 30 * time.Second

// watchStop は、シグナルと時間制限を見張る（別のゴルーチンで動かす。主の処理がシステムコールの中で止まっていても動くように）。
//
//   - 1 回目のシグナルで cancel を呼び、「安全に停止」（区切りまで進めて、途中の結果を書く）を始めさせる。
//   - その後、2 回目のシグナルか、猶予（grace）の経過で、exit を呼んで強制的に終わる。
//   - 時間制限などで止まり始めた場合（stop が閉じられた場合）も、同じ猶予で強制的に終わる。
//   - スキャンが終われば（done が閉じられれば）、何もせずに終わる。
func watchStop(sig <-chan os.Signal, stop <-chan struct{}, cancel func(), done <-chan struct{}, grace time.Duration, exit func(int)) {
	select {
	case <-sig:
		cancel()
	case <-stop:
	case <-done:
		return
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-sig:
	case <-timer.C:
	case <-done:
		return
	}
	exit(exitFatal)
}
