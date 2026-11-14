package cli

import (
	"os"
	"testing"
	"time"
)

// 以下は、独立したレビュー（2026-11-14）の指摘 A-3 への対応。
// 1 回目のシグナルで「安全に停止」を始め、2 回目のシグナルか、猶予の経過で、強制的に終わる。

func startWatcher(grace time.Duration) (sig chan os.Signal, stop chan struct{}, cancelled, exited chan int, done chan struct{}) {
	sig = make(chan os.Signal, 2)
	stop = make(chan struct{})
	cancelled = make(chan int, 1)
	exited = make(chan int, 1)
	done = make(chan struct{})
	go watchStop(sig, stop, func() { cancelled <- 1 }, done, grace, func(code int) { exited <- code })
	return
}

func within(t *testing.T, c chan int, d time.Duration, what string) int {
	t.Helper()
	select {
	case v := <-c:
		return v
	case <-time.After(d):
		t.Fatalf("%s did not happen within %v", what, d)
		return 0
	}
}

func never(t *testing.T, c chan int, d time.Duration, what string) {
	t.Helper()
	select {
	case <-c:
		t.Fatalf("%s must not happen", what)
	case <-time.After(d):
	}
}

func TestSecondSignalForcesExit(t *testing.T) {
	sig, _, cancelled, exited, done := startWatcher(time.Hour)
	defer close(done)
	sig <- os.Interrupt
	within(t, cancelled, time.Second, "the graceful stop")
	never(t, exited, 50*time.Millisecond, "a forced exit after one signal")
	sig <- os.Interrupt
	if code := within(t, exited, time.Second, "the forced exit"); code != exitFatal {
		t.Errorf("exit code = %d", code)
	}
}

func TestGracePeriodForcesExit(t *testing.T) {
	sig, _, cancelled, exited, done := startWatcher(50 * time.Millisecond)
	defer close(done)
	sig <- os.Interrupt
	within(t, cancelled, time.Second, "the graceful stop")
	if code := within(t, exited, time.Second, "the forced exit after the grace period"); code != exitFatal {
		t.Errorf("exit code = %d", code)
	}
}

// 時間制限（--max-duration）で止まり始めた場合も、猶予を過ぎたら強制的に終わる。
func TestDeadlineAlsoStartsGracePeriod(t *testing.T) {
	_, stop, _, exited, done := startWatcher(50 * time.Millisecond)
	defer close(done)
	close(stop)
	within(t, exited, time.Second, "the forced exit after the grace period")
}

// スキャンが終われば、見張りも終わる（後から強制終了しない）。
func TestWatcherEndsWithScan(t *testing.T) {
	sig, _, cancelled, exited, done := startWatcher(50 * time.Millisecond)
	close(done)
	never(t, exited, 150*time.Millisecond, "a forced exit after the scan finished")
	sig, _, cancelled, exited, done = startWatcher(50 * time.Millisecond)
	sig <- os.Interrupt
	within(t, cancelled, time.Second, "the graceful stop")
	close(done)
	never(t, exited, 150*time.Millisecond, "a forced exit after the scan finished")
}
