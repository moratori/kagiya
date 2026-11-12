// Package throttle は本番環境への負荷を抑えるための流量制限（CPU 使用率と読み取り速度）を提供する。
// 優先度を下げるだけでは空きコアを使い切ってしまうため、自分から休む（設計書 6章）。
package throttle

import "time"

type Config struct {
	CPUPercent     int   // 1コアに対する使用率の上限。1〜99 以外は無制限
	BytesPerSecond int64 // 読み取り速度の上限。0 以下は無制限
}

type Clock interface {
	Now() time.Time
	Sleep(time.Duration)
}

type realClock struct{}

func (realClock) Now() time.Time        { return time.Now() }
func (realClock) Sleep(d time.Duration) { time.Sleep(d) }

// RealClock は実時間の時計。
func RealClock() Clock { return realClock{} }

// 休止を細切れにしないよう、これだけ作業時間がたまってから休む。
const minWork = 10 * time.Millisecond

// Limiter は単一のゴルーチンから使う。
type Limiter struct {
	cfg   Config
	clock Clock

	mark time.Time     // 作業時間の計測開始点
	work time.Duration // 未精算の作業時間

	tokens   float64 // 読み取り可能なバイト数
	lastFill time.Time
}

func New(cfg Config, clock Clock) *Limiter {
	now := clock.Now()
	return &Limiter{cfg: cfg, clock: clock, mark: now, lastFill: now}
}

// Yield は直前の Yield 以降の作業時間に応じて休む。処理の区切り（ファイル単位など）で呼ぶ。
func (l *Limiter) Yield() {
	p := l.cfg.CPUPercent
	if p <= 0 || p >= 100 {
		return
	}
	now := l.clock.Now()
	l.work += now.Sub(l.mark)
	l.mark = now
	if l.work < minWork {
		return
	}
	rest := l.work * time.Duration(100-p) / time.Duration(p)
	l.work = 0
	l.clock.Sleep(rest)
	l.mark = l.clock.Now()
}

// Bytes は n バイトの読み取りを申告し、上限を超える分だけ休む。ためられる余裕は1秒分まで。
func (l *Limiter) Bytes(n int64) {
	rate := float64(l.cfg.BytesPerSecond)
	if rate <= 0 || n <= 0 {
		return
	}
	now := l.clock.Now()
	l.tokens += now.Sub(l.lastFill).Seconds() * rate
	if l.tokens > rate {
		l.tokens = rate
	}
	l.lastFill = now
	l.tokens -= float64(n)
	if l.tokens < 0 {
		wait := time.Duration(-l.tokens / rate * float64(time.Second))
		l.clock.Sleep(wait)
		l.tokens = 0
		l.lastFill = l.clock.Now()
		// 休止は作業時間に数えない
		l.mark = l.lastFill
	}
}
