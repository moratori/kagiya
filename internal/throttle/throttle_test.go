package throttle

import (
	"testing"
	"time"
)

type fakeClock struct {
	now   time.Time
	slept time.Duration
}

func (c *fakeClock) Now() time.Time        { return c.now }
func (c *fakeClock) Sleep(d time.Duration) { c.slept += d; c.now = c.now.Add(d) }
func (c *fakeClock) work(d time.Duration)  { c.now = c.now.Add(d) }

// CPU 上限 25% なら、100ms 働いたら 300ms 休む。
func TestCPUDutyCycle(t *testing.T) {
	c := &fakeClock{now: time.Unix(0, 0)}
	l := New(Config{CPUPercent: 25}, c)
	c.work(100 * time.Millisecond)
	l.Yield()
	if c.slept != 300*time.Millisecond {
		t.Errorf("slept %v, want 300ms", c.slept)
	}
	// 休止時間は次の作業時間に数えない
	c.work(50 * time.Millisecond)
	l.Yield()
	if c.slept != 450*time.Millisecond {
		t.Errorf("slept %v, want 450ms", c.slept)
	}
}

func TestCPUDutyIgnoresTinyWork(t *testing.T) {
	c := &fakeClock{now: time.Unix(0, 0)}
	l := New(Config{CPUPercent: 25}, c)
	// ごく短い作業ごとに sleep を呼ばず、ある程度ためてから休む
	for i := 0; i < 5; i++ {
		c.work(1 * time.Millisecond)
		l.Yield()
	}
	if c.slept != 0 {
		t.Errorf("slept %v after 5ms of work, want 0 (accumulate)", c.slept)
	}
	c.work(20 * time.Millisecond)
	l.Yield()
	if c.slept != 75*time.Millisecond {
		t.Errorf("slept %v, want 75ms (3x of 25ms accumulated)", c.slept)
	}
}

func TestNoLimits(t *testing.T) {
	c := &fakeClock{now: time.Unix(0, 0)}
	l := New(Config{}, c)
	c.work(time.Second)
	l.Yield()
	l.Bytes(1 << 30)
	if c.slept != 0 {
		t.Errorf("slept %v with no limits", c.slept)
	}
}

// 読み取り 1MiB/秒 の上限: 3MiB 読んだら、累計で 3 秒かかるように休む。
func TestIORate(t *testing.T) {
	c := &fakeClock{now: time.Unix(0, 0)}
	l := New(Config{BytesPerSecond: 1 << 20}, c)
	l.Bytes(1 << 20)
	l.Bytes(1 << 20)
	l.Bytes(1 << 20)
	elapsed := c.now.Sub(time.Unix(0, 0))
	if elapsed < 2900*time.Millisecond || elapsed > 3100*time.Millisecond {
		t.Errorf("elapsed %v for 3MiB at 1MiB/s, want ~3s", elapsed)
	}
}

// しばらく読まなかった後に、ためた分を一気に使うこと（バースト）は 1 秒分まで。
func TestIORateBurstIsBounded(t *testing.T) {
	c := &fakeClock{now: time.Unix(0, 0)}
	l := New(Config{BytesPerSecond: 1 << 20}, c)
	c.work(time.Hour)
	start := c.now
	l.Bytes(5 << 20)
	elapsed := c.now.Sub(start)
	if elapsed < 3900*time.Millisecond {
		t.Errorf("elapsed %v for 5MiB after idle, want >= ~4s (burst limited to 1s worth)", elapsed)
	}
}

func TestCPUPercentOutOfRangeMeansNoLimit(t *testing.T) {
	for _, p := range []int{0, 100, 150, -5} {
		c := &fakeClock{now: time.Unix(0, 0)}
		l := New(Config{CPUPercent: p}, c)
		c.work(time.Second)
		l.Yield()
		if c.slept != 0 {
			t.Errorf("CPUPercent=%d: slept %v, want 0", p, c.slept)
		}
	}
}
