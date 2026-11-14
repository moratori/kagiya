package cli

import (
	"os"
	"time"
)

// watchStop は、シグナルと時間制限を見張る。
func watchStop(sig <-chan os.Signal, stop <-chan struct{}, cancel func(), done <-chan struct{}, grace time.Duration, exit func(int)) {
}
