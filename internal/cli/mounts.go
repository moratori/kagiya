package cli

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"

	"kagiya/internal/platform"
	"kagiya/internal/safefs"
)

// mountState はマウント表の取得結果。
type mountState struct {
	table *safefs.MountTable // nil: この OS では取得できない
	err   error              // 取得できるはずの OS で失敗した
}

func loadMounts() *mountState {
	data, ok := platform.MountInfo()
	if !ok {
		if runtime.GOOS == "linux" {
			return &mountState{err: errors.New("cannot read the mount table (/proc/self/mountinfo); refusing to run because network filesystems could not be avoided")}
		}
		return &mountState{}
	}
	mounts, err := safefs.ParseMountInfo(bytes.NewReader(data))
	if err != nil {
		return &mountState{err: fmt.Errorf("cannot parse the mount table: %w", err)}
	}
	return &mountState{table: safefs.NewMountTable(mounts, safefs.DefaultPolicy())}
}

// requireLocal は、パスがネットワーク FS 等の上にないことを確かめる（読み書きが通信になるため）。
func (m *mountState) requireLocal(path, what string) error {
	if m.err != nil {
		return m.err
	}
	if m.table == nil {
		return nil
	}
	if v, mnt := m.table.Check(path); v != safefs.Allow {
		return fmt.Errorf("%s %s is on a filesystem that must not be used (%s: %s); use a local directory", what, path, v.Reason(), mnt.FSType)
	}
	return nil
}

func checkWritableLocation(path string, m *mountState) error {
	return m.requireLocal(path, "output directory")
}
