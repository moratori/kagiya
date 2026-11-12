//go:build linux

package platform

import (
	"io/fs"
	"os"
	"syscall"
)

// MountInfo は自プロセスのマウント表（/proc/self/mountinfo）の内容を返す。
func MountInfo() ([]byte, bool) {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, false
	}
	return b, true
}

// DeviceOf はファイルが載っているデバイスの番号を返す。
func DeviceOf(fi fs.FileInfo) (major, minor uint32, ok bool) {
	st, isStat := fi.Sys().(*syscall.Stat_t)
	if !isStat {
		return 0, 0, false
	}
	dev := uint64(st.Dev)
	major = uint32((dev>>8)&0xfff) | uint32((dev>>32)&^uint64(0xfff))
	minor = uint32(dev&0xff) | uint32((dev>>12)&^uint64(0xff))
	return major, minor, true
}
