//go:build linux

package platform

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"syscall"
)

// MountInfo は自プロセスのマウント表（/proc/self/mountinfo）の内容を返す。
// 小さな読み取りを繰り返すと、途中でマウントが変わったときに行が抜けることがあるので、大きなバッファで 1 回の読み取りにし、
// さらに、2 回続けて同じ内容が読めるまで読み直す。
func MountInfo() ([]byte, bool) {
	return readStable(func() ([]byte, error) {
		f, err := os.Open("/proc/self/mountinfo")
		if err != nil {
			return nil, err
		}
		defer f.Close()
		for size := 1 << 20; size <= 64<<20; size *= 4 {
			buf := make([]byte, size)
			n, err := f.ReadAt(buf, 0)
			if err != nil && err != io.EOF {
				return nil, err
			}
			if n < size {
				return buf[:n], nil
			}
		}
		return nil, errors.New("the mount table is too large")
	})
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
