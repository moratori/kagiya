//go:build !linux

package platform

import "io/fs"

// MountInfo は Linux 以外では取得できない。
func MountInfo() ([]byte, bool) { return nil, false }

// DeviceOf は Linux 以外では未対応。
func DeviceOf(fi fs.FileInfo) (major, minor uint32, ok bool) { return 0, 0, false }
