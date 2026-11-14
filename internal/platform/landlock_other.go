//go:build !linux

package platform

// RestrictWrites は、Linux 以外では使えない。
func RestrictWrites(dirs []string) (status, note string) { return "unsupported", "" }
