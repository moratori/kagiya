//go:build !linux

package platform

// NoAtime は、Linux 以外では使えない（フラグなし）。
const NoAtime = 0

// DirectoryFlag は、Linux 以外では付けない。
const DirectoryFlag = 0
