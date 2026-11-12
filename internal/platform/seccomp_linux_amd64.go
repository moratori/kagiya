//go:build linux && amd64

package platform

const sysSeccomp = 317

// renameat2（上書きしない改名に使う）
const sysRenameat2 = 316
