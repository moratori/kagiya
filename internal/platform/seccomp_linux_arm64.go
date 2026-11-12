//go:build linux && arm64

package platform

const sysSeccomp = 277

// renameat2（上書きしない改名に使う）
const sysRenameat2 = 276
