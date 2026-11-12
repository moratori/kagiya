//go:build linux

package platform

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	prSetDumpable   = 4
	prSetNoNewPrivs = 38

	seccompSetModeFilter   = 1
	seccompFilterFlagTSync = 1

	ioprioWhoProcess = 1
	ioprioClassIdle  = 3
	ioprioClassShift = 13

	niceLowest = 19
)

type sockFprog struct {
	Len    uint16
	Filter *sockFilter
}

// Harden は優先度を下げ、コアダンプを無効化し、seccomp で通信・プロセス起動を封じる。
// いずれもベストエフォートで、失敗しても処理は続ける（結果は Status に残す）。
// nice・I/O 優先度・no_new_privs はスレッド単位の属性なので、全スレッドに適用する。
func Harden() Status {
	var st Status

	// CPU 優先度
	if _, _, e := syscall.AllThreadsSyscall(syscall.SYS_SETPRIORITY, syscall.PRIO_PROCESS, 0, niceLowest); e != 0 {
		st.Notes = append(st.Notes, "setpriority: "+e.Error())
	}
	st.PriorityLowered = allThreadsHaveNice(niceLowest)

	// I/O 優先度（I/O スケジューラによっては効果がない。補助的な位置づけ）
	if _, _, e := syscall.AllThreadsSyscall(syscall.SYS_IOPRIO_SET, ioprioWhoProcess, 0, ioprioClassIdle<<ioprioClassShift); e != 0 {
		st.IOPriority = "failed"
		st.Notes = append(st.Notes, "ioprio_set: "+e.Error())
	} else {
		st.IOPriority = "applied"
	}

	// コアダンプ（出力先以外への書き込み・メモリ内容の流出）を防ぐ
	errLimit := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
	_, _, errDump := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0)
	st.CoreDumpDisabled = errLimit == nil && errDump == 0
	if errLimit != nil {
		st.Notes = append(st.Notes, "setrlimit(RLIMIT_CORE): "+errLimit.Error())
	}
	if errDump != 0 {
		st.Notes = append(st.Notes, "prctl(PR_SET_DUMPABLE): "+errDump.Error())
	}

	st.Seccomp = applySeccomp(&st)
	return st
}

func applySeccomp(st *Status) string {
	arch, ok := auditArch(runtime.GOARCH)
	denied := deniedSyscalls(runtime.GOARCH)
	if !ok || denied == nil || sysSeccomp == 0 {
		return "unsupported"
	}
	if _, _, e := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0); e != 0 {
		st.Notes = append(st.Notes, "prctl(PR_SET_NO_NEW_PRIVS): "+e.Error())
		return "failed"
	}
	filter := buildFilter(arch, denied, runtime.GOARCH == "amd64")
	prog := sockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	// TSYNC: 既存の全スレッドに同じフィルタを適用する。
	r, _, e := syscall.Syscall(sysSeccomp, seccompSetModeFilter, seccompFilterFlagTSync, uintptr(unsafe.Pointer(&prog)))
	runtime.KeepAlive(filter)
	runtime.KeepAlive(&prog)
	if e != 0 {
		st.Notes = append(st.Notes, "seccomp: "+e.Error())
		return "failed"
	}
	if r != 0 {
		st.Notes = append(st.Notes, "seccomp: could not synchronize thread "+strconv.Itoa(int(r)))
		return "failed"
	}
	return "applied"
}

// allThreadsHaveNice は /proc/self/task/*/stat を読み、全スレッドの nice 値を確認する。
func allThreadsHaveNice(want int) bool {
	tasks, err := filepath.Glob("/proc/self/task/*/stat")
	if err != nil || len(tasks) == 0 {
		return false
	}
	for _, p := range tasks {
		b, err := os.ReadFile(p)
		if err != nil {
			continue // 確認の間に終了したスレッド
		}
		// "pid (comm) state ..." の comm は空白や括弧を含み得るので、最後の ')' 以降を分割する。
		i := bytes.LastIndexByte(b, ')')
		if i < 0 {
			return false
		}
		f := bytes.Fields(b[i+1:])
		// ')' の後は 3 番目の項目（state）から始まる。nice は 19 番目。
		const niceField = 19 - 3
		if len(f) <= niceField {
			return false
		}
		n, err := strconv.Atoi(string(f[niceField]))
		if err != nil || n != want {
			return false
		}
	}
	return true
}
