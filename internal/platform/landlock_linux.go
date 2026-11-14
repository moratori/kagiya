package platform

import (
	"encoding/binary"
	"syscall"
	"unsafe"
)

// Landlock（Linux 5.13 以降）: プロセスが自分自身に「これ以降、この場所以外は変更できない」という制限をかける仕組み。
// 一度かけると外せず、root でも効く。kagiya は、出力先とログ先を作った後に「変更できるのは、その 2 か所の下だけ」とかける
// （読み取りは制限しない）。コードに誤りが入っても、スキャン対象を書き換える操作はカーネルが拒否する。
//
// 定数と構造体は、カーネルのヘッダ（Debian 13 の linux-libc-dev 6.12.117-1 の linux/landlock.h）で確かめた。
// システムコールの番号（444〜446）は、amd64 と arm64 で同じ。
const (
	sysLandlockCreateRuleset = 444
	sysLandlockAddRule       = 445
	sysLandlockRestrictSelf  = 446

	landlockCreateRulesetVersion = 1 << 0
	landlockRulePathBeneath      = 1

	landlockWriteFile  = 1 << 1
	landlockRemoveDir  = 1 << 4
	landlockRemoveFile = 1 << 5
	landlockMakeChar   = 1 << 6
	landlockMakeDir    = 1 << 7
	landlockMakeReg    = 1 << 8
	landlockMakeSock   = 1 << 9
	landlockMakeFifo   = 1 << 10
	landlockMakeBlock  = 1 << 11
	landlockMakeSym    = 1 << 12
	landlockTruncate   = 1 << 14 // 第 3 版から

	oPath          = 0o10000000
	prSetNoNewPriv = 38
)

// landlockWrites は、制限の対象にする操作（ファイルシステムを変更するもの）。読み取りと実行は対象にしない。
func landlockWrites(abi int) uint64 {
	rights := uint64(landlockWriteFile | landlockRemoveDir | landlockRemoveFile | landlockMakeChar | landlockMakeDir |
		landlockMakeReg | landlockMakeSock | landlockMakeFifo | landlockMakeBlock | landlockMakeSym)
	if abi >= 3 {
		rights |= landlockTruncate
	}
	return rights
}

// RestrictWrites は、ファイルシステムを変更できる場所を dirs の下だけに限る。dirs は、すでにあるディレクトリ。
// 返すのは applied / unsupported（このカーネルでは使えない）/ failed と、補足。使えなくても、処理は続けられる。
func RestrictWrites(dirs []string) (status, note string) {
	abi, _, e := syscall.Syscall(sysLandlockCreateRuleset, 0, 0, landlockCreateRulesetVersion)
	if e != 0 {
		return "unsupported", "landlock: " + e.Error()
	}
	rights := landlockWrites(int(abi))
	// struct landlock_ruleset_attr の先頭の項目（handled_access_fs）だけを渡す
	attr := rights
	fd, _, e := syscall.Syscall(sysLandlockCreateRuleset, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if e != 0 {
		return "failed", "landlock_create_ruleset: " + e.Error()
	}
	defer syscall.Close(int(fd))
	for _, dir := range dirs {
		dfd, err := syscall.Open(dir, oPath|syscall.O_CLOEXEC, 0)
		if err != nil {
			return "failed", "landlock: cannot open a writable directory: " + err.Error()
		}
		// struct landlock_path_beneath_attr { __u64 allowed_access; __s32 parent_fd; }（詰めた並び。12 バイト）
		var rule [12]byte
		binary.NativeEndian.PutUint64(rule[0:], rights)
		binary.NativeEndian.PutUint32(rule[8:], uint32(dfd))
		_, _, e := syscall.Syscall6(sysLandlockAddRule, fd, landlockRulePathBeneath, uintptr(unsafe.Pointer(&rule[0])), 0, 0, 0)
		syscall.Close(dfd)
		if e != 0 {
			return "failed", "landlock_add_rule: " + e.Error()
		}
	}
	// 制限はスレッドごとの属性なので、すべてのスレッドにかける（no_new_privs が前提）
	if _, _, e := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, prSetNoNewPriv, 1, 0); e != 0 {
		return "failed", "prctl(PR_SET_NO_NEW_PRIVS): " + e.Error()
	}
	if _, _, e := syscall.AllThreadsSyscall(sysLandlockRestrictSelf, fd, 0, 0); e != 0 {
		return "failed", "landlock_restrict_self: " + e.Error()
	}
	return "applied", ""
}
