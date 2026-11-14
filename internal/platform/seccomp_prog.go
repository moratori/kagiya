// Package platform は OS 依存の処理（優先度、サンドボックス、マウント表の取得など）をまとめる。
// syscall / unsafe を使ってよいのはこのパッケージだけ（設計書 4.2）。
package platform

// seccomp フィルタ（classic BPF）の生成。生成ロジックは OS に依存しないので、どの環境でもテストできる。

type sockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

const (
	bpfLdAbsW = 0x20 // BPF_LD | BPF_W | BPF_ABS
	bpfJeqK   = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfJgeK   = 0x35 // BPF_JMP | BPF_JGE | BPF_K
	bpfRetK   = 0x06 // BPF_RET | BPF_K

	seccompRetAllow = 0x7fff0000
	seccompRetEPERM = 0x00050000 | 1 // SECCOMP_RET_ERRNO | EPERM

	auditArchX8664   = 0xC000003E
	auditArchAArch64 = 0xC00000B7

	x32SyscallBit = 0x40000000
)

// buildFilter は「arch が一致しなければすべて拒否、denied の番号は拒否、それ以外は許可」のフィルタを作る。
// 拒否はプロセスを殺さず EPERM を返す。x32guard は amd64 の x32 ABI（番号に 0x40000000 が立つ）を拒否する。
func buildFilter(arch uint32, denied []uint32, x32guard bool) []sockFilter {
	prog := []sockFilter{
		{Code: bpfLdAbsW, K: 4},                // A = seccomp_data.arch
		{Code: bpfJeqK, K: arch, Jt: 1, Jf: 0}, // 一致なら次の RET を飛ばす
		{Code: bpfRetK, K: seccompRetEPERM},
		{Code: bpfLdAbsW, K: 0}, // A = seccomp_data.nr
	}
	n := len(denied)
	if x32guard {
		n++
	}
	denyIdx := len(prog) + n + 1 // 判定命令群の後ろに ALLOW、その次が DENY
	jump := func() uint8 { return uint8(denyIdx - len(prog) - 1) }
	if x32guard {
		prog = append(prog, sockFilter{Code: bpfJgeK, K: x32SyscallBit, Jt: jump()})
	}
	for _, nr := range denied {
		prog = append(prog, sockFilter{Code: bpfJeqK, K: nr, Jt: jump()})
	}
	prog = append(prog,
		sockFilter{Code: bpfRetK, K: seccompRetAllow},
		sockFilter{Code: bpfRetK, K: seccompRetEPERM},
	)
	return prog
}

// deniedSyscalls は拒否するシステムコール番号（通信、プロセス起動、他プロセス操作、io_uring、マウント操作、カーネルの鍵保管庫、
// このツールが使わない変更系の呼び出し）。
// 番号は、カーネルのヘッダ（Debian 13 の linux-libc-dev 6.12.116-1 / 6.12.117-1。amd64 と arm64）で確認した。
// 未対応のアーキテクチャでは nil（フィルタを適用しない）。
func deniedSyscalls(goarch string) []uint32 {
	switch goarch {
	case "amd64":
		return []uint32{
			41,  // socket
			42,  // connect
			43,  // accept
			44,  // sendto
			45,  // recvfrom
			46,  // sendmsg
			47,  // recvmsg
			48,  // shutdown
			49,  // bind
			50,  // listen
			51,  // getsockname
			52,  // getpeername
			53,  // socketpair
			54,  // setsockopt
			55,  // getsockopt
			59,  // execve
			101, // ptrace
			288, // accept4
			299, // recvmmsg
			307, // sendmmsg
			310, // process_vm_readv
			311, // process_vm_writev
			322, // execveat
			425, // io_uring_setup
			426, // io_uring_enter
			427, // io_uring_register
			// マウント操作（ネットワークファイルシステムのマウントを含む）
			165, // mount
			166, // umount2
			428, // open_tree
			429, // move_mount
			430, // fsopen
			431, // fsconfig
			432, // fsmount
			// カーネルの鍵保管庫
			248, // add_key
			249, // request_key
			250, // keyctl
			// このツールが決して使わない、ファイルシステムやシステムの状態を変える呼び出し（出力に使うものは含めない:
			// 書き込み用に開く、mkdirat、linkat、unlinkat、renameat2、fchmod）
			90,  // chmod
			268, // fchmodat
			452, // fchmodat2
			92,  // chown
			93,  // fchown
			94,  // lchown
			260, // fchownat
			188, // setxattr
			189, // lsetxattr
			190, // fsetxattr
			197, // removexattr
			198, // lremovexattr
			199, // fremovexattr
			133, // mknod
			259, // mknodat
			88,  // symlink
			266, // symlinkat
			76,  // truncate
			77,  // ftruncate
			132, // utime
			235, // utimes
			261, // futimesat
			280, // utimensat
			84,  // rmdir
			82,  // rename
			264, // renameat
			161, // chroot
			155, // pivot_root
			167, // swapon
			168, // swapoff
			169, // reboot
			175, // init_module
			313, // finit_module
			176, // delete_module
			246, // kexec_load
			320, // kexec_file_load
			321, // bpf
			164, // settimeofday
			227, // clock_settime
			159, // adjtimex
			305, // clock_adjtime
			170, // sethostname
			171, // setdomainname
			285, // fallocate
		}
	case "arm64":
		return []uint32{
			198, // socket
			199, // socketpair
			200, // bind
			201, // listen
			202, // accept
			203, // connect
			204, // getsockname
			205, // getpeername
			206, // sendto
			207, // recvfrom
			208, // setsockopt
			209, // getsockopt
			210, // shutdown
			211, // sendmsg
			212, // recvmsg
			221, // execve
			117, // ptrace
			242, // accept4
			243, // recvmmsg
			269, // sendmmsg
			270, // process_vm_readv
			271, // process_vm_writev
			281, // execveat
			425, // io_uring_setup
			426, // io_uring_enter
			427, // io_uring_register
			40,  // mount
			39,  // umount2
			428, // open_tree
			429, // move_mount
			430, // fsopen
			431, // fsconfig
			432, // fsmount
			217, // add_key
			218, // request_key
			219, // keyctl
			// このツールが決して使わない、ファイルシステムやシステムの状態を変える呼び出し（出力に使うものは含めない:
			// 書き込み用に開く、mkdirat、linkat、unlinkat、renameat2、fchmod）
			53,  // fchmodat
			452, // fchmodat2
			55,  // fchown
			54,  // fchownat
			5,   // setxattr
			6,   // lsetxattr
			7,   // fsetxattr
			14,  // removexattr
			15,  // lremovexattr
			16,  // fremovexattr
			33,  // mknodat
			36,  // symlinkat
			45,  // truncate
			46,  // ftruncate
			88,  // utimensat
			38,  // renameat
			51,  // chroot
			41,  // pivot_root
			224, // swapon
			225, // swapoff
			142, // reboot
			105, // init_module
			273, // finit_module
			106, // delete_module
			104, // kexec_load
			294, // kexec_file_load
			280, // bpf
			170, // settimeofday
			112, // clock_settime
			171, // adjtimex
			266, // clock_adjtime
			161, // sethostname
			162, // setdomainname
			47,  // fallocate
		}
	}
	return nil
}

func auditArch(goarch string) (uint32, bool) {
	switch goarch {
	case "amd64":
		return auditArchX8664, true
	case "arm64":
		return auditArchAArch64, true
	}
	return 0, false
}
