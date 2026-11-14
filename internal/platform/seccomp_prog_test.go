package platform

import "testing"

// テスト用の最小 cBPF 解釈器。seccomp_data の先頭 8 バイト（nr, arch）だけを扱う。
func runFilter(t *testing.T, prog []sockFilter, nr, arch uint32) uint32 {
	t.Helper()
	var acc uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.Code {
		case bpfLdAbsW:
			switch in.K {
			case 0:
				acc = nr
			case 4:
				acc = arch
			default:
				t.Fatalf("pc %d: unexpected load offset %d", pc, in.K)
			}
		case bpfJeqK:
			if acc == in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case bpfJgeK:
			if acc >= in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case bpfRetK:
			return in.K
		default:
			t.Fatalf("pc %d: unexpected opcode %#x", pc, in.Code)
		}
	}
	t.Fatal("fell off the end of the filter")
	return 0
}

const (
	testArchX8664 = 0xC000003E
	testArchI386  = 0x40000003
	testArchARM64 = 0xC00000B7
	retAllow      = 0x7fff0000
	retEPERM      = 0x00050001
)

func TestSeccompFilterAMD64(t *testing.T) {
	denied := []uint32{41, 42, 49, 50, 59, 322, 425}
	prog := buildFilter(testArchX8664, denied, true)

	for _, nr := range denied {
		if got := runFilter(t, prog, nr, testArchX8664); got != retEPERM {
			t.Errorf("syscall %d: got %#x, want EPERM", nr, got)
		}
	}
	for _, nr := range []uint32{0, 1, 2, 3, 9, 40, 43, 257, 424, 426} {
		if got := runFilter(t, prog, nr, testArchX8664); got != retAllow {
			t.Errorf("syscall %d: got %#x, want ALLOW", nr, got)
		}
	}
	// 32bit ABI（int 0x80 経由）はすべて拒否: 番号体系が違い、拒否リストを迂回できるため
	for _, nr := range []uint32{0, 3, 102 /* socketcall */, 359 /* socket */} {
		if got := runFilter(t, prog, nr, testArchI386); got != retEPERM {
			t.Errorf("i386 syscall %d: got %#x, want EPERM", nr, got)
		}
	}
	// x32 ABI（番号に 0x40000000 が立つ）もすべて拒否
	for _, nr := range []uint32{0x40000000, 0x40000000 + 41, 0x40000000 + 1} {
		if got := runFilter(t, prog, nr, testArchX8664); got != retEPERM {
			t.Errorf("x32 syscall %#x: got %#x, want EPERM", nr, got)
		}
	}
}

func TestSeccompFilterARM64(t *testing.T) {
	denied := []uint32{198, 203, 221, 281}
	prog := buildFilter(testArchARM64, denied, false)
	for _, nr := range denied {
		if got := runFilter(t, prog, nr, testArchARM64); got != retEPERM {
			t.Errorf("syscall %d: got %#x, want EPERM", nr, got)
		}
	}
	if got := runFilter(t, prog, 63, testArchARM64); got != retAllow {
		t.Errorf("read: got %#x, want ALLOW", got)
	}
	if got := runFilter(t, prog, 63, testArchX8664); got != retEPERM {
		t.Errorf("foreign arch: got %#x, want EPERM", got)
	}
}

// 実際に適用する拒否リストに、通信・プロセス起動・他プロセス操作・マウント・鍵保管庫の操作が含まれること。
// 番号は、カーネルのヘッダ（Debian 13 の linux-libc-dev 6.12.116-1、amd64 と arm64）から採取して確認した。
func TestDeniedSyscallListsCoverEssentials(t *testing.T) {
	want := map[string]map[string]uint32{
		"amd64": {"socket": 41, "connect": 42, "accept": 43, "sendto": 44, "sendmsg": 46, "bind": 49, "listen": 50,
			"socketpair": 53, "execve": 59, "ptrace": 101, "accept4": 288, "sendmmsg": 307,
			"process_vm_readv": 310, "process_vm_writev": 311, "execveat": 322,
			"io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
			// マウント操作（ネットワークファイルシステムのマウントを含む）とカーネルの鍵保管庫
			"mount": 165, "umount2": 166, "open_tree": 428, "move_mount": 429, "fsopen": 430, "fsconfig": 431, "fsmount": 432,
			"add_key": 248, "request_key": 249, "keyctl": 250},
		"arm64": {"socket": 198, "socketpair": 199, "bind": 200, "listen": 201, "accept": 202, "connect": 203,
			"sendto": 206, "sendmsg": 211, "execve": 221, "accept4": 242, "ptrace": 117, "sendmmsg": 269,
			"process_vm_readv": 270, "process_vm_writev": 271, "execveat": 281,
			"io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
			"mount": 40, "umount2": 39, "open_tree": 428, "move_mount": 429, "fsopen": 430, "fsconfig": 431, "fsmount": 432,
			"add_key": 217, "request_key": 218, "keyctl": 219},
	}
	for arch, calls := range want {
		list := deniedSyscalls(arch)
		have := map[uint32]bool{}
		for _, n := range list {
			have[n] = true
		}
		for name, nr := range calls {
			if !have[nr] {
				t.Errorf("%s: %s (%d) is not in the deny list", arch, name, nr)
			}
		}
	}
	// 独立したレビュー（2026-11-14）の指摘 A-8: このツールが決して使わない、ファイルシステムやシステムの状態を変える呼び出しも拒否する
	// （権限・所有者・時刻・拡張属性の変更、切り詰め、リンクやデバイスの作成、ディレクトリの削除、上書きする改名、時計・ホスト名・
	// カーネルモジュールなど）。出力に使う呼び出し（書き込み用に開く、mkdirat、linkat、unlinkat、renameat2、fchmod）は拒否しない。
	// 番号は、カーネルのヘッダ（Debian 13 の linux-libc-dev 6.12.117-1 と linux-libc-dev-amd64-cross 6.12.38-1cross1）で確かめた。
	never := map[string]map[string]uint32{
		"amd64": {"chmod": 90, "fchmodat": 268, "fchmodat2": 452, "chown": 92, "fchown": 93, "lchown": 94, "fchownat": 260, "setxattr": 188, "lsetxattr": 189, "fsetxattr": 190, "removexattr": 197, "lremovexattr": 198, "fremovexattr": 199, "mknod": 133, "mknodat": 259, "symlink": 88, "symlinkat": 266, "truncate": 76, "ftruncate": 77, "utime": 132, "utimes": 235, "futimesat": 261, "utimensat": 280, "rmdir": 84, "rename": 82, "renameat": 264, "chroot": 161, "pivot_root": 155, "swapon": 167, "swapoff": 168, "reboot": 169, "init_module": 175, "finit_module": 313, "delete_module": 176, "kexec_load": 246, "kexec_file_load": 320, "bpf": 321, "settimeofday": 164, "clock_settime": 227, "adjtimex": 159, "clock_adjtime": 305, "sethostname": 170, "setdomainname": 171, "fallocate": 285},
		"arm64": {"fchmodat": 53, "fchmodat2": 452, "fchown": 55, "fchownat": 54, "setxattr": 5, "lsetxattr": 6, "fsetxattr": 7, "removexattr": 14, "lremovexattr": 15, "fremovexattr": 16, "mknodat": 33, "symlinkat": 36, "truncate": 45, "ftruncate": 46, "utimensat": 88, "renameat": 38, "chroot": 51, "pivot_root": 41, "swapon": 224, "swapoff": 225, "reboot": 142, "init_module": 105, "finit_module": 273, "delete_module": 106, "kexec_load": 104, "kexec_file_load": 294, "bpf": 280, "settimeofday": 170, "clock_settime": 112, "adjtimex": 171, "clock_adjtime": 266, "sethostname": 161, "setdomainname": 162, "fallocate": 47},
	}
	needed := map[string][]uint32{"amd64": {257 /* openat */, 258 /* mkdirat */, 265 /* linkat */, 263 /* unlinkat */, 316 /* renameat2 */, 91 /* fchmod */},
		"arm64": {56 /* openat */, 34 /* mkdirat */, 37 /* linkat */, 35 /* unlinkat */, 276 /* renameat2 */, 52 /* fchmod */}}
	for arch, calls := range never {
		list := deniedSyscalls(arch)
		have := map[uint32]bool{}
		for _, n := range list {
			if have[n] {
				t.Errorf("%s: %d is listed twice", arch, n)
			}
			have[n] = true
		}
		for name, nr := range calls {
			if !have[nr] {
				t.Errorf("%s: %s (%d) is not in the deny list", arch, name, nr)
			}
		}
		for _, nr := range needed[arch] {
			if have[nr] {
				t.Errorf("%s: %d is needed to write the output and must not be denied", arch, nr)
			}
		}
		// 分岐の飛び先は 8 ビット
		if len(list) > 250 {
			t.Errorf("%s: the deny list is too long for the filter (%d)", arch, len(list))
		}
	}
	if deniedSyscalls("riscv64") != nil {
		t.Error("unknown architecture must return nil (no filter)")
	}
}
