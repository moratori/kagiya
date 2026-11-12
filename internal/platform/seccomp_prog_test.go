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

// 実際に適用する拒否リストに、通信・プロセス起動・他プロセス操作の主要なものが含まれること。
func TestDeniedSyscallListsCoverEssentials(t *testing.T) {
	want := map[string]map[string]uint32{
		"amd64": {"socket": 41, "connect": 42, "accept": 43, "sendto": 44, "sendmsg": 46, "bind": 49, "listen": 50,
			"socketpair": 53, "execve": 59, "ptrace": 101, "accept4": 288, "sendmmsg": 307,
			"process_vm_readv": 310, "process_vm_writev": 311, "execveat": 322,
			"io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427},
		"arm64": {"socket": 198, "socketpair": 199, "bind": 200, "listen": 201, "accept": 202, "connect": 203,
			"sendto": 206, "sendmsg": 211, "execve": 221, "accept4": 242, "ptrace": 117, "sendmmsg": 269,
			"process_vm_readv": 270, "process_vm_writev": 271, "execveat": 281,
			"io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427},
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
	if deniedSyscalls("riscv64") != nil {
		t.Error("unknown architecture must return nil (no filter)")
	}
}
