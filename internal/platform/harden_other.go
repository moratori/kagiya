//go:build !linux

package platform

// Harden は Linux 以外では未実装。Windows 向け（優先度クラス、Job オブジェクト）は実機検証とあわせて実装する。
func Harden() Status {
	return Status{
		IOPriority: "unsupported",
		Seccomp:    "unsupported",
		Notes:      []string{"priority lowering and sandboxing are not implemented on this OS"},
	}
}
