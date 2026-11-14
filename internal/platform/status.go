package platform

// Status は起動時に適用した安全策・負荷対策の結果。結果 JSON の meta.hardening とログに記録する。
type Status struct {
	PriorityLowered  bool   `json:"priority_lowered"`
	IOPriority       string `json:"io_priority"` // applied | failed | unsupported
	CoreDumpDisabled bool   `json:"core_dump_disabled"`
	Seccomp          string `json:"seccomp"` // applied | failed | unsupported
	// 書き込める場所を出力先とログ先だけに限る仕組み（Landlock）: applied | failed | unsupported
	Landlock       string   `json:"landlock"`
	MemoryLimitMiB int64    `json:"memory_limit_mib"` // メモリの使用量の上限（Go のソフトリミット）
	MaxProcs       int      `json:"max_procs"`        // 同時に使うプロセッサの数の上限
	Notes          []string `json:"notes,omitempty"`
}
