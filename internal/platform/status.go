package platform

// Status は起動時に適用した安全策・負荷対策の結果。結果 JSON の meta.hardening とログに記録する。
type Status struct {
	PriorityLowered  bool     `json:"priority_lowered"`
	IOPriority       string   `json:"io_priority"` // applied | failed | unsupported
	CoreDumpDisabled bool     `json:"core_dump_disabled"`
	Seccomp          string   `json:"seccomp"` // applied | failed | unsupported
	Notes            []string `json:"notes,omitempty"`
}
