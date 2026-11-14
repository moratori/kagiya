// このファイルは、ルールの出典に書く「どう調べたか」（docs/confidence.md の 5 章）。

package ruleset

// 開発者が、ルールの項目の事実を調べた方法。
const (
	MethodEnumeratedByHandshake         = "enumerated-by-handshake"
	MethodReportedBySoftware            = "reported-by-software"
	MethodReadFromDistributedFiles      = "read-from-distributed-files"
	MethodReadFromUpstreamSourceCode    = "read-from-upstream-source-code"
	MethodReadFromUpstreamDocumentation = "read-from-upstream-documentation"
)

// Evidence は、開発者が、ルールの項目をどう調べたか。
type Evidence struct {
	Method              string `yaml:"method"`
	VerifiedByHandshake *bool  `yaml:"verified-by-handshake"`
}

// Verified は、開発者が、その版そのものの数え上げで裏付けたかを返す。
func (e Evidence) Verified() bool { return false }

// EvidenceFor は、項目 1 つについての記載を返す。
func (s Source) EvidenceFor(item string) Evidence { return Evidence{} }

// SourceAt は、出典と、それがどのルールのものか。
type SourceAt struct {
	Where  string
	Source Source
}

// AllSources は、読み込んだルールの出典を、すべて返す。
func (rs *RuleSet) AllSources() []SourceAt { return nil }
