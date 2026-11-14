package cli

import (
	"os"
	"testing"

	"kagiya/internal/platform"
)

// 単体テストは、1 つのプロセスの中でスキャンを何度も実行する。プロセス全体にかかり、外せない制限（seccomp、Landlock）は、テストの中ではかけない。
// Landlock（変更できる場所を出力先に限る仕組み）は、一度かけると
// そのプロセスでは外せないので、最初のスキャンの後、ほかのテストが一時ディレクトリを作れなくなる。テストの中では、かけない。
// Landlock そのものは、internal/platform の子プロセスでのテストと、ci/verify-linux.sh（実物の実行ファイル）で確かめる。
func TestMain(m *testing.M) {
	restrictWrites = func([]string) (string, string) { return "unsupported", "not applied in unit tests" }
	// seccomp も同じ（権限の変更などを拒否するので、テストの準備で使う chmod まで失敗する）
	harden = func() platform.Status {
		return platform.Status{IOPriority: "unsupported", Seccomp: "unsupported", Notes: []string{"not applied in unit tests"}}
	}
	os.Exit(m.Run())
}
