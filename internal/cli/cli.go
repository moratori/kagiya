// Package cli はコマンドライン引数を解釈し、各サブコマンドを実行する。
// 挙動は引数だけで決まる（環境変数や設定ファイルを暗黙に読まない）。
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"kagiya/internal/platform"
	"kagiya/internal/ruleset"
)

// Version はリリースビルド時に -ldflags で埋め込む。
var Version = "0.0.0-dev"

// 終了コード
const (
	exitOK     = 0
	exitStrict = 1 // --strict 指定時にスキップ・エラーがあった
	exitUsage  = 2
	exitFatal  = 3 // 致命的エラー、または未完了
)

const usage = `kagiya - cryptographic inventory tool (read-only, no network)

Usage:
  kagiya scan [options]                 scan this host and write the inventory
  kagiya convert --to csv RESULT.json   convert a result file to CSV
  kagiya convert --to cbom RESULT.json  convert a result file to a CBOM (CycloneDX 1.6 JSON)
  kagiya report RESULT.json...          write an HTML report (one host, or several hosts combined)
  kagiya rules export --output-dir DIR  write the built-in rules to DIR
  kagiya rules validate --rules DIR     check a rule directory
  kagiya version                        show version information

Run "kagiya scan -h" for scan options.
`

// startedSetID は、setuid / setgid で起動されたかを返す（テストで差し替える）。
var startedSetID = platform.StartedSetID

// Run はコマンドを実行し、終了コードを返す。
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], stderr)
	case "rules":
		return runRules(args[1:], stdout, stderr)
	case "convert":
		return runConvert(args[1:], stdout, stderr)
	case "report":
		return runReport(args[1:], stdout, stderr)
	case "version":
		rs, err := ruleset.Builtin()
		if err != nil {
			fmt.Fprintln(stderr, "kagiya: built-in rules are invalid:", err)
			return exitFatal
		}
		fmt.Fprintf(stdout, "kagiya %s (rules %s, sha256 %s)\n", Version, rs.Version, rs.SHA256[:12])
		return exitOK
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	}
	fmt.Fprintf(stderr, "kagiya: unknown command %q\n\n%s", args[0], usage)
	return exitUsage
}

// listFlag はカンマ区切り・複数回指定を受け付けるフラグ。
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	for _, s := range strings.Split(v, ",") {
		if s == "" {
			return errors.New("empty value")
		}
		*l = append(*l, s)
	}
	return nil
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// absClean は引数のパスを正規化した絶対パスにする（シンボリックリンクは解決しない）。
func absClean(p string) (string, error) {
	if p == "" {
		return "", errors.New("empty path")
	}
	a, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.Clean(a), nil
}
