package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"kagiya/internal/output"
	"kagiya/internal/platform"
	"kagiya/internal/report"
	"kagiya/internal/ruleset"
)

// runReport は、結果 JSON から 1 ホスト分の HTML レポートを作る。
// 評価は、結果ファイルの中の判定を使わず、このコマンドを実行した時点のルール（内包、または --rules）でやり直す。
func runReport(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("report", stderr)
	outDir := fs.String("output-dir", ".", "directory for the report")
	policy := fs.String("policy", "default", "assessment policy")
	rulesDir := fs.String("rules", "", "external rule directory (the built-in rules are used when omitted)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: kagiya report [--output-dir DIR] [--policy NAME] [--rules DIR] RESULT.json")
		if fs.NArg() > 1 {
			fmt.Fprintln(stderr, "kagiya: report takes one result file (a combined report for many hosts is not available yet)")
		}
		return exitUsage
	}
	fatal := func(err error) int {
		fmt.Fprintln(stderr, "kagiya:", err)
		return exitFatal
	}
	platform.Harden()
	in, err := absClean(fs.Arg(0))
	if err != nil {
		return fatal(err)
	}
	dir, err := absClean(*outDir)
	if err != nil {
		return fatal(err)
	}
	mounts := loadMounts()
	if err := mounts.requireLocal(in, "input file"); err != nil {
		return fatal(err)
	}
	if err := checkWritableLocation(dir, mounts); err != nil {
		return fatal(err)
	}
	var rs *ruleset.RuleSet
	if *rulesDir != "" {
		if rs, _, err = loadExternalRules(*rulesDir, mounts); err != nil {
			return fatal(err)
		}
	} else if rs, err = ruleset.Builtin(); err != nil {
		return fatal(err)
	}
	if _, ok := rs.Policy(*policy); !ok {
		return fatal(fmt.Errorf("unknown assessment policy %q", *policy))
	}
	inv, err := readInventory(in)
	if err != nil {
		return fatal(err)
	}
	if err := output.EnsureDir(dir); err != nil {
		return fatal(fmt.Errorf("output directory: %w", err))
	}
	if err := output.Probe(dir); err != nil {
		return fatal(err)
	}
	name := strings.TrimSuffix(filepath.Base(in), ".json") + ".html"
	w, err := output.Create(dir, name)
	if err != nil {
		return fatal(err)
	}
	if err := report.Render(w, inv, rs, *policy); err != nil {
		w.Abort()
		return fatal(err)
	}
	if err := w.Commit(); err != nil {
		return fatal(err)
	}
	fmt.Fprintf(stdout, "wrote %s\n", w.Path())
	return exitOK
}
