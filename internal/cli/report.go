package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"kagiya/internal/model"
	"kagiya/internal/output"
	"kagiya/internal/report"
	"kagiya/internal/ruleset"
)

// 1 つのレポートにまとめる結果ファイルの数の上限。ホストごとの詳細をすべて 1 つのファイルに入れるため、数が多いと
// ファイルが大きくなりすぎる。これを超える規模は、集約（merge）で扱う（未実装）。
const maxReportInputs = 200

// runReport は、結果 JSON から HTML レポートを作る。
// 入力が 1 つなら 1 ホスト分、複数なら「全体の集計」と「ホストごとの詳細」をまとめた 1 つのレポートになる。
// 評価は、結果ファイルの中の判定を使わず、このコマンドを実行した時点のルール（内包、または --rules）でやり直す。
func runReport(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("report", stderr)
	outDir := fs.String("output-dir", ".", "directory for the report")
	policy := fs.String("policy", "default", "assessment policy")
	rulesDir := fs.String("rules", "", "external rule directory (the built-in rules are used when omitted)")
	if err := fs.Parse(args); err != nil || fs.NArg() < 1 {
		fmt.Fprintln(stderr, "usage: kagiya report [--output-dir DIR] [--policy NAME] [--rules DIR] RESULT.json...")
		return exitUsage
	}
	if fs.NArg() > maxReportInputs {
		fmt.Fprintf(stderr, "kagiya: too many result files for one report (at most %d)\n", maxReportInputs)
		return exitUsage
	}
	fatal := func(err error) int {
		fmt.Fprintln(stderr, "kagiya:", err)
		return exitFatal
	}
	harden()
	var inputs []string
	for _, a := range fs.Args() {
		in, err := absClean(a)
		if err != nil {
			return fatal(err)
		}
		inputs = append(inputs, in)
	}
	dir, err := absClean(*outDir)
	if err != nil {
		return fatal(err)
	}
	mounts := loadMounts()
	for _, in := range inputs {
		if err := mounts.requireLocal(in, "input file"); err != nil {
			return fatal(err)
		}
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
	// すべての入力を読めてから書き始める（1 つでも読めなければ、何も書かない）
	var invs []*model.Inventory
	for _, in := range inputs {
		inv, err := readInventory(in)
		if err != nil {
			return fatal(err)
		}
		invs = append(invs, inv)
	}
	if err := output.EnsureDir(dir); err != nil {
		return fatal(fmt.Errorf("output directory: %w", err))
	}
	if err := output.Probe(dir); err != nil {
		return fatal(err)
	}
	name := strings.TrimSuffix(filepath.Base(inputs[0]), ".json") + ".html"
	if len(invs) > 1 {
		name = fmt.Sprintf("kagiya-report-%dhosts.html", len(invs))
	}
	w, err := output.Create(dir, name)
	if err != nil {
		return fatal(err)
	}
	if err := report.RenderAll(w, invs, rs, *policy); err != nil {
		w.Abort()
		return fatal(err)
	}
	if err := w.Commit(); err != nil {
		return fatal(err)
	}
	fmt.Fprintf(stdout, "wrote %s\n", w.Path())
	return exitOK
}
