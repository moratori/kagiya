package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"kagiya/internal/convert"
	"kagiya/internal/model"
	"kagiya/internal/output"
	"kagiya/internal/platform"
)

const maxResultSize = 1 << 30 // 読み込む結果 JSON の上限

func runConvert(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("convert", stderr)
	to := fs.String("to", "", "output format: csv or cbom (required)")
	outDir := fs.String("output-dir", ".", "directory for the converted file")
	noBOM := fs.Bool("no-bom", false, "do not write a UTF-8 byte order mark (CSV)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 || (*to != "csv" && *to != "cbom") {
		fmt.Fprintln(stderr, "usage: kagiya convert --to csv|cbom [--output-dir DIR] [--no-bom] RESULT.json")
		return exitUsage
	}
	fatal := func(err error) int {
		fmt.Fprintln(stderr, "kagiya:", err)
		return exitFatal
	}
	platform.Harden() // 優先度を下げ、通信とプロセス起動を封じる（スキャン以外のサブコマンドでも同じ）
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
	// csv: 出現ごとの表。cbom: CycloneDX 1.6 の JSON（拡張子は、CycloneDX の慣例の .cdx.json）
	ext := ".csv"
	if *to == "cbom" {
		ext = ".cdx.json"
	}
	w, err := output.Create(dir, strings.TrimSuffix(filepath.Base(in), ".json")+ext)
	if err != nil {
		return fatal(err)
	}
	if *to == "cbom" {
		err = convert.WriteCBOM(inv, w)
	} else {
		err = convert.WriteCSV(inv, w, !*noBOM)
	}
	if err != nil {
		w.Abort()
		return fatal(err)
	}
	if err := w.Commit(); err != nil {
		return fatal(err)
	}
	if *to == "cbom" {
		fmt.Fprintf(stdout, "wrote %s\n", w.Path())
	} else {
		fmt.Fprintf(stdout, "wrote %s (%d rows)\n", w.Path(), len(inv.Occurrences))
	}
	return exitOK
}

// readInventory は結果 JSON を読み、このツールの形式であることを確かめる。
func readInventory(path string) (*model.Inventory, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Size() > maxResultSize {
		return nil, fmt.Errorf("%s is too large", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var inv model.Inventory
	if err := json.NewDecoder(io.LimitReader(f, maxResultSize)).Decode(&inv); err != nil {
		return nil, fmt.Errorf("%s is not a kagiya result file", path)
	}
	if inv.Schema != model.Schema {
		return nil, errors.New(path + ": unsupported schema (expected " + model.Schema + ")")
	}
	if err := checkInventory(&inv); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &inv, nil
}

// 結果ファイルの、項目ごとの件数の上限。結果ファイルは、侵害されたホストが作った「形式は正しいが中身に悪意のあるもの」でありうる。
// 小さな要素を大量に並べたファイルで、メモリと処理時間を使い切らされないようにする（スキャンの側の上限より、少し広く取る）。
const (
	maxResultAssets      = 1_000_000
	maxResultOccurrences = 4_000_000
	maxResultServices    = 100_000
	maxResultSettings    = 1_000_000
	maxResultEffective   = 500_000
	maxResultValues      = 50_000 // 1 つの設定・実効値が持つ値の数
	maxResultOther       = 200_000
)

// checkInventory は、読み込んだ結果の件数と数値を確かめる。
func checkInventory(inv *model.Inventory) error {
	for _, c := range []struct {
		what   string
		n, max int
	}{
		{"assets", len(inv.Assets), maxResultAssets}, {"occurrences", len(inv.Occurrences), maxResultOccurrences},
		{"services", len(inv.Services), maxResultServices}, {"settings", len(inv.Settings), maxResultSettings},
		{"effective values", len(inv.EffectiveValues), maxResultEffective}, {"packages", len(inv.Packages), maxResultOther},
		{"components", len(inv.Components), maxResultOther}, {"OS settings", len(inv.OSSettings), maxResultOther},
		{"skipped entries", len(inv.Skipped), maxResultOther}, {"skip reasons", len(inv.Coverage.SkippedByReason), 1000},
	} {
		if c.n > c.max {
			return fmt.Errorf("too many %s (%d; the limit is %d)", c.what, c.n, c.max)
		}
	}
	for _, e := range inv.EffectiveValues {
		if len(e.Values) > maxResultValues || len(e.Steps) > 1000 || len(e.Notes) > 1000 {
			return fmt.Errorf("an effective value has too many entries (the limit is %d values)", maxResultValues)
		}
	}
	for _, s := range inv.Settings {
		if len(s.Values) > maxResultValues {
			return fmt.Errorf("a setting has too many values (the limit is %d)", maxResultValues)
		}
	}
	// 件数は、負にならない（複数のホストを合計するときに、ほかのホストの分を打ち消せてしまう）
	cov := inv.Coverage
	if cov.FilesExamined < 0 || cov.DirsExamined < 0 || cov.SymlinksIgnored < 0 || cov.SpecialIgnored < 0 || cov.BytesRead < 0 || cov.AtimeNotPreserved < 0 {
		return errors.New("the coverage has a negative count")
	}
	for _, n := range cov.SkippedByReason {
		if n < 0 {
			return errors.New("the coverage has a negative count")
		}
	}
	return nil
}
