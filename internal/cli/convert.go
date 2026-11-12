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
	to := fs.String("to", "", "output format: csv (required)")
	outDir := fs.String("output-dir", ".", "directory for the converted file")
	noBOM := fs.Bool("no-bom", false, "do not write a UTF-8 byte order mark (CSV)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 || *to != "csv" {
		fmt.Fprintln(stderr, "usage: kagiya convert --to csv [--output-dir DIR] [--no-bom] RESULT.json")
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
	name := strings.TrimSuffix(filepath.Base(in), ".json") + ".csv"
	w, err := output.Create(dir, name)
	if err != nil {
		return fatal(err)
	}
	if err := convert.WriteCSV(inv, w, !*noBOM); err != nil {
		w.Abort()
		return fatal(err)
	}
	if err := w.Commit(); err != nil {
		return fatal(err)
	}
	fmt.Fprintf(stdout, "wrote %s (%d rows)\n", w.Path(), len(inv.Occurrences))
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
	return &inv, nil
}
