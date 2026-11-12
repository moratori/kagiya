package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"kagiya/internal/output"
	"kagiya/internal/platform"
	"kagiya/internal/ruleset"
)

func runRules(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, "kagiya rules: specify a subcommand: export | validate\n")
		return exitUsage
	}
	switch args[0] {
	case "export":
		fs := newFlagSet("rules export", stderr)
		dir := fs.String("output-dir", "", "directory to write the built-in rules to (required)")
		if err := fs.Parse(args[1:]); err != nil || *dir == "" || fs.NArg() != 0 {
			fmt.Fprintln(stderr, "usage: kagiya rules export --output-dir DIR")
			return exitUsage
		}
		return rulesExport(*dir, stdout, stderr)
	case "validate":
		fs := newFlagSet("rules validate", stderr)
		dir := fs.String("rules", "", "rule directory to check (required)")
		if err := fs.Parse(args[1:]); err != nil || *dir == "" || fs.NArg() != 0 {
			fmt.Fprintln(stderr, "usage: kagiya rules validate --rules DIR")
			return exitUsage
		}
		rs, _, err := loadExternalRules(*dir, nil)
		if err != nil {
			fmt.Fprintln(stderr, "kagiya: rules are invalid:", err)
			return exitFatal
		}
		fmt.Fprintf(stdout, "OK: rules %s, %d algorithms, sha256 %s\n", rs.Version, len(rs.Algorithms), rs.SHA256)
		return exitOK
	}
	fmt.Fprintf(stderr, "kagiya rules: unknown subcommand %q\n", args[0])
	return exitUsage
}

func rulesExport(dir string, stdout, stderr io.Writer) int {
	abs, err := absClean(dir)
	if err != nil {
		fmt.Fprintln(stderr, "kagiya:", err)
		return exitUsage
	}
	if err := checkWritableLocation(abs, loadMounts()); err != nil {
		fmt.Fprintln(stderr, "kagiya:", err)
		return exitFatal
	}
	files, err := ruleset.BuiltinFiles()
	if err != nil {
		fmt.Fprintln(stderr, "kagiya:", err)
		return exitFatal
	}
	if err := output.EnsureDir(abs); err != nil {
		fmt.Fprintln(stderr, "kagiya:", err)
		return exitFatal
	}
	for _, f := range files {
		target := abs
		parts := strings.Split(f.Path, "/")
		for _, sub := range parts[:len(parts)-1] {
			target = filepath.Join(target, sub)
			if err := output.EnsureDir(target); err != nil {
				fmt.Fprintln(stderr, "kagiya:", err)
				return exitFatal
			}
		}
		w, err := output.Create(target, parts[len(parts)-1])
		if err != nil {
			fmt.Fprintln(stderr, "kagiya:", err)
			return exitFatal
		}
		if _, err := w.Write(f.Data); err != nil {
			w.Abort()
			fmt.Fprintln(stderr, "kagiya:", err)
			return exitFatal
		}
		if err := w.Commit(); err != nil {
			fmt.Fprintln(stderr, "kagiya:", err)
			return exitFatal
		}
	}
	fmt.Fprintf(stdout, "wrote %d rule files to %s\n", len(files), abs)
	return exitOK
}

// loadExternalRules は引数で明示されたルールディレクトリを、信頼できる状態か検査したうえで読み込む。
func loadExternalRules(dir string, mounts *mountState) (*ruleset.RuleSet, string, error) {
	abs, err := absClean(dir)
	if err != nil {
		return nil, "", err
	}
	if mounts == nil {
		mounts = loadMounts()
	}
	if err := mounts.requireLocal(abs, "rules directory"); err != nil {
		return nil, "", err
	}
	if err := platform.CheckTrustedDir(abs); err != nil {
		return nil, "", fmt.Errorf("rules directory is not trusted: %w", err)
	}
	rs, err := ruleset.Load(os.DirFS(abs))
	if err != nil {
		return nil, "", fmt.Errorf("rules directory %s: %w", abs, err)
	}
	return rs, abs, nil
}
