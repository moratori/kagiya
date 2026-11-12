package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"time"

	"kagiya/internal/collect/bins"
	"kagiya/internal/collect/fscrawl"
	"kagiya/internal/collect/pkgs"
	"kagiya/internal/inventory"
	"kagiya/internal/logx"
	"kagiya/internal/model"
	"kagiya/internal/output"
	"kagiya/internal/platform"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
	"kagiya/internal/throttle"
)

var labelPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

type scanOptions struct {
	outputDir, logDir, rulesDir string
	roots, excludes             []string
	rootsExplicit               bool
	labels                      map[string]string
	maxFileSizeMiB              int64
	cpuLimit                    int
	ioLimitMiB                  int64
	maxDuration                 time.Duration
	strict                      bool
}

func defaultRoots() []string {
	if runtime.GOOS == "linux" {
		return []string{"/etc", "/opt", "/usr/local", "/srv", "/var/www", "/root"}
	}
	return nil
}

func parseScanOptions(args []string, stderr io.Writer) (*scanOptions, error) {
	o := &scanOptions{labels: map[string]string{}}
	var roots, excludes, labels listFlag
	fs := newFlagSet("scan", stderr)
	fs.StringVar(&o.outputDir, "output-dir", ".", "directory for the result file")
	fs.StringVar(&o.logDir, "log-dir", "logs", "directory for the log file")
	fs.StringVar(&o.rulesDir, "rules", "", "external rule directory (the built-in rules are used when omitted)")
	fs.Var(&roots, "roots", "directories to search for certificates (comma-separated, repeatable)")
	fs.Var(&excludes, "exclude", "glob patterns to exclude (comma-separated, repeatable; ** crosses directories)")
	fs.Var(&labels, "label", "key=value tags recorded in the result (repeatable)")
	fs.Int64Var(&o.maxFileSizeMiB, "max-file-size", 64, "largest file to read, in MiB")
	fs.IntVar(&o.cpuLimit, "cpu-limit", 25, "CPU usage limit as a percentage of one core (100 = no limit)")
	fs.Int64Var(&o.ioLimitMiB, "io-limit", 20, "read rate limit in MiB per second (0 = no limit)")
	fs.DurationVar(&o.maxDuration, "max-duration", 0, "stop after this long and mark the result incomplete (0 = no limit)")
	fs.BoolVar(&o.strict, "strict", false, "exit with code 1 if anything was skipped because of an error")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if o.maxFileSizeMiB <= 0 || o.cpuLimit <= 0 || o.cpuLimit > 100 || o.ioLimitMiB < 0 || o.maxDuration < 0 {
		return nil, errors.New("invalid limit value")
	}
	var err error
	if o.outputDir, err = absClean(o.outputDir); err != nil {
		return nil, fmt.Errorf("--output-dir: %w", err)
	}
	if o.logDir, err = absClean(o.logDir); err != nil {
		return nil, fmt.Errorf("--log-dir: %w", err)
	}
	o.rootsExplicit = len(roots) > 0
	if len(roots) == 0 {
		roots = defaultRoots()
	}
	if len(roots) == 0 {
		return nil, errors.New("--roots is required on this OS")
	}
	for _, r := range roots {
		// 起点は明示的な絶対パスに限る（カレントディレクトリに依存させない）
		if !strings.HasPrefix(r, "/") {
			return nil, fmt.Errorf("--roots %q: must be an absolute path", r)
		}
		c, err := absClean(r)
		if err != nil {
			return nil, err
		}
		o.roots = append(o.roots, c)
	}
	if _, err := safefs.NewExcludes(excludes); err != nil {
		return nil, err
	}
	o.excludes = excludes
	for _, l := range labels {
		k, v, ok := strings.Cut(l, "=")
		if !ok || !labelPattern.MatchString(k) || len(v) > 256 || strings.ContainsAny(v, "\x00\n\r") {
			return nil, fmt.Errorf("--label %q: must be key=value", l)
		}
		o.labels[k] = v
	}
	return o, nil
}

func runScan(args []string, stderr io.Writer) int {
	opts, err := parseScanOptions(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		fmt.Fprintln(stderr, "kagiya scan:", err)
		return exitUsage
	}
	fatal := func(err error) int {
		fmt.Fprintln(stderr, "kagiya:", err)
		return exitFatal
	}

	// 何かを読む前に、優先度を下げ、通信とプロセス起動を封じる。
	hardening := platform.Harden()
	started := time.Now().UTC()

	mounts := loadMounts()
	if mounts.err != nil {
		return fatal(mounts.err)
	}
	if exe, err := os.Executable(); err == nil {
		if err := mounts.requireLocal(exe, "the kagiya executable"); err != nil {
			return fatal(fmt.Errorf("%w; copy it to a local disk and run it from there", err))
		}
	}
	if err := checkWritableLocation(opts.outputDir, mounts); err != nil {
		return fatal(err)
	}
	if err := mounts.requireLocal(opts.logDir, "log directory"); err != nil {
		return fatal(err)
	}

	// ルール（内包、または引数で明示されたディレクトリ）。問題があれば何も書き出さずに終わる。
	rulesMeta := model.Rules{Source: "builtin"}
	var rs *ruleset.RuleSet
	if opts.rulesDir != "" {
		if rs, _, err = loadExternalRules(opts.rulesDir, mounts); err != nil {
			return fatal(err)
		}
		rulesMeta.Source = "external"
	} else if rs, err = ruleset.Builtin(); err != nil {
		return fatal(err)
	}
	rulesMeta.Version, rulesMeta.SHA256 = rs.Version, rs.SHA256

	// 起点が明示されていなければ、ルールにある証明書ストアの場所のうち既定の起点に含まれないものも探す。
	if !opts.rootsExplicit {
		opts.roots = append(opts.roots, extraStoreRoots(opts.roots, rs.StorePaths(), mounts)...)
	}

	if err := output.EnsureDir(opts.outputDir); err != nil {
		return fatal(fmt.Errorf("output directory: %w", err))
	}
	if err := output.EnsureDir(opts.logDir); err != nil {
		return fatal(fmt.Errorf("log directory: %w", err))
	}

	scanID := newScanID()
	host := sanitizeHostname()
	stamp := started.Format("20060102T150405Z")
	logFile, err := output.Create(opts.logDir, fmt.Sprintf("kagiya-%s-%s-%s.log", host, stamp, scanID[:8]))
	if err != nil {
		return fatal(err)
	}
	log := logx.New(logFile, time.Now)
	log.Info("scan-start", "scan_id", scanID, "tool_version", Version, "rules_source", rulesMeta.Source,
		"rules_version", rs.Version, "rules_sha256", rs.SHA256, "roots", opts.roots, "excludes", opts.excludes,
		"output_dir", opts.outputDir, "elevated", platform.Elevated())
	log.Info("hardening", "priority_lowered", hardening.PriorityLowered, "io_priority", hardening.IOPriority,
		"core_dump_disabled", hardening.CoreDumpDisabled, "seccomp", hardening.Seccomp, "notes", hardening.Notes)
	var warnings []string
	if mounts.table == nil {
		w := "the mount table is not available on this OS; network filesystem checks are disabled"
		warnings = append(warnings, w)
		log.Warn("no-mount-table", "detail", w)
	}

	ctx, stop := signal.NotifyContext(context.Background(), platform.TerminationSignals()...)
	defer stop()
	if opts.maxDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.maxDuration)
		defer cancel()
	}

	builder := inventory.NewBuilder(rs, log)
	crawl := fscrawl.New(builder)
	limiter := throttle.New(throttle.Config{CPUPercent: opts.cpuLimit, BytesPerSecond: opts.ioLimitMiB << 20}, throttle.RealClock())

	// パッケージ管理データベース（導入済みパッケージの版）
	opener := &safefs.Opener{Limiter: limiter, OnSkip: builder.Skip}
	if mounts.table != nil {
		opener.Mounts = mounts.table
	}
	(&pkgs.Collector{Opener: opener, Builder: builder, Rules: rs}).Collect()

	// アプリケーションのバイナリと、リンクしている暗号ライブラリ
	(&bins.Collector{Opener: opener, Builder: builder, Rules: rs}).Collect()

	excludes, _ := safefs.NewExcludes(opts.excludes)
	walker := &safefs.Walker{
		Excludes:    excludes,
		SkipDirs:    []string{opts.outputDir, opts.logDir},
		MaxFileSize: opts.maxFileSizeMiB << 20,
		Limiter:     limiter,
		OnSkip:      builder.Skip,
	}
	if mounts.table != nil {
		walker.Mounts = mounts.table
	}

	incomplete := ""
	for _, root := range opts.roots {
		err := walker.Walk(ctx, root, crawl.Visit)
		switch {
		case err == nil:
		case errors.Is(err, context.DeadlineExceeded):
			incomplete = "max-duration"
		case errors.Is(err, context.Canceled):
			incomplete = "interrupted"
		case errors.Is(err, fs.ErrNotExist):
			builder.Skip(safefs.Skip{Path: root, Reason: "not-found"})
		default:
			builder.Skip(safefs.Skip{Path: root, Reason: "invalid-root"})
			log.Error("invalid-root", "path", root, "detail", err.Error())
		}
		if incomplete != "" {
			log.Error("scan-incomplete", "reason", incomplete)
			break
		}
	}

	inv := builder.Inventory()
	inv.Meta = model.Meta{
		ScanID: scanID, StartedAt: started.Format(time.RFC3339), FinishedAt: time.Now().UTC().Format(time.RFC3339),
		Completed: incomplete == "", Incomplete: incomplete,
		Tool: model.Tool{Version: Version}, Rules: rulesMeta,
		Host:       model.Host{Hostname: host, OS: runtime.GOOS, Arch: runtime.GOARCH},
		Labels:     opts.labels,
		Invocation: model.Invocation{Roots: opts.roots, Excludes: opts.excludes},
		Privilege:  model.Privilege{Elevated: platform.Elevated()},
		Hardening:  hardening, Warnings: warnings,
	}
	inv.Coverage.FilesExamined = walker.Stats.Files
	inv.Coverage.DirsExamined = walker.Stats.Dirs
	inv.Coverage.SymlinksIgnored = walker.Stats.Symlinks
	inv.Coverage.SpecialIgnored = walker.Stats.Special
	inv.Coverage.BytesRead = walker.Stats.BytesRead + opener.BytesRead

	resultName := fmt.Sprintf("kagiya-%s-%s-%s.json", host, stamp, scanID[:8])
	resultPath, werr := writeResult(opts.outputDir, resultName, inv)
	if werr != nil {
		log.Error("write-failed", "detail", werr.Error())
	}
	log.Info("scan-finished", "completed", inv.Meta.Completed, "assets", len(inv.Assets), "occurrences", len(inv.Occurrences),
		"files_examined", walker.Stats.Files, "skipped_by_reason", inv.Coverage.SkippedByReason, "result", resultPath)
	logErr := log.Err()
	if err := logFile.Commit(); err != nil && logErr == nil {
		logErr = err
	}

	switch {
	case werr != nil:
		return fatal(werr)
	case logErr != nil:
		return fatal(fmt.Errorf("writing the log failed: %w", logErr))
	case incomplete != "":
		fmt.Fprintf(stderr, "kagiya: scan stopped early (%s); partial result: %s\n", incomplete, resultPath)
		return exitFatal
	}
	fmt.Fprintf(stderr, "kagiya: %d assets, %d occurrences, %d skipped; result: %s\n",
		len(inv.Assets), len(inv.Occurrences), builder.SkipTotal(), resultPath)
	if opts.strict && builder.ProblemSkips() > 0 {
		return exitStrict
	}
	return exitOK
}

func writeResult(dir, name string, inv *model.Inventory) (string, error) {
	w, err := output.Create(dir, name)
	if err != nil {
		return "", err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(inv); err != nil {
		w.Abort()
		return "", err
	}
	if err := w.Commit(); err != nil {
		return "", err
	}
	return w.Path(), nil
}

func newScanID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// 乱数が得られない場合も識別子は必要。時刻から作る。
		s := sha256.Sum256([]byte(time.Now().String()))
		copy(b[:], s[:])
	}
	return hex.EncodeToString(b[:])
}

func sanitizeHostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown-host"
	}
	h = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		}
		return '_'
	}, h)
	if len(h) > 64 {
		h = h[:64]
	}
	return h
}

// extraStoreRoots は、ストアの場所のうち既存の起点の配下になく、ローカルに実在するディレクトリを返す。
func extraStoreRoots(roots, storePaths []string, mounts *mountState) []string {
	var extra []string
	for _, p := range storePaths {
		covered := false
		for _, r := range append(append([]string{}, roots...), extra...) {
			if p == r || strings.HasPrefix(p, r+"/") {
				covered = true
				break
			}
		}
		if covered || mounts.requireLocal(p, "store") != nil {
			continue
		}
		if fi, err := os.Lstat(p); err == nil && fi.IsDir() {
			extra = append(extra, p)
		}
	}
	return extra
}
