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
	"kagiya/internal/collect/jars"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"kagiya/internal/assess"
	"kagiya/internal/collect/apps"
	"kagiya/internal/collect/bins"
	"kagiya/internal/collect/fscrawl"
	"kagiya/internal/collect/osconf"
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

// harden は、優先度を下げ、通信・プロセス起動・使わない変更系の呼び出しを封じる（seccomp など）。一度かけると、そのプロセスでは
// 外せない。単体テストでは、テスト自身の準備（権限の変更など）まで拒否されてしまうので、テストでだけ差し替える。
var harden = platform.Harden

// restrictWrites は、変更できる場所を出力先とログ先に限る（Landlock）。一度かけると、そのプロセスでは外せない。
// 単体テストは、1 つのプロセスの中でスキャンを何度も実行するので、テストでだけ差し替える（実物での確認は、ci/verify-linux.sh と、
// internal/platform の子プロセスでのテストで行う）。
var restrictWrites = platform.RestrictWrites

// scanHook は、スキャンの各フェーズの始めに呼ばれる（テストで、途中の異常を起こすため。通常は nil）。
var scanHook func(phase string)

// メモリの使用量の上限（設計書 6 章）。
const memoryLimitMiB = 512

const (
	// 同時に使うプロセッサの数。処理は 1 つのゴルーチンで進むので、絞っても速さはほぼ変わらない。絞らないと、メモリの回収が
	// 空いているコアをすべて使い、「1 コアの 25%」のような上限が守られない
	maxProcs = 2
	// --max-file-size に指定できる上限（MiB）。読むファイルは、この大きさまでメモリに載る
	maxFileSizeLimitMiB = 1024
	// ログ全体の大きさの上限
	maxLogBytes = 64 << 20
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
	fs.StringVar(&o.logDir, "log-dir", "", "directory for the log file (default: logs under the output directory)")
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
	if o.maxFileSizeMiB <= 0 || o.maxFileSizeMiB > maxFileSizeLimitMiB || o.cpuLimit <= 0 || o.cpuLimit > 100 || o.ioLimitMiB < 0 || o.maxDuration < 0 {
		return nil, errors.New("invalid limit value")
	}
	var err error
	if o.outputDir, err = absClean(o.outputDir); err != nil {
		return nil, fmt.Errorf("--output-dir: %w", err)
	}
	if o.logDir == "" {
		// 既定は、出力先の下（kagiya が書く場所を、指定した 1 か所にまとめる）
		o.logDir = filepath.Join(o.outputDir, "logs")
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
	// 出力先・ログ先が、探索の起点と同じか、起点の上位にあると、その起点が丸ごと探索から外れる（出力先は探索しないため）。
	// 何も読まずに断る
	for _, d := range []struct{ what, dir string }{{"output directory", o.outputDir}, {"log directory", o.logDir}} {
		for _, root := range o.roots {
			if d.dir == "/" || root == d.dir || strings.HasPrefix(root, d.dir+"/") {
				return nil, fmt.Errorf("the %s %s is, or contains, the scan root %s, which would then not be scanned; "+
					"choose another place with --output-dir (and --log-dir)", d.what, d.dir, root)
			}
		}
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
	hardening := harden()
	hardening.MemoryLimitMiB = platform.LimitMemory(memoryLimitMiB)
	runtime.GOMAXPROCS(maxProcs)
	hardening.MaxProcs = maxProcs
	// 異常終了したときの出力の詳しさを固定する（環境変数 GOTRACEBACK の指定に左右されないように。
	// crash を指定されると、コアダンプを作ろうとする）
	debug.SetTraceback("single")
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
		probe := &safefs.Opener{}
		if mounts.table != nil {
			probe.Mounts = mounts.table
		}
		opts.roots = append(opts.roots, extraStoreRoots(opts.roots, rs.StorePaths(), probe)...)
	}

	if err := output.EnsureDir(opts.outputDir); err != nil {
		return fatal(fmt.Errorf("output directory: %w", err))
	}
	if err := output.EnsureDir(opts.logDir); err != nil {
		return fatal(fmt.Errorf("log directory: %w", err))
	}
	// ここから先は、出力先とログ先の下しか変更できないようにする（使えるカーネルでだけ。使えなくても続ける）。
	// この後の「書けるかの確認」は、制限をかけた状態で行う
	landlockNote := ""
	hardening.Landlock, landlockNote = restrictWrites([]string{opts.outputDir, opts.logDir})
	if landlockNote != "" {
		hardening.Notes = append(hardening.Notes, landlockNote)
	}
	// スキャンを終えてから結果を書けないと分かるのを避けるため、先に確かめる。
	for _, d := range []string{opts.outputDir, opts.logDir} {
		if err := output.Probe(d); err != nil {
			return fatal(err)
		}
	}

	scanID := newScanID()
	host := sanitizeHostname()
	stamp := started.Format("20060102T150405Z")
	// ログは、最初から最終名で作る（異常終了しても、書きかけの名前で残らないように）
	logFile, err := output.CreateDirect(opts.logDir, fmt.Sprintf("kagiya-%s-%s-%s.log", host, stamp, scanID[:8]))
	if err != nil {
		return fatal(err)
	}
	log := logx.New(logFile, time.Now)
	log.MaxBytes = maxLogBytes
	log.Info("scan-start", "scan_id", scanID, "tool_version", Version, "rules_source", rulesMeta.Source,
		"rules_version", rs.Version, "rules_sha256", rs.SHA256, "roots", opts.roots, "excludes", opts.excludes,
		"output_dir", opts.outputDir, "elevated", platform.Elevated())
	log.Info("hardening", "priority_lowered", hardening.PriorityLowered, "io_priority", hardening.IOPriority,
		"core_dump_disabled", hardening.CoreDumpDisabled, "seccomp", hardening.Seccomp, "landlock", hardening.Landlock, "memory_limit_mib", hardening.MemoryLimitMiB, "notes", hardening.Notes)
	var warnings []string
	// Go の実行環境そのものが読む環境変数。設定されていると挙動が変わりうるので、名前だけを警告に残す（値は残さない）。
	// メモリの上限・並列数・異常終了時の出力は、上でコードから設定しているので、環境変数の指定より優先される
	var runtimeEnv []string
	for _, name := range []string{"GODEBUG", "GOTRACEBACK", "GOGC", "GOMEMLIMIT", "GOMAXPROCS"} {
		if v, ok := os.LookupEnv(name); ok && v != "" {
			runtimeEnv = append(runtimeEnv, name)
		}
	}
	if len(runtimeEnv) > 0 {
		w := "environment variables read by the Go runtime are set (" + strings.Join(runtimeEnv, ", ") + "); they can change how the tool behaves"
		warnings = append(warnings, w)
		log.Warn("runtime-environment", "names", runtimeEnv)
	}
	if mounts.table == nil {
		w := "the mount table is not available on this OS; network filesystem checks are disabled"
		warnings = append(warnings, w)
		log.Warn("no-mount-table", "detail", w)
	}

	// 中断（シグナル）と時間制限。1 回目のシグナルで「安全に停止」を始め、2 回目か、猶予の経過で、強制的に終わる
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if opts.maxDuration > 0 {
		var cancelTimeout context.CancelFunc
		ctx, cancelTimeout = context.WithTimeout(ctx, opts.maxDuration)
		defer cancelTimeout()
	}
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, platform.TerminationSignals()...)
	defer signal.Stop(signals)
	var interrupted atomic.Bool
	finished := make(chan struct{})
	defer close(finished)
	go watchStop(signals, ctx.Done(), func() { interrupted.Store(true); cancel() }, finished, stopGrace, func(code int) {
		fmt.Fprintln(stderr, "kagiya: forced to exit before the result was written")
		os.Exit(code)
	})
	stopped := func() bool { return ctx.Err() != nil }
	// stopReason は、止まり始めていれば、その理由を返す
	stopReason := func() string {
		switch {
		case ctx.Err() == nil:
			return ""
		case errors.Is(ctx.Err(), context.DeadlineExceeded) && !interrupted.Load():
			return "max-duration"
		}
		return "interrupted"
	}

	builder := inventory.NewBuilder(rs, log)
	crawl := fscrawl.New(builder)
	limiter := throttle.New(throttle.Config{CPUPercent: opts.cpuLimit, BytesPerSecond: opts.ioLimitMiB << 20}, throttle.RealClock())
	// 止める合図は、処理の区切り（ファイル、JAR、アプリ、コレクタ）と、流量制限の休止の間に確かめる
	builder.SetStop(stopped)
	limiter.Stop = stopped
	// 流量制限の休止は、探索の後のフェーズでも、処理の区切りごとに入れる
	builder.SetYield(limiter.Yield)

	// パッケージ管理データベース（導入済みパッケージの版）
	opener := &safefs.Opener{Limiter: limiter, OnSkip: builder.Skip}
	if mounts.table != nil {
		opener.Mounts = mounts.table
	}
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

	// 処理の本体。途中で panic が起きても（コレクタごと・ファイルごとの回復をすり抜けたものでも）、そこまでの結果を
	// 「未完了」として書き出せるように、ここで受け止める。panic の値は入力の断片を含みうるので、どこにも出さない
	incomplete := ""
	func() {
		current := ""
		phase := func(name string) {
			current = name
			log.Info("phase", "name", name) // どこまで進んだかを、ログで追えるようにする
			if scanHook != nil {
				scanHook(name)
			}
		}
		defer func() {
			if r := recover(); r != nil {
				incomplete = "internal-error"
				log.Error("internal-error", "phase", current)
			}
		}()
		phase("collectors")
		// OS 全体の暗号設定（暗号ポリシー、OpenSSL のシステム既定の設定、FIPS モード）
		opener.AllowPseudo = []string{"/proc/sys/crypto"}
		builder.Guard("", "collecting the OS settings", (&osconf.Collector{Opener: opener, Builder: builder, Rules: rs}).Collect)

		builder.Guard("", "collecting the package records", (&pkgs.Collector{Opener: opener, Builder: builder, Rules: rs}).Collect)

		// アプリケーションのバイナリと、リンクしている暗号ライブラリ
		builder.Guard("", "collecting the libraries of applications", (&bins.Collector{Opener: opener, Builder: builder, Rules: rs}).Collect)

		// アプリケーションの設定値と、サービスの有効化状態
		(&apps.Collector{Opener: opener, Builder: builder, Rules: rs}).Collect()

		phase("walk")
		incomplete = stopReason()
		for _, root := range opts.roots {
			if incomplete != "" {
				log.Error("scan-incomplete", "reason", incomplete)
				break
			}
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

		// 探索で見つかった JAR の中の、同梱されている暗号ライブラリ（途中で打ち切られた場合は読まない）
		if incomplete == "" {
			phase("archives")
			archives, more := crawl.Archives()
			(&jars.Collector{Opener: opener, Builder: builder, Rules: rs}).Collect(archives)
			// Java のアプリ（Spring Boot）: 見つかった JAR と、起動の定義から参照されている JAR の中の設定
			(&apps.Collector{Opener: opener, Builder: builder, Rules: rs}).CollectJavaApps(archives)
			if more > 0 {
				builder.Skip(safefs.Skip{Path: "", Reason: "limit", Detail: strconv.Itoa(more) + " more archive(s) were found than are kept; they are not opened"})
			}
			if incomplete = stopReason(); incomplete != "" {
				log.Error("scan-incomplete", "reason", incomplete)
			}
		}
	}()
	if incomplete == "" && builder.Overflowed() {
		incomplete = "limit" // 資産や出現の数が上限を超え、記録を打ち切った
		log.Error("scan-incomplete", "reason", incomplete)
	}
	// ここから先（結果の書き出し）は、止める合図があっても最後まで行う
	builder.SetStop(nil)

	// ディストリの名前と版（レポートのスキャン概要に出す）
	var distribution *model.Distribution
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		if data, err := opener.ReadFile(p, 64<<10); err == nil {
			distribution = parseOSRelease(data)
			break
		}
	}

	inv := builder.Inventory()
	inv.Meta = model.Meta{
		ScanID: scanID, StartedAt: started.Format(time.RFC3339), FinishedAt: time.Now().UTC().Format(time.RFC3339),
		Completed: incomplete == "", Incomplete: incomplete,
		Tool: model.Tool{Version: Version}, Rules: rulesMeta,
		Host:       model.Host{Hostname: host, OS: runtime.GOOS, Arch: runtime.GOARCH, Distribution: distribution},
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
	if n := walker.Stats.AtimeNotPreserved + opener.AtimeNotPreserved; n > 0 {
		// 所有者でも root でもないファイルは、アクセス時刻を更新しない開き方ができない
		inv.Coverage.AtimeNotPreserved = n
		w := "the access time of " + strconv.Itoa(n) + " file(s) or directories could not be preserved (not the owner; run as root to avoid changing access times)"
		inv.Meta.Warnings = append(inv.Meta.Warnings, w)
		log.Warn("atime-not-preserved", "count", n)
	}

	// 評価（スキャン時点の評価ポリシーによる参考値）。指定されたルールに既定のポリシーがなければ付けない。
	if ev, err := assess.New(rs, "default"); err == nil {
		inv.Assessment = ev.Assess(inv)
	} else {
		log.Info("assessment-skipped", "detail", err.Error())
	}

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
	// 読み飛ばしがあれば、理由ごとの件数も出す（多い順。何が起きたかを、結果のファイルを開かなくても分かるようにする）
	reasons := ""
	if by := inv.Coverage.SkippedByReason; len(by) > 0 {
		names := make([]string, 0, len(by))
		for r := range by {
			names = append(names, r)
		}
		sort.Slice(names, func(i, j int) bool {
			if by[names[i]] != by[names[j]] {
				return by[names[i]] > by[names[j]]
			}
			return names[i] < names[j]
		})
		parts := make([]string, 0, len(names))
		for _, r := range names {
			parts = append(parts, r+": "+strconv.Itoa(by[r]))
		}
		reasons = " (" + strings.Join(parts, ", ") + ")"
	}
	fmt.Fprintf(stderr, "kagiya: %d assets, %d occurrences, %d skipped%s; result: %s\n",
		len(inv.Assets), len(inv.Occurrences), builder.SkipTotal(), reasons, resultPath)
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
// 実在の確認は safefs を通す（触れる前にマウント表で判定し、リンクは辿らない）。
func extraStoreRoots(roots, storePaths []string, opener *safefs.Opener) []string {
	var extra []string
	for _, p := range storePaths {
		covered := false
		for _, r := range append(append([]string{}, roots...), extra...) {
			if p == r || strings.HasPrefix(p, r+"/") {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		if _, err := opener.ListNames(p); err == nil {
			extra = append(extra, p)
		}
	}
	return extra
}
