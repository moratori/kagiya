package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"kagiya/internal/logx"
	"kagiya/internal/model"
	"kagiya/internal/output"
	"kagiya/internal/parse/der"
	"kagiya/internal/parse/x509cert"
	"kagiya/internal/platform"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
	"kagiya/internal/throttle"
)

const (
	maxSkippedInResult = 10_000
	maxCertFileSize    = 1 << 20 // 証明書ファイルとして読む上限
)

var (
	labelPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	certExts     = map[string]bool{".pem": true, ".crt": true, ".cer": true, ".cert": true}
)

type scanOptions struct {
	outputDir, logDir, rulesDir string
	roots, excludes             []string
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

	sc := newScanner(rs, log)
	excludes, _ := safefs.NewExcludes(opts.excludes)
	walker := &safefs.Walker{
		Excludes:    excludes,
		SkipDirs:    []string{opts.outputDir, opts.logDir},
		MaxFileSize: opts.maxFileSizeMiB << 20,
		Limiter: throttle.New(throttle.Config{CPUPercent: opts.cpuLimit, BytesPerSecond: opts.ioLimitMiB << 20},
			throttle.RealClock()),
		OnSkip: sc.skip,
	}
	if mounts.table != nil {
		walker.Mounts = mounts.table
	}

	incomplete := ""
	for _, root := range opts.roots {
		err := walker.Walk(ctx, root, sc.visit)
		switch {
		case err == nil:
		case errors.Is(err, context.DeadlineExceeded):
			incomplete = "max-duration"
		case errors.Is(err, context.Canceled):
			incomplete = "interrupted"
		case errors.Is(err, fs.ErrNotExist):
			sc.skip(safefs.Skip{Path: root, Reason: "not-found"})
		default:
			sc.skip(safefs.Skip{Path: root, Reason: "invalid-root"})
			log.Error("invalid-root", "path", root, "detail", err.Error())
		}
		if incomplete != "" {
			log.Error("scan-incomplete", "reason", incomplete)
			break
		}
	}

	inv := sc.inventory()
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
	inv.Coverage.BytesRead = walker.Stats.BytesRead

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
		len(inv.Assets), len(inv.Occurrences), sc.skipTotal, resultPath)
	if opts.strict && sc.problemSkips > 0 {
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

// scanner は見つけたものを資産と出現にまとめる。
type scanner struct {
	rs  *ruleset.RuleSet
	log *logx.Logger

	assets       map[string]model.Asset
	occurrences  []model.Occurrence
	skipped      []model.Skipped
	skipByReason map[string]int
	skipTotal    int
	problemSkips int // 除外指定など意図したもの以外のスキップ
}

func newScanner(rs *ruleset.RuleSet, log *logx.Logger) *scanner {
	return &scanner{rs: rs, log: log, assets: map[string]model.Asset{}, skipByReason: map[string]int{}}
}

func (s *scanner) skip(k safefs.Skip) {
	s.skipTotal++
	s.skipByReason[k.Reason]++
	if k.Reason != "excluded" && k.Reason != "not-found" {
		s.problemSkips++
	}
	s.log.Warn("skip", "path", k.Path, "reason", k.Reason, "detail", k.Detail)
	if len(s.skipped) < maxSkippedInResult {
		s.skipped = append(s.skipped, model.Skipped{Path: k.Path, Reason: k.Reason, Detail: k.Detail})
	}
}

// visit は通常ファイル1つを調べる。Phase 0 では証明書ファイル（PEM / DER）のみ。
func (s *scanner) visit(e *safefs.Entry) error {
	ext := ""
	if i := strings.LastIndexByte(e.Name, '.'); i >= 0 {
		ext = strings.ToLower(e.Name[i:])
	}
	if !certExts[ext] {
		return nil
	}
	data, err := e.ReadLimited(maxCertFileSize)
	if err != nil {
		return nil // スキップは記録済み
	}
	var ders [][]byte
	if len(data) > 0 && data[0] == 0x30 {
		ders = append(ders, data)
	} else {
		rest := data
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			// 証明書以外のブロック（秘密鍵など）は中身に触れない。
			switch block.Type {
			case "CERTIFICATE", "X509 CERTIFICATE":
				ders = append(ders, block.Bytes)
			case "TRUSTED CERTIFICATE":
				// OpenSSL の信頼設定付き証明書: 証明書の後ろに補助データ（信頼用途など）が続く。
				// 先頭の要素（証明書本体）だけを取り出す。
				if cert, _, err := der.Read(block.Bytes); err == nil {
					ders = append(ders, cert.Raw)
				} else {
					ders = append(ders, block.Bytes)
				}
			}
		}
	}
	found, failed := 0, 0
	for i, der := range ders {
		cert, err := x509cert.Parse(der)
		if err != nil {
			failed++
			continue
		}
		found++
		s.addCertificate(cert, e.Path, i)
	}
	if failed > 0 {
		s.skip(safefs.Skip{Path: e.Path, Reason: "parse-error", Detail: strconv.Itoa(failed) + " certificate(s) could not be parsed"})
	}
	return nil
}

func (s *scanner) addCertificate(c *x509cert.Certificate, path string, index int) {
	sigID := s.algorithmByOID(c.SignatureAlgorithmOID)
	keyID := s.publicKeyAlgorithm(c)
	id := "cert:sha256:" + c.FingerprintSHA256
	if _, ok := s.assets[id]; !ok {
		s.assets[id] = model.Asset{ID: id, Type: "certificate", Certificate: &model.Certificate{
			Subject: c.Subject, Issuer: c.Issuer, Serial: c.SerialHex,
			NotBefore: c.NotBefore.Format(time.RFC3339), NotAfter: c.NotAfter.Format(time.RFC3339),
			IsCA: c.IsCA, SelfSigned: c.SelfSigned, SignatureAlgorithm: sigID,
			PublicKey:         model.PublicKey{Algorithm: keyID, FingerprintSHA256: c.PublicKeyFingerprintSHA256},
			FingerprintSHA256: c.FingerprintSHA256,
		}}
	}
	h := sha256.Sum256([]byte(id + "\x00fscrawl\x00" + path + "\x00" + strconv.Itoa(index)))
	s.occurrences = append(s.occurrences, model.Occurrence{
		ID: "occ:" + hex.EncodeToString(h[:12]), Asset: id, Collector: "fscrawl",
		State: "present", Confidence: "high",
		Location: model.Location{Kind: "file", Path: path, Index: index},
	})
}

// algorithmByOID は OID をカタログで引き、アルゴリズム資産の ID を返す。
// カタログにない OID も捨てずに「未知」として記録する（OID は数字とドットだけなので秘密を含み得ない）。
func (s *scanner) algorithmByOID(oid string) string {
	if a, ok := s.rs.LookupAlias("oid", oid); ok {
		id := "alg:" + a.ID
		if _, exists := s.assets[id]; !exists {
			s.assets[id] = model.Asset{ID: id, Type: "algorithm", Algorithm: &model.Algorithm{
				Family: a.Family, Primitive: a.Primitive, KeyBits: a.KeyBits, RawName: oid, Scheme: "oid", Known: true}}
		}
		return id
	}
	id := "alg:unknown:oid:" + oid
	if _, exists := s.assets[id]; !exists {
		s.assets[id] = model.Asset{ID: id, Type: "algorithm", Algorithm: &model.Algorithm{RawName: oid, Scheme: "oid"}}
	}
	return id
}

func (s *scanner) publicKeyAlgorithm(c *x509cert.Certificate) string {
	switch {
	case c.RSABits > 0:
		a, ok := s.rs.LookupAlias("oid", c.PublicKeyAlgorithmOID)
		if !ok {
			break
		}
		id := "alg:" + a.ID + "-" + strconv.Itoa(c.RSABits)
		if _, exists := s.assets[id]; !exists {
			s.assets[id] = model.Asset{ID: id, Type: "algorithm", Algorithm: &model.Algorithm{
				Family: a.Family, Primitive: a.Primitive, KeyBits: c.RSABits, RawName: c.PublicKeyAlgorithmOID, Scheme: "oid", Known: true}}
		}
		return id
	case c.CurveOID != "":
		return s.algorithmByOID(c.CurveOID)
	}
	return s.algorithmByOID(c.PublicKeyAlgorithmOID)
}

func (s *scanner) inventory() *model.Inventory {
	inv := &model.Inventory{Schema: model.Schema, Assets: []model.Asset{}, Occurrences: s.occurrences, Skipped: s.skipped}
	for _, a := range s.assets {
		inv.Assets = append(inv.Assets, a)
	}
	sort.Slice(inv.Assets, func(i, j int) bool { return inv.Assets[i].ID < inv.Assets[j].ID })
	if inv.Occurrences == nil {
		inv.Occurrences = []model.Occurrence{}
	}
	if inv.Skipped == nil {
		inv.Skipped = []model.Skipped{}
	}
	inv.Coverage.SkippedByReason = s.skipByReason
	inv.Coverage.SkippedTruncated = s.skipTotal > len(s.skipped)
	return inv
}
