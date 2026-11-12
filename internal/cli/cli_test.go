//go:build unix

package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tmp(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func run(args ...string) (code int, stdout, stderr string) {
	var o, e bytes.Buffer
	code = Run(args, &o, &e)
	return code, o.String(), e.String()
}

const secretMarker = "TOP-SECRET-MARKER-9f3a"

type fixture struct {
	root, out, logs string
	rsaDER, ecDER   []byte
}

func setup(t *testing.T) fixture {
	t.Helper()
	base := tmp(t)
	fx := fixture{root: base + "/tree", out: base + "/out", logs: base + "/logs"}
	os.MkdirAll(fx.root+"/etc/ssl", 0o755)
	os.MkdirAll(fx.root+"/excluded", 0o755)

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "rsa.example.jp"},
		NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}
	fx.rsaDER, _ = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rsaKey.PublicKey, rsaKey)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl2 := &x509.Certificate{SerialNumber: big.NewInt(78), Subject: pkix.Name{CommonName: "ec.example.jp"},
		NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}
	fx.ecDER, _ = x509.CreateCertificate(rand.Reader, tmpl2, tmpl2, &ecKey.PublicKey, ecKey)

	certPEM := func(der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}) }
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte(secretMarker + "-key-material")})

	// 証明書と秘密鍵が同じファイルに入っているもの
	os.WriteFile(fx.root+"/etc/ssl/server.pem", append(certPEM(fx.rsaDER), keyPEM...), 0o644)
	// DER 形式
	os.WriteFile(fx.root+"/etc/ssl/ec.cer", fx.ecDER, 0o644)
	// 同じ証明書がもう1か所にある
	os.WriteFile(fx.root+"/etc/copy.crt", certPEM(fx.rsaDER), 0o644)
	// 秘密鍵だけのファイル、秘密を含む設定ファイル
	os.WriteFile(fx.root+"/etc/ssl/server.key", keyPEM, 0o600)
	os.WriteFile(fx.root+"/etc/app.conf", []byte("password="+secretMarker+"\n"), 0o644)
	// 壊れた証明書
	os.WriteFile(fx.root+"/etc/broken.crt", []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), 0o644)
	// 除外対象
	os.WriteFile(fx.root+"/excluded/x.pem", certPEM(fx.ecDER), 0o644)
	return fx
}

func (fx fixture) scanArgs(extra ...string) []string {
	return append([]string{"scan", "--roots", fx.root, "--output-dir", fx.out, "--log-dir", fx.logs,
		"--exclude", fx.root + "/excluded", "--cpu-limit", "100", "--io-limit", "0", "--label", "system=test"}, extra...)
}

func singleFile(t *testing.T, dir, suffix string) string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), suffix) {
			found = append(found, filepath.Join(dir, e.Name()))
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one *%s in %s, got %v", suffix, dir, ents)
	}
	return found[0]
}

func fp(der []byte) string {
	s := sha256.Sum256(der)
	return hex.EncodeToString(s[:])
}

func TestScanEndToEnd(t *testing.T) {
	fx := setup(t)
	code, _, stderr := run(fx.scanArgs()...)
	if code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr)
	}
	resultPath := singleFile(t, fx.out, ".json")
	if !strings.HasPrefix(filepath.Base(resultPath), "kagiya-") {
		t.Errorf("result file name = %s", filepath.Base(resultPath))
	}
	fi, _ := os.Stat(resultPath)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("result file mode = %o, want 600", fi.Mode().Perm())
	}
	logPath := singleFile(t, fx.logs, ".log")
	if fi, _ := os.Stat(logPath); fi.Mode().Perm() != 0o600 {
		t.Errorf("log file mode = %o, want 600", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(fx.out); fi.Mode().Perm() != 0o700 {
		t.Errorf("output dir mode = %o, want 700", fi.Mode().Perm())
	}

	raw, _ := os.ReadFile(resultPath)
	var inv struct {
		Schema string `json:"schema"`
		Meta   struct {
			ScanID    string `json:"scan_id"`
			Completed bool   `json:"completed"`
			Rules     struct{ Source, Version, SHA256 string }
			Host      struct{ Hostname, OS, Arch string }
			Labels    map[string]string
			Hardening map[string]any
		}
		Assets []struct {
			ID, Type  string
			Algorithm *struct {
				Family, Primitive string
				KeyBits           int `json:"key_bits"`
			}
			Certificate *struct {
				Subject, Issuer, Serial string
				NotBefore               string `json:"not_before"`
				NotAfter                string `json:"not_after"`
				SelfSigned              bool   `json:"self_signed"`
				SignatureAlgorithm      string `json:"signature_algorithm"`
				PublicKey               struct {
					Algorithm string
				} `json:"public_key"`
			}
		}
		Occurrences []struct {
			ID, Asset, Collector, State string
			Location                    struct{ Kind, Path string }
		}
		Skipped  []struct{ Path, Reason, Detail string }
		Coverage struct {
			FilesExamined   int            `json:"files_examined"`
			SkippedByReason map[string]int `json:"skipped_by_reason"`
		}
	}
	if err := json.Unmarshal(raw, &inv); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	if inv.Schema != "kagiya-inventory/v0" || !inv.Meta.Completed || inv.Meta.ScanID == "" {
		t.Errorf("schema=%q completed=%v scan_id=%q", inv.Schema, inv.Meta.Completed, inv.Meta.ScanID)
	}
	if inv.Meta.Rules.Source != "builtin" || len(inv.Meta.Rules.SHA256) != 64 || inv.Meta.Rules.Version == "" {
		t.Errorf("rules meta = %+v", inv.Meta.Rules)
	}
	if inv.Meta.Labels["system"] != "test" || inv.Meta.Host.OS == "" || inv.Meta.Hardening == nil {
		t.Errorf("meta = %+v", inv.Meta)
	}

	assets := map[string]int{}
	for i, a := range inv.Assets {
		assets[a.ID] = i
	}
	rsaID, ecID := "cert:sha256:"+fp(fx.rsaDER), "cert:sha256:"+fp(fx.ecDER)
	i, ok := assets[rsaID]
	if !ok {
		t.Fatalf("RSA certificate asset missing; assets: %v", assets)
	}
	c := inv.Assets[i].Certificate
	if c == nil || c.Subject != "CN=rsa.example.jp" || c.Serial != "4d" || !c.SelfSigned ||
		c.NotAfter != "2027-01-01T00:00:00Z" || c.SignatureAlgorithm != "alg:sha256-with-rsa" || c.PublicKey.Algorithm != "alg:rsa-2048" {
		t.Errorf("RSA certificate = %+v", c)
	}
	if j, ok := assets["alg:rsa-2048"]; !ok || inv.Assets[j].Algorithm == nil || inv.Assets[j].Algorithm.KeyBits != 2048 || inv.Assets[j].Algorithm.Family != "RSA" {
		t.Errorf("alg:rsa-2048 asset missing or wrong")
	}
	if j, ok := assets[ecID]; !ok || inv.Assets[j].Certificate.PublicKey.Algorithm != "alg:ec-p256" ||
		inv.Assets[j].Certificate.SignatureAlgorithm != "alg:ecdsa-with-sha256" {
		t.Errorf("EC certificate asset missing or wrong")
	}
	for _, id := range []string{"alg:sha256-with-rsa", "alg:ecdsa-with-sha256", "alg:ec-p256"} {
		if _, ok := assets[id]; !ok {
			t.Errorf("asset %s missing", id)
		}
	}

	// 同じ証明書は資産1つ・出現2つ。除外ディレクトリの中のものは出現しない。
	occ := map[string][]string{}
	ids := map[string]bool{}
	for _, o := range inv.Occurrences {
		occ[o.Asset] = append(occ[o.Asset], o.Location.Path)
		if ids[o.ID] {
			t.Errorf("duplicate occurrence id %s", o.ID)
		}
		ids[o.ID] = true
		if o.Collector != "fscrawl" || o.Location.Kind != "file" || o.State == "" {
			t.Errorf("occurrence = %+v", o)
		}
	}
	if len(occ[rsaID]) != 2 || len(occ[ecID]) != 1 {
		t.Errorf("occurrences: rsa=%v ec=%v", occ[rsaID], occ[ecID])
	}

	skips := map[string]string{}
	for _, s := range inv.Skipped {
		skips[strings.TrimPrefix(s.Path, fx.root)] = s.Reason
	}
	if skips["/excluded"] != "excluded" || skips["/etc/broken.crt"] != "parse-error" {
		t.Errorf("skipped = %v", skips)
	}
	if inv.Coverage.SkippedByReason["excluded"] != 1 || inv.Coverage.FilesExamined < 6 {
		t.Errorf("coverage = %+v", inv.Coverage)
	}

	// 秘密の値は結果にもログにも現れない
	logRaw, _ := os.ReadFile(logPath)
	for name, content := range map[string][]byte{"result": raw, "log": logRaw} {
		if bytes.Contains(content, []byte(secretMarker)) ||
			bytes.Contains(content, []byte("VE9QLVNFQ1JFVC1NQVJLRVI")) { // マーカーの Base64
			t.Errorf("secret material leaked into %s", name)
		}
	}
	// ログには除外と、読めなかったものが記録される
	if !bytes.Contains(logRaw, []byte(`"reason":"excluded"`)) || !bytes.Contains(logRaw, []byte(`"event":"scan-finished"`)) {
		t.Errorf("log lacks expected records:\n%s", logRaw)
	}
}

func TestScanIsRepeatableWithoutOverwriting(t *testing.T) {
	fx := setup(t)
	for i := 0; i < 2; i++ {
		if code, _, stderr := run(fx.scanArgs()...); code != 0 {
			t.Fatalf("run %d: exit %d: %s", i, code, stderr)
		}
	}
	ents, _ := os.ReadDir(fx.out)
	if len(ents) != 2 {
		t.Errorf("want 2 result files after 2 runs, got %d", len(ents))
	}
}

func TestScanStrictExitCode(t *testing.T) {
	fx := setup(t)
	if code, _, _ := run(fx.scanArgs("--strict")...); code != 1 {
		t.Errorf("exit code with --strict and a parse error = %d, want 1", code)
	}
}

func TestScanMissingRootIsRecorded(t *testing.T) {
	fx := setup(t)
	code, _, stderr := run("scan", "--roots", fx.root+"/nope", "--output-dir", fx.out, "--log-dir", fx.logs, "--cpu-limit", "100", "--io-limit", "0")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	raw, _ := os.ReadFile(singleFile(t, fx.out, ".json"))
	if !bytes.Contains(raw, []byte(`"reason": "not-found"`)) && !bytes.Contains(raw, []byte(`"reason":"not-found"`)) {
		t.Errorf("missing root not recorded: %s", raw)
	}
}

func TestScanUsageErrors(t *testing.T) {
	fx := setup(t)
	cases := [][]string{
		{},
		{"frobnicate"},
		{"scan", "--no-such-flag"},
		{"scan", "--roots", "relative/path", "--output-dir", fx.out, "--log-dir", fx.logs},
		{"scan", "--roots", fx.root, "--output-dir", fx.out, "--log-dir", fx.logs, "--exclude", ""},
		{"scan", "--roots", fx.root, "--output-dir", fx.out, "--log-dir", fx.logs, "--label", "novalue"},
		{"rules"},
		{"rules", "export"},
	}
	for _, args := range cases {
		if code, _, _ := run(args...); code != 2 {
			t.Errorf("args %v: exit code %d, want 2", args, code)
		}
	}
	// 引数エラーでは何も書き出さない
	if _, err := os.Stat(fx.out); err == nil {
		t.Error("output directory was created despite usage errors")
	}
}

func TestScanRefusesWorldWritableOutputDir(t *testing.T) {
	fx := setup(t)
	os.Mkdir(fx.out, 0o777)
	os.Chmod(fx.out, 0o777)
	if code, _, stderr := run(fx.scanArgs()...); code != 3 || !strings.Contains(stderr, "writable by other users") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
}

func TestVersion(t *testing.T) {
	code, stdout, _ := run("version")
	if code != 0 || !strings.HasPrefix(stdout, "kagiya ") || !strings.Contains(stdout, "rules ") {
		t.Errorf("version: code=%d stdout=%q", code, stdout)
	}
}

func TestRulesExportValidateAndUse(t *testing.T) {
	fx := setup(t)
	rulesDir := filepath.Dir(fx.root) + "/rules"
	if code, _, stderr := run("rules", "export", "--output-dir", rulesDir); code != 0 {
		t.Fatalf("rules export: exit %d: %s", code, stderr)
	}
	for _, p := range []string{"manifest.yaml", "catalog/algorithms.yaml"} {
		fi, err := os.Stat(filepath.Join(rulesDir, p))
		if err != nil {
			t.Fatalf("exported file missing: %v", err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 600", p, fi.Mode().Perm())
		}
	}
	// 既存ファイルは上書きしない
	if code, _, _ := run("rules", "export", "--output-dir", rulesDir); code == 0 {
		t.Error("second export into the same directory must fail (no overwrite)")
	}
	if code, stdout, stderr := run("rules", "validate", "--rules", rulesDir); code != 0 || !strings.Contains(stdout, "OK") {
		t.Errorf("rules validate: exit %d stdout=%q stderr=%q", code, stdout, stderr)
	}

	// 外部ルールでスキャンすると、その旨が結果に残る
	if code, _, stderr := run(fx.scanArgs("--rules", rulesDir)...); code != 0 {
		t.Fatalf("scan with external rules: exit %d: %s", code, stderr)
	}
	raw, _ := os.ReadFile(singleFile(t, fx.out, ".json"))
	if !bytes.Contains(raw, []byte(`"source": "external"`)) {
		t.Errorf("rules source not recorded as external")
	}

	// 壊れたルールは検証で弾かれ、スキャンも始まらない
	os.Chmod(filepath.Join(rulesDir, "manifest.yaml"), 0o600)
	f, _ := os.OpenFile(filepath.Join(rulesDir, "manifest.yaml"), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("surprise: true\n")
	f.Close()
	if code, _, _ := run("rules", "validate", "--rules", rulesDir); code != 3 {
		t.Errorf("validate of broken rules: exit %d, want 3", code)
	}
	before, _ := os.ReadDir(fx.out)
	if code, _, _ := run(fx.scanArgs("--rules", rulesDir)...); code != 3 {
		t.Errorf("scan with broken rules: exit %d, want 3", code)
	}
	after, _ := os.ReadDir(fx.out)
	if len(after) != len(before) {
		t.Error("scan with broken rules produced output")
	}
}

func TestScanRefusesUntrustedRulesDir(t *testing.T) {
	fx := setup(t)
	rulesDir := filepath.Dir(fx.root) + "/rules"
	if code, _, stderr := run("rules", "export", "--output-dir", rulesDir); code != 0 {
		t.Fatalf("rules export: %s", stderr)
	}
	// 他ユーザーが書き込めるルールファイル
	os.Chmod(filepath.Join(rulesDir, "catalog", "algorithms.yaml"), 0o666)
	if code, _, stderr := run(fx.scanArgs("--rules", rulesDir)...); code != 3 || !strings.Contains(stderr, "rules") {
		t.Errorf("writable rule file: exit %d, stderr %q", code, stderr)
	}
	os.Chmod(filepath.Join(rulesDir, "catalog", "algorithms.yaml"), 0o600)
	// シンボリックリンクを含むルールディレクトリ
	os.Symlink("/etc/passwd", filepath.Join(rulesDir, "catalog", "link.yaml"))
	if code, _, _ := run(fx.scanArgs("--rules", rulesDir)...); code != 3 {
		t.Errorf("rules dir with symlink: exit %d, want 3", code)
	}
}

// OpenSSL の「信頼設定付き証明書」（BEGIN TRUSTED CERTIFICATE）は、証明書の後ろに補助データが続く。
// 実物: RHEL 8.10 (UBI) の /etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt
// （redhat/ubi8@sha256:44f19e308462e9152cb26d641fc0ce5bf6cbdab3cd101367aed67573eb2cf20e で確認）
func TestScanTrustedCertificateWithAuxData(t *testing.T) {
	fx := setup(t)
	aux := []byte{0x30, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01} // 信頼用途の一覧
	block := pem.EncodeToMemory(&pem.Block{Type: "TRUSTED CERTIFICATE", Bytes: append(append([]byte{}, fx.ecDER...), aux...)})
	os.MkdirAll(fx.root+"/trust", 0o755)
	os.WriteFile(fx.root+"/trust/ca-bundle.trust.crt", block, 0o644)

	if code, _, stderr := run("scan", "--roots", fx.root+"/trust", "--output-dir", fx.out, "--log-dir", fx.logs,
		"--cpu-limit", "100", "--io-limit", "0", "--strict"); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	raw, _ := os.ReadFile(singleFile(t, fx.out, ".json"))
	if !bytes.Contains(raw, []byte(`"id": "cert:sha256:`+fp(fx.ecDER)+`"`)) {
		t.Errorf("trusted certificate was not recognised (fingerprint must cover the certificate only)")
	}
	if bytes.Contains(raw, []byte("parse-error")) {
		t.Errorf("trusted certificate reported as parse error")
	}
}
