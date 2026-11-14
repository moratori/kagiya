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
	"runtime"
	"runtime/debug"
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

// noProblemsUnder は、スキャンの結果に、root の下のファイルについての「問題のある読み飛ばし」がないことを確かめる。
// スキャンは実行環境そのもの（/etc の設定など）も読むので、--strict の終了コードで確かめると、テストの対象と関係のない
// 読み飛ばし（root 以外で実行したときに読めない設定ファイルなど）で失敗する。対象のディレクトリの下だけを見る。
func noProblemsUnder(t *testing.T, outDir, root string) {
	t.Helper()
	raw, err := os.ReadFile(singleFile(t, outDir, ".json"))
	if err != nil {
		t.Fatal(err)
	}
	var inv struct {
		Skipped []struct{ Path, Reason, Detail string } `json:"skipped"`
	}
	if err := json.Unmarshal(raw, &inv); err != nil {
		t.Fatal(err)
	}
	for _, s := range inv.Skipped {
		if strings.HasPrefix(s.Path, root) && s.Reason != "excluded" && s.Reason != "not-found" {
			t.Errorf("a file under the scanned directory was skipped: %s (%s %s)", s.Path, s.Reason, s.Detail)
		}
	}
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
	// 除外の指定で外したものは、件数だけを記録する（名前は、結果にもログにも残さない。2026-11-14 のレビューの指摘 A-7・B-4）
	if _, listed := skips["/excluded"]; listed || skips["/etc/broken.crt"] != "parse-error" {
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
	// ログには、読めなかったものと、理由ごとの件数（除外を含む）が記録される
	if !bytes.Contains(logRaw, []byte(`"reason":"parse-error"`)) || !bytes.Contains(logRaw, []byte(`"event":"skip-summary"`)) ||
		!bytes.Contains(logRaw, []byte(`"excluded":1`)) || !bytes.Contains(logRaw, []byte(`"event":"scan-finished"`)) {
		t.Errorf("log lacks expected records:\n%s", logRaw)
	}
	if bytes.Contains(logRaw, []byte(fx.root+"/excluded"+`","reason"`)) {
		t.Errorf("the name of an excluded path is logged:\n%s", logRaw)
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
		"--cpu-limit", "100", "--io-limit", "0"); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	noProblemsUnder(t, fx.out, fx.root)
	raw, _ := os.ReadFile(singleFile(t, fx.out, ".json"))
	if !bytes.Contains(raw, []byte(`"id": "cert:sha256:`+fp(fx.ecDER)+`"`)) {
		t.Errorf("trusted certificate was not recognised (fingerprint must cover the certificate only)")
	}
	if bytes.Contains(raw, []byte("parse-error")) {
		t.Errorf("trusted certificate reported as parse error")
	}
}

// 実物のツールで生成した鍵素材一式（internal/parse/testdata/material）をスキャンする。
func TestScanKeyMaterial(t *testing.T) {
	src, err := filepath.Abs("../parse/testdata/material")
	if err != nil {
		t.Fatal(err)
	}
	base := tmp(t)
	root, out, logs := base+"/material", base+"/out", base+"/logs"
	os.Mkdir(root, 0o755)
	ents, _ := os.ReadDir(src)
	var keyLines [][]byte // 秘密鍵ファイルの中身の一部（出力に現れてはならない）
	for _, e := range ents {
		data, _ := os.ReadFile(filepath.Join(src, e.Name()))
		os.WriteFile(filepath.Join(root, e.Name()), data, 0o600)
		if bytes.Contains(data, []byte("PRIVATE KEY-----")) {
			lines := bytes.Split(data, []byte("\n"))
			if len(lines) > 4 {
				keyLines = append(keyLines, lines[len(lines)/2])
			}
		}
	}
	// SSH の秘密鍵は拡張子がないので、よくある名前でも置く
	for from, to := range map[string]string{"ssh-ed25519": "id_ed25519", "ssh-rsa3072": "ssh_host_rsa_key"} {
		data, _ := os.ReadFile(filepath.Join(src, from))
		os.WriteFile(filepath.Join(root, to), data, 0o600)
	}

	code, _, stderr := run("scan", "--roots", root, "--output-dir", out, "--log-dir", logs, "--cpu-limit", "100", "--io-limit", "0")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	noProblemsUnder(t, out, root)
	raw, _ := os.ReadFile(singleFile(t, out, ".json"))
	logRaw, _ := os.ReadFile(singleFile(t, logs, ".log"))

	type protection struct {
		Scheme, KDF, PRF, Cipher string
		Iterations               int
	}
	var inv struct {
		Assets []struct {
			ID, Type string
			Key      *struct {
				Algorithm               string
				PublicFingerprintSHA256 string `json:"public_fingerprint_sha256"`
				SSHFingerprint          string `json:"ssh_fingerprint"`
			}
			CSR *struct {
				Subject            string
				SignatureAlgorithm string                     `json:"signature_algorithm"`
				PublicKey          struct{ Algorithm string } `json:"public_key"`
			}
			Keystore *struct {
				Format    string
				Integrity *struct {
					Algorithm  string
					Iterations int
				}
				Entries map[string]int
				Opaque  bool `json:"contents_unreadable"`
			}
			Certificate *struct {
				PublicKey struct {
					FingerprintSHA256 string `json:"fingerprint_sha256"`
				} `json:"public_key"`
			}
		}
		Occurrences []struct {
			Asset    string
			State    string
			Location struct {
				Path      string
				Container string
			}
			Detail *struct {
				Format     string
				Encrypted  *bool
				Protection *protection
			}
		}
		Skipped []struct{ Path, Reason string }
	}
	if err := json.Unmarshal(raw, &inv); err != nil {
		t.Fatal(err)
	}
	// 鍵素材のディレクトリの下に、読み飛ばしがないこと（実行環境そのものの設定の読み飛ばしは、ここでは見ない）
	for _, sk := range inv.Skipped {
		if strings.HasPrefix(sk.Path, root) {
			t.Errorf("skipped: %+v", sk)
		}
	}
	types := map[string]int{}
	asset := map[string]int{}
	for i, a := range inv.Assets {
		types[a.Type]++
		asset[a.ID] = i
	}
	for _, typ := range []string{"certificate", "private-key", "public-key", "csr", "keystore", "algorithm"} {
		if types[typ] == 0 {
			t.Errorf("no asset of type %s; types: %v", typ, types)
		}
	}
	occ := map[string][]int{} // ファイル名 → 出現の添字
	for i, o := range inv.Occurrences {
		occ[filepath.Base(o.Location.Path)] = append(occ[filepath.Base(o.Location.Path)], i)
	}
	only := func(file string) (assetIdx, occIdx int) {
		t.Helper()
		if len(occ[file]) != 1 {
			t.Fatalf("%s: %d occurrences, want 1", file, len(occ[file]))
		}
		o := inv.Occurrences[occ[file][0]]
		return asset[o.Asset], occ[file][0]
	}

	// 同じ RSA 鍵は、形式が違っても（PKCS#1 / PKCS#8 / DER）1つの資産にまとまり、証明書の公開鍵と指紋で対応づく。
	a1, o1 := only("rsa2048-pkcs1.pem")
	a2, o2 := only("rsa2048-pkcs8.pem")
	a3, _ := only("rsa2048-pkcs8.der")
	if a1 != a2 || a1 != a3 {
		t.Errorf("the same key in different formats must be one asset: %d %d %d", a1, a2, a3)
	}
	key := inv.Assets[a1]
	if key.Type != "private-key" || key.Key == nil || key.Key.Algorithm != "alg:rsa-2048" {
		t.Fatalf("rsa private key asset = %+v", key)
	}
	if d := inv.Occurrences[o1].Detail; d == nil || d.Format != "pkcs1" || d.Encrypted == nil || *d.Encrypted {
		t.Errorf("pkcs1 occurrence detail = %+v", d)
	}
	if d := inv.Occurrences[o2].Detail; d == nil || d.Format != "pkcs8" {
		t.Errorf("pkcs8 occurrence detail = %+v", d)
	}
	ca, _ := only("cert-rsa.der")
	if inv.Assets[ca].Certificate.PublicKey.FingerprintSHA256 != key.Key.PublicFingerprintSHA256 {
		t.Error("certificate and private key are not linked by the public key fingerprint")
	}

	// 暗号化された秘密鍵: 保護方式が記録される
	_, oe := only("rsa2048-pkcs8-enc.pem")
	d := inv.Occurrences[oe].Detail
	if d == nil || d.Encrypted == nil || !*d.Encrypted || d.Protection == nil || d.Protection.Scheme != "alg:pbes2" ||
		d.Protection.KDF != "alg:pbkdf2" || d.Protection.Cipher != "alg:aes-256-cbc" || d.Protection.PRF != "alg:hmac-sha256" || d.Protection.Iterations != 4096 {
		t.Errorf("encrypted PKCS#8 detail = %+v protection=%+v", d, d.Protection)
	}
	_, ol := only("rsa2048-pkcs1-enc.pem")
	if d := inv.Occurrences[ol].Detail; d.Protection == nil || d.Protection.Cipher != "alg:aes-128-cbc" {
		t.Errorf("legacy PEM encryption = %+v", d.Protection)
	}
	_, os1 := only("ssh-ed25519-enc")
	if d := inv.Occurrences[os1].Detail; d.Format != "openssh" || d.Protection == nil || d.Protection.Cipher != "alg:aes-256-ctr" || d.Protection.KDF != "alg:bcrypt-pbkdf" {
		t.Errorf("OpenSSH encryption = %+v", d.Protection)
	}

	// SSH: 秘密鍵と公開鍵が同じ指紋を持ち、よくある名前のファイルも見つかる
	ap, _ := only("id_ed25519")
	apub, _ := only("ssh-ed25519.pub")
	if inv.Assets[ap].Type != "private-key" || inv.Assets[apub].Type != "public-key" ||
		inv.Assets[ap].Key.SSHFingerprint == "" || inv.Assets[ap].Key.SSHFingerprint != inv.Assets[apub].Key.SSHFingerprint ||
		inv.Assets[ap].Key.Algorithm != "alg:ed25519" {
		t.Errorf("ssh keys: private=%+v public=%+v", inv.Assets[ap].Key, inv.Assets[apub].Key)
	}
	if len(occ["ssh_host_rsa_key"]) != 1 || len(occ["authorized_keys"]) != 3 || len(occ["known_hosts"]) != 3 {
		t.Errorf("ssh files: host key %d, authorized_keys %d, known_hosts %d", len(occ["ssh_host_rsa_key"]), len(occ["authorized_keys"]), len(occ["known_hosts"]))
	}

	// 耐量子計算機暗号（ML-DSA-65）の鍵と証明書
	am, _ := only("mldsa65-pkcs8.pem")
	if inv.Assets[am].Key.Algorithm != "alg:ml-dsa-65" {
		t.Errorf("ML-DSA key algorithm = %s", inv.Assets[am].Key.Algorithm)
	}

	// CSR
	ar, _ := only("csr-rsa.pem")
	if c := inv.Assets[ar].CSR; c == nil || c.Subject != "C=JP, O=Kagiya Test, CN=csr.test.example" ||
		c.SignatureAlgorithm != "alg:sha256-with-rsa" || c.PublicKey.Algorithm != "alg:rsa-2048" {
		t.Errorf("csr = %+v", inv.Assets[ar].CSR)
	}

	// キーストア: 資産として記録され、中の証明書は「キーストアの中」として出現する
	findStore := func(file string) int {
		t.Helper()
		for _, i := range occ[file] {
			if a := inv.Assets[asset[inv.Occurrences[i].Asset]]; a.Type == "keystore" {
				return asset[inv.Occurrences[i].Asset]
			}
		}
		t.Fatalf("%s: no keystore asset", file)
		return 0
	}
	ks := inv.Assets[findStore("modern.p12")].Keystore
	if ks.Format != "pkcs12" || !ks.Opaque || ks.Integrity == nil || ks.Integrity.Algorithm != "alg:sha256" || ks.Integrity.Iterations != 2048 || ks.Entries["private_keys"] != 1 {
		t.Errorf("modern.p12 = %+v integrity=%+v", ks, ks.Integrity)
	}
	jks := inv.Assets[findStore("store.jks")].Keystore
	if jks.Format != "jks" || jks.Opaque || jks.Entries["private_keys"] != 1 || jks.Entries["trusted_certificates"] != 1 {
		t.Errorf("store.jks = %+v", jks)
	}
	inStore := 0
	for _, i := range occ["store.jks"] {
		o := inv.Occurrences[i]
		if inv.Assets[asset[o.Asset]].Type == "certificate" && o.Location.Container == "jks" {
			inStore++
		}
	}
	if inStore != 2 {
		t.Errorf("certificates found inside store.jks = %d, want 2", inStore)
	}
	if len(occ["bundle.p7b"]) != 2 {
		t.Errorf("bundle.p7b: %d occurrences, want 2 certificates", len(occ["bundle.p7b"]))
	}

	// 秘密鍵の中身は結果にもログにも現れない
	if len(keyLines) < 10 {
		t.Fatalf("only %d private key samples", len(keyLines))
	}
	for _, line := range keyLines {
		if len(line) >= 32 && (bytes.Contains(raw, line) || bytes.Contains(logRaw, line)) {
			t.Fatalf("private key material leaked: %s", line[:16])
		}
	}
	if bytes.Contains(raw, []byte("kagiya-test-password")) || bytes.Contains(raw, []byte("mykey")) {
		t.Error("password or keystore alias leaked")
	}
}

func TestConvertToCSV(t *testing.T) {
	fx := setup(t)
	if code, _, stderr := run(fx.scanArgs()...); code != 0 {
		t.Fatalf("scan: exit %d: %s", code, stderr)
	}
	result := singleFile(t, fx.out, ".json")
	csvDir := filepath.Dir(fx.root) + "/csv"
	code, stdout, stderr := run("convert", "--to", "csv", "--output-dir", csvDir, result)
	if code != 0 {
		t.Fatalf("convert: exit %d: %s", code, stderr)
	}
	out := singleFile(t, csvDir, ".csv")
	if !strings.Contains(stdout, out) {
		t.Errorf("stdout must name the written file: %q", stdout)
	}
	if filepath.Base(out) != strings.TrimSuffix(filepath.Base(result), ".json")+".csv" {
		t.Errorf("csv file name = %s", filepath.Base(out))
	}
	fi, _ := os.Stat(out)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("csv mode = %o, want 600", fi.Mode().Perm())
	}
	data, _ := os.ReadFile(out)
	if !bytes.HasPrefix(data, []byte("\xef\xbb\xbf")) {
		t.Error("CSV must start with a BOM by default")
	}
	if n := bytes.Count(data, []byte("\n")); n != 4 { // 見出し + 出現3件
		t.Errorf("csv has %d lines, want 4", n)
	}
	if !bytes.Contains(data, []byte("CN=rsa.example.jp")) || !bytes.Contains(data, []byte("/etc/ssl/ec.cer")) {
		t.Errorf("csv lacks expected content:\n%s", data)
	}
	// 上書きしない
	if code, _, _ := run("convert", "--to", "csv", "--output-dir", csvDir, result); code != 3 {
		t.Errorf("second convert: exit %d, want 3 (no overwrite)", code)
	}
	// BOM なし
	csv2 := filepath.Dir(fx.root) + "/csv2"
	if code, _, _ := run("convert", "--to", "csv", "--no-bom", "--output-dir", csv2, result); code != 0 {
		t.Fatal("convert --no-bom failed")
	}
	if d, _ := os.ReadFile(singleFile(t, csv2, ".csv")); bytes.HasPrefix(d, []byte("\xef\xbb\xbf")) {
		t.Error("--no-bom must omit the BOM")
	}
}

func TestConvertRejectsBadInput(t *testing.T) {
	base := tmp(t)
	notJSON := base + "/x.json"
	os.WriteFile(notJSON, []byte("hello"), 0o600)
	otherSchema := base + "/y.json"
	os.WriteFile(otherSchema, []byte(`{"schema":"something-else/v9"}`), 0o600)
	for _, c := range []struct {
		args []string
		want int
	}{
		{[]string{"convert"}, 2},
		{[]string{"convert", "--to", "csv"}, 2},
		{[]string{"convert", "--to", "xml", notJSON}, 2},
		{[]string{"convert", "--to", "csv", "--output-dir", base + "/o", base + "/missing.json"}, 3},
		{[]string{"convert", "--to", "csv", "--output-dir", base + "/o", notJSON}, 3},
		{[]string{"convert", "--to", "csv", "--output-dir", base + "/o", otherSchema}, 3},
	} {
		if code, _, _ := run(c.args...); code != c.want {
			t.Errorf("args %v: exit %d, want %d", c.args, code, c.want)
		}
	}
	if ents, _ := os.ReadDir(base + "/o"); len(ents) != 0 {
		t.Errorf("failed conversions left files behind: %v", ents)
	}
}

// 証明書ストアの場所はルールで定義され、そこで見つかったものには store が付く。
func TestScanLabelsCertificateStores(t *testing.T) {
	fx := setup(t)
	rulesDir := filepath.Dir(fx.root) + "/rules"
	if code, _, stderr := run("rules", "export", "--output-dir", rulesDir); code != 0 {
		t.Fatalf("rules export: %s", stderr)
	}
	f, err := os.OpenFile(filepath.Join(rulesDir, "os", "stores.yaml"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("exported rules lack os/stores.yaml: %v", err)
	}
	f.WriteString("  - id: test-store\n    paths: [\"" + fx.root + "/etc/ssl\"]\n    sources:\n" +
		"      - image: \"test@sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6\"\n        os: \"test\"\n")
	f.Close()
	if code, _, stderr := run(fx.scanArgs("--rules", rulesDir)...); code != 0 {
		t.Fatalf("scan: exit %d: %s", code, stderr)
	}
	raw, _ := os.ReadFile(singleFile(t, fx.out, ".json"))
	var inv struct {
		Occurrences []struct {
			Store    string
			Location struct{ Path string }
		}
	}
	json.Unmarshal(raw, &inv)
	for _, o := range inv.Occurrences {
		inStore := strings.HasPrefix(o.Location.Path, fx.root+"/etc/ssl/")
		if inStore && o.Store != "test-store" || !inStore && o.Store != "" {
			t.Errorf("%s: store = %q", o.Location.Path, o.Store)
		}
	}
	if len(inv.Occurrences) != 3 {
		t.Errorf("occurrences = %d", len(inv.Occurrences))
	}
}

// スキャン結果には、既定の評価ポリシーによる判定（スキャン時点の参考値）が付く。
func TestScanAddsAssessment(t *testing.T) {
	fx := setup(t)
	if code, _, stderr := run(fx.scanArgs()...); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr)
	}
	raw, _ := os.ReadFile(singleFile(t, fx.out, ".json"))
	var inv struct {
		Assets     []struct{ ID, Type string }
		Assessment *struct {
			Policy        string
			PolicyVersion string `json:"policy_version"`
			Assets        map[string]struct {
				Quantum, Classical string
				Rules              []string
			}
			Values map[string]any
		}
	}
	if err := json.Unmarshal(raw, &inv); err != nil {
		t.Fatal(err)
	}
	if inv.Assessment == nil || inv.Assessment.Policy != "default" || inv.Assessment.PolicyVersion == "" || inv.Assessment.Values == nil {
		t.Fatalf("assessment = %+v", inv.Assessment)
	}
	certs := 0
	for _, a := range inv.Assets {
		if a.Type != "certificate" && a.Type != "algorithm" {
			continue
		}
		v, ok := inv.Assessment.Assets[a.ID]
		if !ok || v.Quantum == "" || v.Classical == "" {
			t.Errorf("%s has no verdict: %+v", a.ID, v)
		}
		if a.Type == "certificate" {
			certs++
			// テストデータの証明書はすべて RSA か楕円曲線（現行の公開鍵暗号）
			if v.Quantum != "vulnerable" || len(v.Rules) == 0 {
				t.Errorf("%s: %+v", a.ID, v)
			}
		}
	}
	if certs == 0 {
		t.Fatal("no certificate in the result")
	}
}

// report は、結果 JSON から 1 ホスト分の HTML レポートを作る。
func TestReport(t *testing.T) {
	fx := setup(t)
	if code, _, stderr := run(fx.scanArgs()...); code != 0 {
		t.Fatalf("scan: exit %d: %s", code, stderr)
	}
	result := singleFile(t, fx.out, ".json")
	dir := filepath.Dir(fx.root) + "/report"
	code, stdout, stderr := run("report", "--output-dir", dir, result)
	if code != 0 {
		t.Fatalf("report: exit %d: %s", code, stderr)
	}
	out := singleFile(t, dir, ".html")
	if !strings.Contains(stdout, out) {
		t.Errorf("stdout must name the written file: %q", stdout)
	}
	if filepath.Base(out) != strings.TrimSuffix(filepath.Base(result), ".json")+".html" {
		t.Errorf("report file name = %s", filepath.Base(out))
	}
	if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o600 {
		t.Errorf("report mode = %o, want 600", fi.Mode().Perm())
	}
	data, _ := os.ReadFile(out)
	for _, want := range []string{"<!DOCTYPE html>", "Content-Security-Policy", "CN=rsa.example.jp", "/etc/ssl/ec.cer", "量子計算機に弱い", "判定の基準と出典"} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("the report does not contain %q", want)
		}
	}
	// 同じ名前のレポートがすでにあれば、上書きしない
	if code, _, _ := run("report", "--output-dir", dir, result); code == 0 {
		t.Error("an existing report must not be overwritten")
	}
}

func TestReportRejectsBadInput(t *testing.T) {
	fx := setup(t)
	if code, _, stderr := run(fx.scanArgs()...); code != 0 {
		t.Fatalf("scan: exit %d: %s", code, stderr)
	}
	result := singleFile(t, fx.out, ".json")
	dir := filepath.Dir(fx.root) + "/report"
	// 評価ポリシーが見つからない
	if code, _, stderr := run("report", "--output-dir", dir, "--policy", "nosuch", result); code != exitFatal || !strings.Contains(stderr, "nosuch") {
		t.Errorf("unknown policy: exit %d: %s", code, stderr)
	}
	// 入力なし
	if code, _, _ := run("report", "--output-dir", dir); code != exitUsage {
		t.Errorf("no input: exit %d", code)
	}
	// このツールの結果ではないファイル
	other := filepath.Dir(fx.root) + "/other.json"
	os.WriteFile(other, []byte(`{"schema":"something-else"}`), 0o600)
	if code, _, _ := run("report", "--output-dir", dir, other); code != exitFatal {
		t.Errorf("foreign file: exit %d", code)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("no report must be written on errors, found %d files", len(entries))
	}
	// 入力が複数なら、全体の集計とホストごとの詳細をまとめた1つのレポートになる
	code, stdout, stderr := run("report", "--output-dir", dir, result, result)
	if code != 0 {
		t.Fatalf("two inputs: exit %d: %s", code, stderr)
	}
	out := singleFile(t, dir, ".html")
	if filepath.Base(out) != "kagiya-report-2hosts.html" || !strings.Contains(stdout, out) {
		t.Errorf("combined report file = %s (stdout %q)", out, stdout)
	}
	data, _ := os.ReadFile(out)
	if !bytes.Contains(data, []byte(`id="dashboard"`)) || !bytes.Contains(data, []byte(`id="host-2"`)) {
		t.Error("the combined report must have a dashboard and a view for each host")
	}
	// 混ざった入力のうち1つでも読めなければ、何も書かない
	if code, _, _ := run("report", "--output-dir", filepath.Dir(fx.root)+"/report2", result, other); code != exitFatal {
		t.Errorf("mixed inputs: exit %d", code)
	}
}

// CBOM（CycloneDX）への変換。出力は、結果と同じ名前に .cdx.json を付け、作成者だけが読める権限で作る。
func TestConvertToCBOM(t *testing.T) {
	fx := setup(t)
	if code, _, stderr := run(fx.scanArgs()...); code != 0 {
		t.Fatalf("scan: exit %d: %s", code, stderr)
	}
	result := singleFile(t, fx.out, ".json")
	dir := filepath.Dir(fx.root) + "/cbom"
	code, stdout, stderr := run("convert", "--to", "cbom", "--output-dir", dir, result)
	if code != 0 {
		t.Fatalf("convert: exit %d: %s", code, stderr)
	}
	out := singleFile(t, dir, ".cdx.json")
	if !strings.Contains(stdout, out) || filepath.Base(out) != strings.TrimSuffix(filepath.Base(result), ".json")+".cdx.json" {
		t.Errorf("stdout = %q, file = %s", stdout, filepath.Base(out))
	}
	if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", fi.Mode().Perm())
	}
	data, _ := os.ReadFile(out)
	var doc struct {
		BomFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Components  []struct {
			Type string `json:"type"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || doc.BomFormat != "CycloneDX" || doc.SpecVersion != "1.6" || len(doc.Components) == 0 {
		t.Errorf("cbom = %+v (%v)", doc, err)
	}
}

// 読み飛ばしがあったときは、終了時の 1 行に、理由ごとの件数も出す（何が起きたかを、結果のファイルを開かなくても分かるようにする）。
func TestScanSummaryShowsSkipReasons(t *testing.T) {
	fx := setup(t)
	_, _, stderr := run("scan", "--roots", fx.root+"/no-such-directory", "--output-dir", fx.out, "--log-dir", fx.logs, "--cpu-limit", "100", "--io-limit", "0")
	if !strings.Contains(stderr, "not-found: 1") {
		t.Errorf("the summary must show the reasons: %s", stderr)
	}
}

// setuid / setgid で起動された場合は、どのコマンドも実行せずに終わる（設計書 4.7）。
func TestRefusesSetIDStart(t *testing.T) {
	old := startedSetID
	startedSetID = func() bool { return true }
	defer func() { startedSetID = old }()
	fx := setup(t)
	for _, args := range [][]string{fx.scanArgs(), {"version"}, {"rules", "export", "--output-dir", filepath.Join(fx.out, "rules")}} {
		code, stdout, stderr := run(args...)
		if code != 3 || stdout != "" || !strings.Contains(stderr, "setuid") {
			t.Errorf("%v: code=%d stdout=%q stderr=%q", args[0], code, stdout, stderr)
		}
	}
	if ents, _ := os.ReadDir(fx.out); len(ents) != 0 {
		t.Errorf("nothing may be written: %v", ents)
	}
}

// スキャンは、メモリの使用量の上限（Go のソフトリミット）を設定し、結果に記録する（設計書 6 章）。
func TestScanSetsMemoryLimit(t *testing.T) {
	fx := setup(t)
	if code, _, stderr := run(fx.scanArgs()...); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr)
	}
	raw, _ := os.ReadFile(singleFile(t, fx.out, ".json"))
	var inv struct {
		Meta struct {
			Hardening struct {
				MemoryLimitMiB int64 `json:"memory_limit_mib"`
			} `json:"hardening"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(raw, &inv); err != nil {
		t.Fatal(err)
	}
	if inv.Meta.Hardening.MemoryLimitMiB != 512 {
		t.Errorf("meta.hardening.memory_limit_mib = %d, want 512", inv.Meta.Hardening.MemoryLimitMiB)
	}
	if got := debug.SetMemoryLimit(-1); got != 512<<20 {
		t.Errorf("the memory limit of the process = %d, want %d", got, 512<<20)
	}
}

// 以下は、独立したレビュー（2026-11-14）の指摘 A-6 への対応（利用者と確認して、要件から変えた点）。

// 出力先やログ先が、探索の起点と同じか、起点の上位にある場合は、何も読まずにエラーで終わる
// （出力先は探索から外すので、起点と重なると、その起点が丸ごと読まれなくなる）。
func TestScanRefusesOutputDirOverlappingRoots(t *testing.T) {
	fx := setup(t)
	for name, args := range map[string][]string{
		"output dir is a root":            {"scan", "--roots", fx.root, "--output-dir", fx.root, "--log-dir", fx.logs},
		"output dir is above a root":      {"scan", "--roots", fx.root + "/etc", "--output-dir", fx.root, "--log-dir", fx.logs},
		"log dir is a root":               {"scan", "--roots", fx.root, "--output-dir", fx.out, "--log-dir", fx.root},
		"output dir is the root of all":   {"scan", "--roots", fx.root, "--output-dir", "/", "--log-dir", fx.logs},
		"default log dir is above a root": {"scan", "--roots", fx.out + "/logs/x", "--output-dir", fx.out},
	} {
		code, _, stderr := run(args...)
		if code != 2 || !strings.Contains(stderr, "--output-dir") {
			t.Errorf("%s: code=%d stderr=%q", name, code, stderr)
		}
	}
	for _, dir := range []string{fx.out, fx.logs} {
		if _, err := os.Stat(dir); err == nil {
			t.Errorf("%s must not be created", dir)
		}
	}
	// 起点の下にある出力先は、これまでどおり使える（その場所だけを探索から外す）
	if code, _, stderr := run("scan", "--roots", fx.root, "--output-dir", fx.root+"/out", "--log-dir", fx.root+"/out/logs", "--cpu-limit", "100", "--io-limit", "0"); code != 0 {
		t.Errorf("an output directory below a root must work: code=%d stderr=%q", code, stderr)
	}
}

// --log-dir を指定しなければ、ログは出力先の下の logs/ に書く（kagiya が書く場所を、指定した 1 か所にまとめる）。
func TestScanDefaultLogDirIsUnderOutputDir(t *testing.T) {
	fx := setup(t)
	cwd := tmp(t)
	t.Chdir(cwd)
	if code, _, stderr := run("scan", "--roots", fx.root, "--output-dir", fx.out, "--cpu-limit", "100", "--io-limit", "0"); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	singleFile(t, fx.out+"/logs", ".log")
	if ents, _ := os.ReadDir(cwd); len(ents) != 0 {
		t.Errorf("nothing may be written to the current directory: %v", ents)
	}
}

// 以下は、独立したレビュー（2026-11-14）の指摘 A-4・A-5 への対応。

// スキャンは、同時に使うプロセッサの数を絞る（メモリの回収が、空いているコアをすべて使わないように）。
func TestScanLimitsParallelism(t *testing.T) {
	fx := setup(t)
	if code, _, stderr := run(fx.scanArgs()...); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr)
	}
	if got := runtime.GOMAXPROCS(0); got != 2 {
		t.Errorf("GOMAXPROCS = %d, want 2", got)
	}
	raw, _ := os.ReadFile(singleFile(t, fx.out, ".json"))
	if !bytes.Contains(raw, []byte(`"max_procs": 2`)) {
		t.Error("meta.hardening.max_procs is not recorded")
	}
}

// 1 ファイルの読み取り上限には、指定できる上限がある（大きな値を指定されると、その分のメモリを確保するため）。
func TestScanMaxFileSizeIsBounded(t *testing.T) {
	fx := setup(t)
	if code, _, _ := run(fx.scanArgs("--max-file-size", "1025")...); code != 2 {
		t.Errorf("--max-file-size 1025: code=%d, want 2", code)
	}
	if code, _, stderr := run(fx.scanArgs("--max-file-size", "1024")...); code != 0 {
		t.Errorf("--max-file-size 1024: code=%d stderr=%q", code, stderr)
	}
}

// 処理の途中で panic が起きても、そこまでの結果を「未完了」として書き出して終わる（panic の値は、どこにも出さない）。
func TestScanWritesPartialResultAfterPanic(t *testing.T) {
	fx := setup(t)
	scanHook = func(phase string) {
		if phase == "walk" {
			panic("boom " + secretMarker)
		}
	}
	defer func() { scanHook = nil }()
	code, _, stderr := run(fx.scanArgs()...)
	if code != 3 || strings.Contains(stderr, secretMarker) {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	raw, _ := os.ReadFile(singleFile(t, fx.out, ".json"))
	logRaw, _ := os.ReadFile(singleFile(t, fx.logs, ".log"))
	if !bytes.Contains(raw, []byte(`"completed": false`)) || !bytes.Contains(raw, []byte(`"incomplete_reason": "internal-error"`)) {
		t.Errorf("the result must be marked incomplete: %s", raw[:min(len(raw), 600)])
	}
	if !bytes.Contains(logRaw, []byte(`"event":"internal-error"`)) || bytes.Contains(logRaw, []byte(secretMarker)) || bytes.Contains(raw, []byte(secretMarker)) {
		t.Errorf("log: %s", logRaw)
	}
}
