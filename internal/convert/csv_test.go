package convert

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"

	"kagiya/internal/model"
)

func sample() *model.Inventory {
	yes := true
	return &model.Inventory{
		Schema: model.Schema,
		Meta: model.Meta{ScanID: "abc", StartedAt: "2026-11-12T00:00:00Z",
			Host: model.Host{Hostname: "host1", OS: "linux"}, Labels: map[string]string{"system": "勘定系", "owner": "infra"}},
		Assets: []model.Asset{
			{ID: "alg:rsa-2048", Type: "algorithm", Algorithm: &model.Algorithm{Family: "RSA", Primitive: "public-key", KeyBits: 2048, Known: true}},
			{ID: "alg:sha256-with-rsa", Type: "algorithm", Algorithm: &model.Algorithm{Family: "RSA", Primitive: "signature", Known: true}},
			{ID: "cert:sha256:aa", Type: "certificate", Certificate: &model.Certificate{
				Subject: "CN==cmd|' /C calc'!A0, O=日本語", Issuer: "CN=ca", NotBefore: "2025-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z",
				SignatureAlgorithm: "alg:sha256-with-rsa", PublicKey: model.PublicKey{Algorithm: "alg:rsa-2048"}, FingerprintSHA256: "aa"}},
			{ID: "key:private:spki-sha256:bb", Type: "private-key", Key: &model.Key{Algorithm: "alg:rsa-2048", PublicFingerprintSHA256: "bb"}},
			{ID: "keystore:loc:cc", Type: "keystore", Keystore: &model.Keystore{Format: "pkcs12", Unreadable: true, Entries: map[string]int{"private_keys": 1}}},
		},
		Occurrences: []model.Occurrence{
			{ID: "occ:1", Asset: "cert:sha256:aa", Collector: "fscrawl", State: "present", Confidence: "high",
				Location: model.Location{Kind: "file", Path: "/etc/ssl/a.pem"}},
			{ID: "occ:2", Asset: "key:private:spki-sha256:bb", Collector: "fscrawl", State: "present", Confidence: "high",
				Location: model.Location{Kind: "file", Path: "=HYPERLINK(\"http://evil\")", Index: 1},
				Detail:   &model.Detail{Format: "pkcs8-encrypted", Encrypted: &yes, Protection: &model.Protection{Cipher: "alg:aes-256-cbc", Iterations: 4096}}},
			{ID: "occ:3", Asset: "cert:sha256:aa", Collector: "fscrawl", State: "present", Confidence: "high",
				Location: model.Location{Kind: "file", Path: "/opt/app/store.jks", Container: "jks", Index: 2}},
			{ID: "occ:4", Asset: "keystore:loc:cc", Collector: "fscrawl", State: "present", Confidence: "high",
				Location: model.Location{Kind: "file", Path: "/opt/app/a.p12"}, Detail: &model.Detail{Format: "pkcs12"}},
		},
	}
}

func rows(t *testing.T, bom bool) ([][]string, []byte) {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteCSV(sample(), &buf, bom); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	r := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))))
	out, err := r.ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v", err)
	}
	return out, raw
}

func TestCSVRows(t *testing.T) {
	out, _ := rows(t, false)
	if len(out) != 5 {
		t.Fatalf("got %d rows, want header + 4 occurrences", len(out))
	}
	col := map[string]int{}
	for i, h := range out[0] {
		col[h] = i
	}
	for _, h := range []string{"hostname", "scan_started_at", "labels", "asset_type", "asset_id", "algorithm", "key_bits", "subject", "issuer",
		"not_after", "signature_algorithm", "format", "encrypted", "protection_cipher", "protection_iterations",
		"state", "confidence", "collector", "path", "container", "index"} {
		if _, ok := col[h]; !ok {
			t.Errorf("column %q missing; header = %v", h, out[0])
		}
	}
	get := func(row int, name string) string { return out[row][col[name]] }

	// 証明書: 公開鍵のアルゴリズムと鍵長、署名アルゴリズム、期限
	if get(1, "hostname") != "host1" || get(1, "asset_type") != "certificate" || get(1, "algorithm") != "rsa-2048" ||
		get(1, "key_bits") != "2048" || get(1, "signature_algorithm") != "sha256-with-rsa" ||
		get(1, "not_after") != "2027-01-01T00:00:00Z" || get(1, "path") != "/etc/ssl/a.pem" || get(1, "issuer") != "CN=ca" {
		t.Errorf("certificate row = %v", out[1])
	}
	if get(1, "labels") != "owner=infra; system=勘定系" {
		t.Errorf("labels = %q", get(1, "labels"))
	}
	// 秘密鍵
	if get(2, "asset_type") != "private-key" || get(2, "algorithm") != "rsa-2048" || get(2, "encrypted") != "true" ||
		get(2, "format") != "pkcs8-encrypted" || get(2, "protection_cipher") != "aes-256-cbc" || get(2, "protection_iterations") != "4096" || get(2, "index") != "1" {
		t.Errorf("private key row = %v", out[2])
	}
	// キーストアの中の証明書
	if get(3, "container") != "jks" || get(3, "index") != "2" {
		t.Errorf("row in keystore = %v", out[3])
	}
	if get(4, "asset_type") != "keystore" || get(4, "format") != "pkcs12" {
		t.Errorf("keystore row = %v", out[4])
	}
	// 暗号化の有無が意味を持たない行は空欄
	if get(1, "encrypted") != "" {
		t.Errorf("encrypted for a certificate = %q, want empty", get(1, "encrypted"))
	}
}

// 表計算ソフトで開いたときに数式として実行されないよう、= + - @ で始まるセルを無害化する。
func TestCSVFormulaInjectionIsNeutralised(t *testing.T) {
	out, _ := rows(t, false)
	for _, row := range out[1:] {
		for _, cell := range row {
			if cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
				t.Errorf("cell starts with a formula character: %q", cell)
			}
		}
	}
	joined := strings.Join(out[2], "|")
	if !strings.Contains(joined, "'=HYPERLINK") {
		t.Errorf("formula-like path must be kept but prefixed with an apostrophe: %v", out[2])
	}
	if !strings.Contains(strings.Join(out[1], "|"), "CN==cmd") {
		t.Errorf("a value that merely contains '=' must be left as is: %v", out[1])
	}
}

func TestCSVByteOrderMark(t *testing.T) {
	_, with := rows(t, true)
	_, without := rows(t, false)
	if !bytes.HasPrefix(with, []byte("\xef\xbb\xbf")) {
		t.Error("BOM missing")
	}
	if bytes.HasPrefix(without, []byte("\xef\xbb\xbf")) {
		t.Error("unexpected BOM")
	}
	if !bytes.Contains(with, []byte("日本語")) {
		t.Error("non-ASCII text must be written as UTF-8")
	}
}

func TestCSVEmptyInventory(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCSV(&model.Inventory{Schema: model.Schema}, &buf, false); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(buf.String(), "\n"); n != 1 {
		t.Errorf("empty inventory must produce the header only, got %d lines", n)
	}
}

// 独立したレビュー（2026-11-14）の指摘 C-3。数式として解釈されうる先頭の文字は、全角のもの（日本語環境の表計算ソフト）と、
// 先頭の空白の後ろにあるものも対象にする。
func TestNeutraliseFullWidthAndLeadingSpace(t *testing.T) {
	for _, s := range []string{"＝HYPERLINK(\"http://x\")", "＋1+1", "－1", "＠SUM(A1)", " =1+1", "　＝x", "\t=1", "  @x", "=1", "+1", "-1", "@a"} {
		if got := neutralise(s); got != "'"+s {
			t.Errorf("neutralise(%q) = %q, want an apostrophe in front", s, got)
		}
	}
	for _, s := range []string{"CN==cmd", "normal", "日本語のパス", "/etc/ssl/a=b.pem", "", " plain text", "1-2"} {
		if got := neutralise(s); got != s {
			t.Errorf("neutralise(%q) = %q, want unchanged", s, got)
		}
	}
}
