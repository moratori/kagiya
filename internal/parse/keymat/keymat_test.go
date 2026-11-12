package keymat

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const dir = "../testdata/material"

// expected.tsv: 実物のツール（OpenSSL / OpenSSH）が報告した値。
func loadExpected(t *testing.T) map[string]map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, "expected.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		cols := strings.Split(sc.Text(), "\t")
		kv := map[string]string{}
		for _, c := range cols[1:] {
			k, v, _ := strings.Cut(c, "=")
			kv[k] = v
		}
		out[cols[0]] = kv
	}
	return out
}

var algOIDs = map[string]string{
	"rsa": "1.2.840.113549.1.1.1", "ec": "1.2.840.10045.2.1", "ed25519": "1.3.101.112",
	"dsa": "1.2.840.10040.4.1", "ml-dsa-65": "2.16.840.1.101.3.4.3.18",
}

func parseFile(t *testing.T, name string) ([]Item, int) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return Parse(name, data)
}

func TestKeysAgainstToolOutput(t *testing.T) {
	exp := loadExpected(t)
	tested := 0
	for name, want := range exp {
		if want["kind"] != "private-key" && want["kind"] != "public-key" {
			continue
		}
		tested++
		items, failed := parseFile(t, name)
		if failed != 0 || len(items) != 1 {
			t.Errorf("%s: got %d items, %d failures; want exactly 1 item", name, len(items), failed)
			continue
		}
		it := items[0]
		if it.Kind != want["kind"] || it.Format != want["format"] || it.Key == nil {
			t.Errorf("%s: kind=%q format=%q; want %q %q", name, it.Kind, it.Format, want["kind"], want["format"])
			continue
		}
		k := it.Key
		if a := want["alg"]; a != "" && k.AlgOID != algOIDs[a] {
			t.Errorf("%s: AlgOID=%q, want %s (%s)", name, k.AlgOID, algOIDs[a], a)
		}
		if b := want["bits"]; b != "" && strconv.Itoa(k.Bits) != b {
			t.Errorf("%s: Bits=%d, want %s", name, k.Bits, b)
		}
		if c := want["curve"]; c != "" && k.CurveOID != c {
			t.Errorf("%s: CurveOID=%q, want %s", name, k.CurveOID, c)
		}
		if e := want["encrypted"]; e != "" && strconv.FormatBool(k.Encrypted) != e {
			t.Errorf("%s: Encrypted=%v, want %s", name, k.Encrypted, e)
		}
		if s := want["sshtype"]; s != "" && k.SSHType != s {
			t.Errorf("%s: SSHType=%q, want %s", name, k.SSHType, s)
		}
		if s := want["sshfp"]; s != "" && k.SSHFingerprint != s {
			t.Errorf("%s: SSHFingerprint=%q, want %s", name, k.SSHFingerprint, s)
		}
		wantSPKI := want["spki"]
		if name == "dsa2048-pkcs8.pem" {
			// PKCS#8 の DSA 鍵は公開成分を含まない。秘密成分からの計算は行わない方針なので指紋は得られない。
			wantSPKI = ""
		}
		if extra, ok := exp[name+"+spki"]; ok {
			wantSPKI = extra["spki"] // SSH 鍵を SPKI に変換したときの指紋（ssh-keygen -e -m PKCS8 で確認）
		}
		if strings.HasPrefix(name, "ssh-") && !strings.HasSuffix(name, ".pub") {
			if extra, ok := exp[name+".pub+spki"]; ok {
				wantSPKI = extra["spki"]
			}
		}
		if k.SPKISHA256 != wantSPKI {
			if wantSPKI != "" || !strings.Contains(name, "ed25519") {
				t.Errorf("%s: SPKISHA256=%q, want %q", name, k.SPKISHA256, wantSPKI)
			}
		}
	}
	if tested < 20 {
		t.Fatalf("only %d key fixtures were tested", tested)
	}
}

func TestEncryptionMetadata(t *testing.T) {
	items, _ := parseFile(t, "rsa2048-pkcs8-enc.pem")
	if len(items) != 1 || items[0].Key.Enc == nil {
		t.Fatalf("items = %+v", items)
	}
	e := items[0].Key.Enc
	// openssl pkcs8 -topk8 -v2 aes-256-cbc -iter 4096（PRF は OpenSSL 3 の既定 hmacWithSHA256）
	if e.SchemeOID != "1.2.840.113549.1.5.13" || e.KDFOID != "1.2.840.113549.1.5.12" ||
		e.CipherOID != "2.16.840.1.101.3.4.1.42" || e.PRFOID != "1.2.840.113549.2.9" || e.Iterations != 4096 {
		t.Errorf("PBES2 metadata = %+v", e)
	}

	items, _ = parseFile(t, "rsa2048-pkcs1-enc.pem")
	if len(items) != 1 || items[0].Key.Enc == nil || items[0].Key.Enc.Name != "AES-128-CBC" || !items[0].Key.Encrypted {
		t.Errorf("legacy PEM encryption: %+v", items)
	}

	items, _ = parseFile(t, "ssh-ed25519-enc")
	if len(items) != 1 || items[0].Key.Enc == nil || items[0].Key.Enc.Name != "aes256-ctr" ||
		items[0].Key.Enc.KDFName != "bcrypt" || items[0].Key.Enc.Iterations < 1 {
		t.Errorf("OpenSSH encryption: %+v", items[0].Key.Enc)
	}
}

func TestCertificatesAndCSR(t *testing.T) {
	exp := loadExpected(t)
	for _, name := range []string{"cert-rsa.pem", "cert-rsa.der", "cert-ec.pem", "cert-mldsa65.pem", "cert-rsa-pss.pem"} {
		items, failed := parseFile(t, name)
		if failed != 0 || len(items) != 1 || items[0].Kind != "certificate" || items[0].Cert == nil {
			t.Errorf("%s: items=%d failed=%d", name, len(items), failed)
			continue
		}
		c, want := items[0].Cert, exp[name]
		if c.FingerprintSHA256 != want["sha256"] {
			t.Errorf("%s: fingerprint %s, want %s", name, c.FingerprintSHA256, want["sha256"])
		}
		if s := want["spki"]; s != "" && c.PublicKeyFingerprintSHA256 != s {
			t.Errorf("%s: SPKI fingerprint %s, want %s", name, c.PublicKeyFingerprintSHA256, s)
		}
		if s := want["sigalg"]; s != "" && c.SignatureAlgorithmOID != s {
			t.Errorf("%s: sigalg %s, want %s", name, c.SignatureAlgorithmOID, s)
		}
		if s := want["keyalg"]; s != "" && c.PublicKeyAlgorithmOID != s {
			t.Errorf("%s: keyalg %s, want %s", name, c.PublicKeyAlgorithmOID, s)
		}
	}
	items, failed := parseFile(t, "csr-rsa.pem")
	want := exp["csr-rsa.pem"]
	if failed != 0 || len(items) != 1 || items[0].Kind != "csr" || items[0].CSR == nil {
		t.Fatalf("csr: items=%+v failed=%d", items, failed)
	}
	r := items[0].CSR
	if r.Subject != want["subject"] || r.SignatureAlgorithmOID != want["sigalg"] || r.Key.SPKISHA256 != want["spki"] || r.Key.Bits != 2048 {
		t.Errorf("csr = %+v key=%+v", r, r.Key)
	}
}

func TestSSHKeyLists(t *testing.T) {
	exp := loadExpected(t)
	for _, name := range []string{"authorized_keys", "known_hosts"} {
		items, failed := parseFile(t, name)
		if failed != 0 || len(items) != 3 {
			t.Errorf("%s: %d items, %d failed; want 3 items", name, len(items), failed)
			continue
		}
		fps := map[string]bool{}
		for _, it := range items {
			if it.Kind != "public-key" || it.Format != "ssh-public" {
				t.Errorf("%s: item %+v", name, it)
			}
			fps[it.Key.SSHFingerprint] = true
		}
		for _, k := range []string{"ssh-ed25519.pub", "ssh-rsa3072.pub", "ssh-ecdsa256.pub"} {
			if !fps[exp[k]["sshfp"]] {
				t.Errorf("%s: key %s not found", name, k)
			}
		}
	}
}

// 同じファイルに証明書と秘密鍵が並んでいる場合、順番どおりに両方が得られる。
func TestMixedPEM(t *testing.T) {
	a, _ := os.ReadFile(filepath.Join(dir, "cert-ec.pem"))
	b, _ := os.ReadFile(filepath.Join(dir, "ec256-sec1.pem"))
	items, failed := Parse("server.pem", append(append(a, []byte("some text\n")...), b...))
	if failed != 0 || len(items) != 2 || items[0].Kind != "certificate" || items[1].Kind != "private-key" ||
		items[0].Index != 0 || items[1].Index != 1 {
		t.Fatalf("items=%+v failed=%d", items, failed)
	}
	// 証明書の公開鍵と秘密鍵が指紋で対応づく
	if items[0].Cert.PublicKeyFingerprintSHA256 != items[1].Key.SPKISHA256 {
		t.Error("certificate and private key fingerprints do not match")
	}
}

func TestUnknownAndBrokenInput(t *testing.T) {
	// 未知の種類の秘密鍵ブロックも「秘密鍵がある」ことは記録する
	items, failed := Parse("x.pem", []byte("-----BEGIN FOO PRIVATE KEY-----\nAAAA\n-----END FOO PRIVATE KEY-----\n"))
	if len(items) != 1 || items[0].Kind != "private-key" || items[0].Format != "unknown" || failed != 0 {
		t.Errorf("unknown private key block: %+v failed=%d", items, failed)
	}
	// 壊れた中身は失敗として数える
	_, failed = Parse("x.pem", []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
	if failed != 1 {
		t.Errorf("broken certificate: failed=%d, want 1", failed)
	}
	// 関係のないファイル
	if items, failed := Parse("notes.txt", []byte("hello world\n")); len(items) != 0 || failed != 0 {
		t.Errorf("plain text: %+v %d", items, failed)
	}
	if items, failed := Parse("empty.pem", nil); len(items) != 0 || failed != 0 {
		t.Errorf("empty: %+v %d", items, failed)
	}
}

// 途中で切れた入力・壊れた入力で panic しない。
func TestNeverPanics(t *testing.T) {
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		data, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		step := len(data)/200 + 1
		for i := 0; i < len(data); i += step {
			Parse(e.Name(), data[:i])
			m := append([]byte(nil), data...)
			m[i] ^= 0x5a
			Parse(e.Name(), m)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, n := range []string{"rsa2048-pkcs8.der", "ssh-ed25519", "ssh-rsa3072.pub", "rsa2048-pkcs8-enc.pem", "csr-rsa.pem"} {
		b, _ := os.ReadFile(filepath.Join(dir, n))
		f.Add(n, b)
	}
	f.Fuzz(func(t *testing.T, name string, b []byte) { Parse(name, b) })
}
