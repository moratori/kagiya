package keystore

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const dir = "../testdata/material"

func expected(t *testing.T) map[string]map[string]string {
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

func load(t *testing.T, name string) *Store {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	s, ok := Parse(data)
	if !ok {
		t.Fatalf("%s: not recognised as a keystore", name)
	}
	return s
}

// OID の名前は、実物の OpenSSL 3.5.7 が同じファイルについて報告した内容（testdata の pkcs12-info.txt）と対応する。
const (
	oidSHA256      = "2.16.840.1.101.3.4.2.1"
	oidSHA1        = "1.3.14.3.2.26"
	oidPBES2       = "1.2.840.113549.1.5.13"
	oidPBKDF2      = "1.2.840.113549.1.5.12"
	oidAES256CBC   = "2.16.840.1.101.3.4.1.42"
	oidHMACSHA256  = "1.2.840.113549.2.9"
	oidPBESHA1RC2  = "1.2.840.113549.1.12.1.6" // pbeWithSHA1And40BitRC2-CBC
	oidPBESHA13DES = "1.2.840.113549.1.12.1.3" // pbeWithSHA1And3-KeyTripleDES-CBC
)

// modern.p12: "MAC: sha256, Iteration 2048 / PKCS7 Encrypted data: PBES2, PBKDF2, AES-256-CBC, Iteration 2048, PRF hmacWithSHA256 /
// PKCS7 Data / Shrouded Keybag: PBES2, PBKDF2, AES-256-CBC, Iteration 2048, PRF hmacWithSHA256"
func TestPKCS12Modern(t *testing.T) {
	s := load(t, "modern.p12")
	if s.Format != "pkcs12" || s.MAC == nil || s.MAC.DigestOID != oidSHA256 || s.MAC.Iterations != 2048 {
		t.Fatalf("format=%s mac=%+v", s.Format, s.MAC)
	}
	if len(s.Containers) != 2 || !s.Containers[0].Encrypted || s.Containers[1].Encrypted {
		t.Fatalf("containers = %+v", s.Containers)
	}
	e := s.Containers[0].Enc
	if e == nil || e.SchemeOID != oidPBES2 || e.KDFOID != oidPBKDF2 || e.CipherOID != oidAES256CBC || e.PRFOID != oidHMACSHA256 || e.Iterations != 2048 {
		t.Errorf("certificate container protection = %+v", e)
	}
	if len(s.KeyProtections) != 1 || s.KeyProtections[0].SchemeOID != oidPBES2 || s.KeyProtections[0].CipherOID != oidAES256CBC || s.KeyProtections[0].Iterations != 2048 {
		t.Errorf("key protections = %+v", s.KeyProtections)
	}
	if s.Entries.PrivateKeys != 1 || len(s.Certs) != 0 || !s.Opaque {
		t.Errorf("entries=%+v certs=%d opaque=%v; certificates are encrypted and must be reported as unreadable", s.Entries, len(s.Certs), s.Opaque)
	}
}

// legacy.p12: "MAC: sha1, Iteration 2048 / PKCS7 Encrypted data: pbeWithSHA1And40BitRC2-CBC, Iteration 2048 /
// Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2048"
func TestPKCS12Legacy(t *testing.T) {
	s := load(t, "legacy.p12")
	if s.MAC == nil || s.MAC.DigestOID != oidSHA1 || s.MAC.Iterations != 2048 {
		t.Errorf("mac = %+v", s.MAC)
	}
	if len(s.Containers) != 2 || s.Containers[0].Enc == nil || s.Containers[0].Enc.SchemeOID != oidPBESHA1RC2 || s.Containers[0].Enc.Iterations != 2048 {
		t.Errorf("containers = %+v", s.Containers)
	}
	if len(s.KeyProtections) != 1 || s.KeyProtections[0].SchemeOID != oidPBESHA13DES || s.KeyProtections[0].Iterations != 2048 {
		t.Errorf("key protections = %+v", s.KeyProtections)
	}
}

// plaincert.p12: 証明書は暗号化されていない（PKCS7 Data / Certificate bag）ので、パスワードなしで読める。
func TestPKCS12PlainCertificate(t *testing.T) {
	s := load(t, "plaincert.p12")
	want := expected(t)["plaincert.p12"]["certsha256"]
	if len(s.Certs) != 1 || s.Certs[0].FingerprintSHA256 != want {
		t.Fatalf("certs = %d, want the certificate %s", len(s.Certs), want)
	}
	if s.Entries.PrivateKeys != 1 || s.Entries.Certificates != 1 || s.Opaque {
		t.Errorf("entries=%+v opaque=%v", s.Entries, s.Opaque)
	}
	for _, c := range s.Containers {
		if c.Encrypted {
			t.Errorf("unexpected encrypted container: %+v", c)
		}
	}
}

// keytool（Temurin 21）が作った PKCS#12。
func TestPKCS12Keytool(t *testing.T) {
	s := load(t, "store-keytool.p12")
	if s.Format != "pkcs12" || s.MAC == nil || s.MAC.Iterations < 1 || !s.Opaque {
		t.Errorf("format=%s mac=%+v opaque=%v", s.Format, s.MAC, s.Opaque)
	}
	if len(s.KeyProtections) != 1 || s.KeyProtections[0].SchemeOID != oidPBES2 || s.KeyProtections[0].Iterations < 1 {
		t.Errorf("key protections = %+v", s.KeyProtections)
	}
}

func TestJKSAndJCEKS(t *testing.T) {
	exp := expected(t)
	ecCert := exp["cert-ec.pem"]["sha256"]
	for _, name := range []string{"store.jks", "store.jceks"} {
		s := load(t, name)
		want := exp[name]
		if s.Format != want["format"] {
			t.Errorf("%s: format = %s", name, s.Format)
		}
		if s.Entries.PrivateKeys != 1 || s.Entries.TrustedCerts != 1 {
			t.Errorf("%s: entries = %+v", name, s.Entries)
		}
		fps := map[string]bool{}
		for _, c := range s.Certs {
			fps[c.FingerprintSHA256] = true
		}
		// keytool -list -v が報告した鍵エントリの証明書と、取り込んだ信頼済み証明書
		if !fps[want["keycertsha256"]] || !fps[ecCert] || len(s.Certs) != 2 {
			t.Errorf("%s: certificates %v; want %s and %s", name, fps, want["keycertsha256"], ecCert)
		}
		if len(s.KeyProtections) != 1 || s.KeyProtections[0].SchemeOID == "" {
			t.Errorf("%s: key protections = %+v", name, s.KeyProtections)
		}
		t.Logf("%s: key protection OID = %s", name, s.KeyProtections[0].SchemeOID)
		if s.MAC == nil || s.MAC.Name == "" {
			t.Errorf("%s: integrity = %+v", name, s.MAC)
		}
		if s.Opaque {
			t.Errorf("%s: certificates in JKS/JCEKS are readable without a password", name)
		}
	}
}

func TestNotAKeystore(t *testing.T) {
	for _, name := range []string{"cert-rsa.der", "rsa2048-pkcs8.der", "cert-rsa.pem", "bundle-der.p7b"} {
		data, _ := os.ReadFile(filepath.Join(dir, name))
		if _, ok := Parse(data); ok {
			t.Errorf("%s was recognised as a keystore", name)
		}
	}
	if _, ok := Parse(nil); ok {
		t.Error("empty input recognised as a keystore")
	}
}

func TestNeverPanics(t *testing.T) {
	for _, name := range []string{"modern.p12", "legacy.p12", "plaincert.p12", "store-keytool.p12", "store.jks", "store.jceks"} {
		data, _ := os.ReadFile(filepath.Join(dir, name))
		step := len(data)/300 + 1
		for i := 0; i < len(data); i += step {
			Parse(data[:i])
			m := append([]byte(nil), data...)
			m[i] ^= 0xa5
			Parse(m)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, n := range []string{"modern.p12", "store.jks", "store.jceks"} {
		b, _ := os.ReadFile(filepath.Join(dir, n))
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) { Parse(b) })
}
