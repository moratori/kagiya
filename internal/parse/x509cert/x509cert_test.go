package x509cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
)

func makeCert(t *testing.T, key crypto.Signer, tmpl *x509.Certificate) []byte {
	t.Helper()
	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = big.NewInt(0x1234abcd)
	}
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
		tmpl.NotAfter = time.Date(2035, 6, 7, 8, 9, 10, 0, time.UTC)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParseRSACertificate(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	raw := makeCert(t, key, &x509.Certificate{
		Subject: pkix.Name{Country: []string{"JP"}, Organization: []string{"Example, Inc."}, CommonName: "www.example.co.jp"},
	})
	c, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != `C=JP, O=Example\, Inc., CN=www.example.co.jp` {
		t.Errorf("Subject = %q", c.Subject)
	}
	if c.Issuer != c.Subject || !c.SelfSigned {
		t.Errorf("Issuer = %q, SelfSigned = %v", c.Issuer, c.SelfSigned)
	}
	if c.SerialHex != "1234abcd" {
		t.Errorf("SerialHex = %q", c.SerialHex)
	}
	if !c.NotBefore.Equal(time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)) || !c.NotAfter.Equal(time.Date(2035, 6, 7, 8, 9, 10, 0, time.UTC)) {
		t.Errorf("validity = %v .. %v", c.NotBefore, c.NotAfter)
	}
	if c.SignatureAlgorithmOID != "1.2.840.113549.1.1.11" {
		t.Errorf("SignatureAlgorithmOID = %q", c.SignatureAlgorithmOID)
	}
	if c.PublicKeyAlgorithmOID != "1.2.840.113549.1.1.1" || c.RSABits != 2048 || c.CurveOID != "" {
		t.Errorf("key: alg=%q bits=%d curve=%q", c.PublicKeyAlgorithmOID, c.RSABits, c.CurveOID)
	}
	if c.IsCA {
		t.Error("IsCA = true for a leaf certificate")
	}
	sum := sha256.Sum256(raw)
	if c.FingerprintSHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("FingerprintSHA256 = %q", c.FingerprintSHA256)
	}
	std, _ := x509.ParseCertificate(raw)
	spki := sha256.Sum256(std.RawSubjectPublicKeyInfo)
	if c.PublicKeyFingerprintSHA256 != hex.EncodeToString(spki[:]) {
		t.Errorf("PublicKeyFingerprintSHA256 = %q", c.PublicKeyFingerprintSHA256)
	}
}

func TestParseECDSACACertificate(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	raw := makeCert(t, key, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "日本語 CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		NotBefore:             time.Date(2049, 12, 31, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2060, 1, 1, 0, 0, 0, 0, time.UTC), // 2050年以降は GeneralizedTime
	})
	c, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "CN=日本語 CA" {
		t.Errorf("Subject = %q", c.Subject)
	}
	if c.PublicKeyAlgorithmOID != "1.2.840.10045.2.1" || c.CurveOID != "1.3.132.0.34" || c.RSABits != 0 {
		t.Errorf("key: alg=%q curve=%q bits=%d", c.PublicKeyAlgorithmOID, c.CurveOID, c.RSABits)
	}
	if c.SignatureAlgorithmOID != "1.2.840.10045.4.3.3" {
		t.Errorf("SignatureAlgorithmOID = %q", c.SignatureAlgorithmOID)
	}
	if !c.IsCA {
		t.Error("IsCA = false for a CA certificate")
	}
	if c.NotBefore.Year() != 2049 || c.NotAfter.Year() != 2060 {
		t.Errorf("validity = %v .. %v", c.NotBefore, c.NotAfter)
	}
}

func TestParseEd25519Certificate(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	raw := makeCert(t, key, &x509.Certificate{Subject: pkix.Name{CommonName: "ed"}})
	c, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicKeyAlgorithmOID != "1.3.101.112" || c.SignatureAlgorithmOID != "1.3.101.112" {
		t.Errorf("alg: key=%q sig=%q", c.PublicKeyAlgorithmOID, c.SignatureAlgorithmOID)
	}
}

func TestParseIssuerDiffersFromSubject(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	raw, err := x509.CreateCertificate(rand.Reader, leaf, ca, leafKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "CN=leaf" || c.Issuer != "CN=ca" || c.SelfSigned {
		t.Errorf("subject=%q issuer=%q selfSigned=%v", c.Subject, c.Issuer, c.SelfSigned)
	}
}

// 壊れた入力・途中で切れた入力でも panic せず、エラーを返す。
func TestParseNeverPanicsOnTruncatedOrCorruptInput(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw := makeCert(t, key, &x509.Certificate{Subject: pkix.Name{CommonName: "x"}})
	for i := 0; i < len(raw); i++ {
		if _, err := Parse(raw[:i]); err == nil {
			t.Fatalf("truncated input of %d bytes parsed without error", i)
		}
	}
	for i := 0; i < len(raw); i++ {
		mutated := append([]byte(nil), raw...)
		mutated[i] ^= 0xff
		Parse(mutated) // 結果は問わない（panic しないこと）
	}
	for _, in := range [][]byte{nil, {0x30, 0x00}, []byte("-----BEGIN CERTIFICATE-----")} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) must fail", in)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x05})
	f.Fuzz(func(t *testing.T, b []byte) { Parse(b) })
}
