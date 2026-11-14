package keystore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
)

// 以下の形式は、検証ラボで実物の Bouncy Castle（bcprov-jdk18on 1.87）と keytool で作ったキーストアで確かめたもの:
//   BKS  : 版（4 バイト。2）、ソルトの長さと中身、反復回数、エントリの並び（種類 1 バイト、別名、日時、証明書チェーン、中身）、0、HMAC-SHA1（20 バイト）。
//          証明書のエントリは暗号化されていない。鍵のエントリ（種類 4）は暗号化されている。
//   UBER : 版（1）、ソルト、反復回数の後ろは、全体が暗号化されている。
//   BCFKS: ASN.1。先頭は PBES2 で暗号化されたデータで、証明書を含めて全体が暗号化されている。

func testCert(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "lab.test"}, NotBefore: time.Unix(1700000000, 0), NotAfter: time.Unix(1800000000, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

type bksBuilder struct{ bytes.Buffer }

func (b *bksBuilder) u32(v uint32) { binary.Write(&b.Buffer, binary.BigEndian, v) }
func (b *bksBuilder) utf(s string) {
	binary.Write(&b.Buffer, binary.BigEndian, uint16(len(s)))
	b.WriteString(s)
}
func (b *bksBuilder) cert(der []byte) { b.utf("X.509"); b.u32(uint32(len(der))); b.Write(der) }
func (b *bksBuilder) header(version uint32) {
	b.u32(version)
	b.u32(20)
	b.Write(bytes.Repeat([]byte{0xab}, 20))
	b.u32(1833)
}
func (b *bksBuilder) entry(kind byte, alias string, chain [][]byte) {
	b.WriteByte(kind)
	b.utf(alias)
	b.Write(make([]byte, 8))
	b.u32(uint32(len(chain)))
	for _, c := range chain {
		b.cert(c)
	}
}

func TestBKS(t *testing.T) {
	der := testCert(t)
	var b bksBuilder
	b.header(2)
	b.entry(1, "ca", nil)
	b.cert(der)
	b.entry(4, "server", [][]byte{der})
	b.u32(64)
	b.Write(bytes.Repeat([]byte{0x5a}, 64)) // 暗号化された鍵
	b.entry(4, "secret", nil)
	b.u32(32)
	b.Write(bytes.Repeat([]byte{0x5a}, 32))
	b.WriteByte(0)
	b.Write(make([]byte, 20)) // HMAC
	s, ok := Parse(b.Bytes())
	if !ok || s.Format != "bks" {
		t.Fatalf("format: ok=%v %+v", ok, s)
	}
	if s.Entries.TrustedCerts != 1 || s.Entries.PrivateKeys != 1 || s.Entries.SecretKeys != 1 || len(s.Certs) != 2 || s.Truncated {
		t.Errorf("entries = %+v certs=%d truncated=%v", s.Entries, len(s.Certs), s.Truncated)
	}
	if !s.Opaque || s.MAC == nil || s.MAC.Name != "hmac-sha1" || s.MAC.Iterations != 1833 {
		t.Errorf("opaque=%v mac=%+v", s.Opaque, s.MAC)
	}
	// 途中で切れている場合は、読めたところまで
	cut, ok := Parse(b.Bytes()[:b.Len()-60])
	if !ok || !cut.Truncated || cut.Entries.TrustedCerts != 1 {
		t.Errorf("truncated: ok=%v %+v", ok, cut)
	}
	// 版 1 の BKS（古い Bouncy Castle）も、エントリの並びが読めれば BKS
	var v1 bksBuilder
	v1.header(1)
	v1.entry(1, "ca", nil)
	v1.cert(der)
	v1.WriteByte(0)
	v1.Write(make([]byte, 20))
	if s, ok := Parse(v1.Bytes()); !ok || s.Format != "bks" || len(s.Certs) != 1 {
		t.Errorf("version 1: ok=%v %+v", ok, s)
	}
}

func TestUBER(t *testing.T) {
	var b bksBuilder
	b.header(1)
	// 実物の UBER の、反復回数の後ろの並び（暗号化されている）
	enc, _ := hex.DecodeString("7b5a527b39e01cc8190ade1200107870")
	b.Write(enc)
	b.Write(bytes.Repeat([]byte{0xc3, 0x17, 0x9e, 0x44}, 200))
	s, ok := Parse(b.Bytes())
	if !ok || s.Format != "uber" || !s.Opaque || len(s.Certs) != 0 || s.Entries != (Entries{}) {
		t.Errorf("uber: ok=%v %+v", ok, s)
	}
}

func TestBCFKS(t *testing.T) {
	// 実物の BCFKS の先頭 48 バイト（PBES2 と PBKDF2 の識別子まで）。長さの欄を、この短いデータに合わせて作り直す
	inner, _ := hex.DecodeString("300b06092a864886f70d01050d")                                  // AlgorithmIdentifier { pbes2 }（引数は省いた形）
	enc := append(append([]byte{0x30, byte(len(inner) + 6)}, inner...), 0x04, 0x04, 1, 2, 3, 4) // EncryptedObjectStoreData { アルゴリズム, 暗号文 }
	check := []byte{0x30, 0x02, 0x05, 0x00}                                                     // ObjectStoreIntegrityCheck（中身は見ない）
	data := append(append([]byte{0x30, byte(len(enc) + len(check))}, enc...), check...)
	s, ok := Parse(data)
	if !ok || s.Format != "bcfks" || !s.Opaque || len(s.Certs) != 0 {
		t.Errorf("bcfks: ok=%v %+v", ok, s)
	}
}

// 似た始まりの、キーストアではないデータを、キーストアと取り違えない。
func TestNotBouncyCastle(t *testing.T) {
	for name, data := range map[string][]byte{
		"zeros":            make([]byte, 64),
		"version only":     {0, 0, 0, 2},
		"huge salt":        append([]byte{0, 0, 0, 2, 0x7f, 0xff, 0xff, 0xff}, make([]byte, 64)...),
		"zero salt":        append([]byte{0, 0, 0, 2, 0, 0, 0, 0}, make([]byte, 64)...),
		"version 2 random": append([]byte{0, 0, 0, 2, 0, 0, 0, 20}, bytes.Repeat([]byte{0x99}, 100)...),
		"version 3":        append([]byte{0, 0, 0, 3, 0, 0, 0, 20}, make([]byte, 64)...),
		"short version 1":  append([]byte{0, 0, 0, 1, 0, 0, 0, 20}, make([]byte, 20)...),
	} {
		if s, ok := Parse(data); ok {
			t.Errorf("%s: taken as %s", name, s.Format)
		}
	}
}
