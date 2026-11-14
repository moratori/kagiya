// Package keystore はキーストア（PKCS#12、JKS、JCEKS）から、パスワードなしで読める情報だけを取り出す。
// パスワードを使った復号は一切行わない。暗号化されていて読めない部分があることは Opaque で示す。
package keystore

import (
	"encoding/binary"

	"kagiya/internal/parse/der"
	"kagiya/internal/parse/keymat"
	"kagiya/internal/parse/x509cert"
)

type Store struct {
	Format         string // pkcs12 | jks | jceks | bks | uber | bcfks
	MAC            *MAC   // 完全性保護
	Entries        Entries
	Containers     []Container         // PKCS#12 の区画（暗号化の有無と方式）
	KeyProtections []keymat.Encryption // 秘密鍵エントリの保護方式（重複は除く）
	Certs          []*x509cert.Certificate
	Opaque         bool // 暗号化されていて中身を確認できない部分がある
	Truncated      bool // 途中までしか読めなかった
}

type MAC struct {
	DigestOID  string
	Name       string // OID を持たない方式の名前
	Iterations int
}

type Entries struct {
	PrivateKeys  int
	TrustedCerts int // JKS / JCEKS の信頼済み証明書エントリ
	Certificates int // PKCS#12 の証明書バッグ（読めたもの）
	SecretKeys   int
	Other        int
}

type Container struct {
	Encrypted bool
	Enc       *keymat.Encryption
}

const (
	jksMagic   = 0xFEEDFEED
	jceksMagic = 0xCECECECE

	oidData          = "1.2.840.113549.1.7.1"
	oidEncryptedData = "1.2.840.113549.1.7.6"
	oidKeyBag        = "1.2.840.113549.1.12.10.1.1"
	oidShroudedKey   = "1.2.840.113549.1.12.10.1.2"
	oidCertBag       = "1.2.840.113549.1.12.10.1.3"
	oidSecretBag     = "1.2.840.113549.1.12.10.1.5"
	oidSafeContents  = "1.2.840.113549.1.12.10.1.6"

	maxEntries = 100_000
	maxNesting = 8
)

// Parse はキーストアを読む。キーストアでなければ ok=false。
func Parse(data []byte) (*Store, bool) {
	if len(data) >= 12 {
		switch binary.BigEndian.Uint32(data) {
		case jksMagic:
			return parseJKS(data, "jks")
		case jceksMagic:
			return parseJKS(data, "jceks")
		}
	}
	if len(data) > 0 && data[0] == 0x30 {
		if s, ok := parsePKCS12(data); ok {
			return s, true
		}
		return parseBCFKS(data)
	}
	return parseBouncyCastle(data)
}

func isSeq(e der.Element) bool {
	return e.Class == der.ClassUniversal && e.Tag == der.TagSequence && e.Constructed
}

func seqChildren(e der.Element) ([]der.Element, bool) {
	if !isSeq(e) {
		return nil, false
	}
	kids, err := der.Children(e.Content)
	return kids, err == nil
}

func oidOf(e der.Element) string {
	if e.Class != der.ClassUniversal || e.Tag != der.TagOID {
		return ""
	}
	s, _ := der.OID(e.Content)
	return s
}

// explicit は [0] EXPLICIT の中身を1要素として読む。
func explicit(e der.Element) (der.Element, bool) {
	if e.Class != der.ClassContext || e.Tag != 0 || !e.Constructed {
		return der.Element{}, false
	}
	inner, rest, err := der.Read(e.Content)
	return inner, err == nil && len(rest) == 0
}

func (s *Store) addKeyProtection(enc keymat.Encryption) {
	for _, p := range s.KeyProtections {
		if p == enc {
			return
		}
	}
	s.KeyProtections = append(s.KeyProtections, enc)
}

// ---- PKCS#12 ----

func parsePKCS12(data []byte) (*Store, bool) {
	pfx, rest, err := der.Read(data)
	if err != nil || len(rest) != 0 {
		return nil, false
	}
	kids, ok := seqChildren(pfx)
	if !ok || len(kids) < 2 || kids[0].Tag != der.TagInteger || len(kids[0].Content) != 1 || kids[0].Content[0] != 3 {
		return nil, false
	}
	auth, ok := seqChildren(kids[1])
	if !ok || len(auth) != 2 || oidOf(auth[0]) != oidData {
		return nil, false
	}
	inner, ok := explicit(auth[1])
	if !ok {
		return nil, false
	}
	safeBytes, err := der.OctetString(inner)
	if err != nil {
		return nil, false
	}
	safe, rest, err := der.Read(safeBytes)
	if err != nil || len(rest) != 0 {
		return nil, false
	}
	infos, ok := seqChildren(safe)
	if !ok {
		return nil, false
	}
	s := &Store{Format: "pkcs12"}
	for _, ci := range infos {
		parts, ok := seqChildren(ci)
		if !ok || len(parts) < 1 {
			s.Truncated = true
			continue
		}
		switch oidOf(parts[0]) {
		case oidData:
			s.Containers = append(s.Containers, Container{})
			if len(parts) < 2 {
				continue
			}
			if o, ok := explicit(parts[1]); ok {
				if b, err := der.OctetString(o); err == nil {
					s.safeContents(b, 0)
					continue
				}
			}
			s.Truncated = true
		case oidEncryptedData:
			c := Container{Encrypted: true}
			s.Opaque = true
			// EncryptedData ::= SEQUENCE { version, EncryptedContentInfo { contentType, algorithm, [0] content } }
			if len(parts) >= 2 {
				if ed, ok := explicit(parts[1]); ok {
					if f, ok := seqChildren(ed); ok && len(f) >= 2 {
						if eci, ok := seqChildren(f[1]); ok && len(eci) >= 2 {
							if enc, ok := keymat.ParsePBE(eci[1]); ok {
								c.Enc = &enc
							}
						}
					}
				}
			}
			s.Containers = append(s.Containers, c)
		default: // 公開鍵で暗号化された区画など
			s.Opaque = true
			s.Containers = append(s.Containers, Container{Encrypted: true})
		}
	}
	if len(kids) >= 3 {
		s.MAC = parseMacData(kids[2])
	}
	return s, true
}

// MacData ::= SEQUENCE { mac DigestInfo { algorithm, digest }, salt, iterations DEFAULT 1 }
func parseMacData(e der.Element) *MAC {
	f, ok := seqChildren(e)
	if !ok || len(f) < 2 {
		return nil
	}
	di, ok := seqChildren(f[0])
	if !ok || len(di) != 2 {
		return nil
	}
	oid, _, err := x509cert.AlgorithmIdentifier(di[0])
	if err != nil {
		return nil
	}
	m := &MAC{DigestOID: oid, Iterations: 1}
	if len(f) >= 3 && f[2].Tag == der.TagInteger && len(f[2].Content) > 0 && len(f[2].Content) <= 4 && f[2].Content[0]&0x80 == 0 {
		n := 0
		for _, c := range f[2].Content {
			n = n<<8 | int(c)
		}
		m.Iterations = n
	}
	return m
}

func (s *Store) safeContents(b []byte, depth int) {
	sc, rest, err := der.Read(b)
	if err != nil || len(rest) != 0 || depth > maxNesting {
		s.Truncated = true
		return
	}
	bags, ok := seqChildren(sc)
	if !ok {
		s.Truncated = true
		return
	}
	for _, bag := range bags {
		f, ok := seqChildren(bag)
		if !ok || len(f) < 2 {
			s.Truncated = true
			continue
		}
		val, ok := explicit(f[1])
		if !ok {
			s.Truncated = true
			continue
		}
		switch oidOf(f[0]) {
		case oidKeyBag: // 暗号化されていない秘密鍵。中身には触れない。
			s.Entries.PrivateKeys++
		case oidShroudedKey:
			s.Entries.PrivateKeys++
			if epki, ok := seqChildren(val); ok && len(epki) == 2 {
				if enc, ok := keymat.ParsePBE(epki[0]); ok {
					s.addKeyProtection(enc)
				}
			}
		case oidCertBag:
			// CertBag ::= SEQUENCE { certId, [0] EXPLICIT OCTET STRING }
			if cb, ok := seqChildren(val); ok && len(cb) == 2 {
				if o, ok := explicit(cb[1]); ok {
					if raw, err := der.OctetString(o); err == nil {
						if c, err := x509cert.Parse(raw); err == nil && len(s.Certs) < maxEntries {
							s.Certs = append(s.Certs, c)
							s.Entries.Certificates++
							continue
						}
					}
				}
			}
			s.Entries.Other++
		case oidSecretBag:
			s.Entries.SecretKeys++
		case oidSafeContents:
			s.safeContents(val.Raw, depth+1)
		default:
			s.Entries.Other++
		}
	}
}

// ---- JKS / JCEKS ----

type reader struct {
	b   []byte
	bad bool
}

func (r *reader) take(n int) []byte {
	if r.bad || n < 0 || n > len(r.b) {
		r.bad = true
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u16() int {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return int(binary.BigEndian.Uint16(b))
}

func (r *reader) u32() int {
	b := r.take(4)
	if b == nil {
		return 0
	}
	v := binary.BigEndian.Uint32(b)
	if v > 1<<30 {
		r.bad = true
		return 0
	}
	return int(v)
}

// parseJKS は JKS / JCEKS を読む。証明書はパスワードなしで読める。秘密鍵は暗号化されており、保護方式だけを読む。
func parseJKS(data []byte, format string) (*Store, bool) {
	r := &reader{b: data}
	r.take(4)
	version := r.u32()
	count := r.u32()
	if r.bad || (version != 1 && version != 2) || count > maxEntries {
		return nil, false
	}
	// 完全性保護は形式で固定（パスワードと内容の SHA-1。JDK の実装による）
	s := &Store{Format: format, MAC: &MAC{Name: "sha1-keyed-digest"}}
	readCert := func() {
		if version == 2 {
			r.take(r.u16()) // 証明書の種類（"X.509"）
		}
		raw := r.take(r.u32())
		if r.bad {
			return
		}
		if c, err := x509cert.Parse(raw); err == nil {
			s.Certs = append(s.Certs, c)
		}
	}
	for i := 0; i < count && !r.bad; i++ {
		tag := r.u32()
		r.take(r.u16()) // 別名（出力しない）
		r.take(8)       // 作成日時
		if r.bad {
			break
		}
		switch tag {
		case 1:
			s.Entries.PrivateKeys++
			key := r.take(r.u32())
			if e, rest, err := der.Read(key); err == nil && len(rest) == 0 {
				if f, ok := seqChildren(e); ok && len(f) == 2 {
					if enc, ok := keymat.ParsePBE(f[0]); ok {
						s.addKeyProtection(enc)
					}
				}
			}
			chain := r.u32()
			for j := 0; j < chain && !r.bad; j++ {
				readCert()
			}
		case 2:
			s.Entries.TrustedCerts++
			readCert()
		default:
			// JCEKS の共通鍵エントリ（直列化された Java オブジェクト）は長さが分からないため、ここで打ち切る。
			if tag == 3 {
				s.Entries.SecretKeys++
			} else {
				s.Entries.Other++
			}
			s.Truncated = true
			return s, true
		}
	}
	if r.bad {
		s.Truncated = true
	}
	return s, true
}

// maxKeyProtections は、1 つのキーストアについて記録する、秘密鍵の保護方式の種類の上限。
const maxKeyProtections = 64
