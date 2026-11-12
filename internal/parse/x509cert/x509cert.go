// Package x509cert は X.509 証明書からインベントリに必要なメタデータだけを取り出す。
// 標準の crypto/x509 は使わない（通信用パッケージに依存し、未知のアルゴリズムに弱いため）。
// 署名の検証や信頼性の判断は行わない。
package x509cert

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/bits"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"kagiya/internal/parse/der"
)

type Certificate struct {
	Subject, Issuer            string
	SerialHex                  string
	NotBefore, NotAfter        time.Time
	SignatureAlgorithmOID      string
	PublicKeyAlgorithmOID      string
	CurveOID                   string // EC 鍵の名前付き曲線
	RSABits                    int
	IsCA                       bool
	SelfSigned                 bool // Subject と Issuer が同一（署名は検証しない）
	FingerprintSHA256          string
	PublicKeyFingerprintSHA256 string // SubjectPublicKeyInfo のハッシュ（鍵と証明書の対応付け用）
}

var errInvalid = errors.New("not a valid X.509 certificate")

const (
	oidRSA              = "1.2.840.113549.1.1.1"
	oidECPublicKey      = "1.2.840.10045.2.1"
	oidBasicConstraints = "2.5.29.19"
	maxNameLen          = 1024
)

func seq(e der.Element) bool {
	return e.Class == der.ClassUniversal && e.Tag == der.TagSequence && e.Constructed
}

// Parse は DER 形式の証明書を読む。
func Parse(raw []byte) (*Certificate, error) {
	top, rest, err := der.Read(raw)
	if err != nil || len(rest) != 0 || !seq(top) {
		return nil, errInvalid
	}
	parts, err := der.Children(top.Content)
	if err != nil || len(parts) != 3 || !seq(parts[0]) || !seq(parts[1]) {
		return nil, errInvalid
	}
	tbs, err := der.Children(parts[0].Content)
	if err != nil {
		return nil, errInvalid
	}
	if len(tbs) > 0 && tbs[0].Class == der.ClassContext && tbs[0].Tag == 0 {
		tbs = tbs[1:] // version
	}
	if len(tbs) < 6 {
		return nil, errInvalid
	}
	serial, sigAlg, issuer, validity, subject, spki := tbs[0], tbs[1], tbs[2], tbs[3], tbs[4], tbs[5]
	if serial.Class != der.ClassUniversal || serial.Tag != der.TagInteger || len(serial.Content) == 0 ||
		!seq(sigAlg) || !seq(issuer) || !seq(validity) || !seq(subject) || !seq(spki) {
		return nil, errInvalid
	}

	c := &Certificate{}
	sum := sha256.Sum256(top.Raw)
	c.FingerprintSHA256 = hex.EncodeToString(sum[:])
	spkiSum := sha256.Sum256(spki.Raw)
	c.PublicKeyFingerprintSHA256 = hex.EncodeToString(spkiSum[:])

	sn := serial.Content
	for len(sn) > 1 && sn[0] == 0 {
		sn = sn[1:]
	}
	if len(sn) > 64 {
		return nil, errInvalid
	}
	c.SerialHex = strings.TrimLeft(hex.EncodeToString(sn), "0")
	if c.SerialHex == "" {
		c.SerialHex = "0"
	}

	if c.SignatureAlgorithmOID, _, err = algorithmIdentifier(sigAlg); err != nil {
		return nil, errInvalid
	}
	if c.Issuer, err = NameString(issuer); err != nil {
		return nil, errInvalid
	}
	if c.Subject, err = NameString(subject); err != nil {
		return nil, errInvalid
	}
	c.SelfSigned = bytes.Equal(issuer.Raw, subject.Raw)

	times, err := der.Children(validity.Content)
	if err != nil || len(times) != 2 {
		return nil, errInvalid
	}
	if c.NotBefore, err = parseTime(times[0]); err != nil {
		return nil, errInvalid
	}
	if c.NotAfter, err = parseTime(times[1]); err != nil {
		return nil, errInvalid
	}

	pk, err := ParseSPKI(spki)
	if err != nil {
		return nil, errInvalid
	}
	c.PublicKeyAlgorithmOID, c.CurveOID = pk.AlgOID, pk.CurveOID
	if pk.AlgOID == oidRSA {
		c.RSABits = pk.Bits
	}

	for _, e := range tbs[6:] {
		if e.Class == der.ClassContext && e.Tag == 3 && e.Constructed {
			c.IsCA = basicConstraintsCA(e.Content)
		}
	}
	return c, nil
}

// PublicKeyInfo は SubjectPublicKeyInfo から得られる公開鍵のメタデータ。
type PublicKeyInfo struct {
	AlgOID     string
	CurveOID   string // EC の名前付き曲線
	Bits       int    // RSA はモジュラス長、DSA は素数 p の長さ。それ以外は 0（曲線やパラメータセットで決まる）
	SPKISHA256 string
}

const oidDSA = "1.2.840.10040.4.1"

// ParseSPKI は SubjectPublicKeyInfo を読む。
func ParseSPKI(spki der.Element) (PublicKeyInfo, error) {
	var pk PublicKeyInfo
	if !seq(spki) {
		return pk, errInvalid
	}
	keyParts, err := der.Children(spki.Content)
	if err != nil || len(keyParts) != 2 || !seq(keyParts[0]) ||
		keyParts[1].Class != der.ClassUniversal || keyParts[1].Tag != der.TagBitString {
		return pk, errInvalid
	}
	var params *der.Element
	if pk.AlgOID, params, err = algorithmIdentifier(keyParts[0]); err != nil {
		return pk, errInvalid
	}
	sum := sha256.Sum256(spki.Raw)
	pk.SPKISHA256 = hex.EncodeToString(sum[:])
	switch pk.AlgOID {
	case oidRSA:
		pk.Bits = rsaModulusBits(keyParts[1].Content)
	case oidECPublicKey:
		if params != nil && params.Class == der.ClassUniversal && params.Tag == der.TagOID {
			pk.CurveOID, _ = der.OID(params.Content)
		}
	case oidDSA:
		if params != nil && seq(*params) {
			if pqg, err := der.Children(params.Content); err == nil && len(pqg) >= 1 && pqg[0].Tag == der.TagInteger {
				pk.Bits = UintBits(pqg[0].Content)
			}
		}
	}
	return pk, nil
}

// UintBits は INTEGER の内容（符号なしとして）のビット長を返す。
func UintBits(n []byte) int {
	for len(n) > 0 && n[0] == 0 {
		n = n[1:]
	}
	if len(n) == 0 {
		return 0
	}
	return (len(n)-1)*8 + bits.Len8(n[0])
}

// AlgorithmIdentifier は AlgorithmIdentifier の OID とパラメータを返す。
func AlgorithmIdentifier(e der.Element) (oid string, params *der.Element, err error) {
	return algorithmIdentifier(e)
}

func algorithmIdentifier(e der.Element) (oid string, params *der.Element, err error) {
	kids, err := der.Children(e.Content)
	if err != nil || len(kids) == 0 || len(kids) > 2 || kids[0].Class != der.ClassUniversal || kids[0].Tag != der.TagOID {
		return "", nil, errInvalid
	}
	if oid, err = der.OID(kids[0].Content); err != nil {
		return "", nil, errInvalid
	}
	if len(kids) == 2 {
		params = &kids[1]
	}
	return oid, params, nil
}

// rsaModulusBits は BIT STRING に入った RSAPublicKey からモジュラスのビット長を得る。分からなければ 0。
func rsaModulusBits(bitString []byte) int {
	if len(bitString) < 1 || bitString[0] != 0 {
		return 0
	}
	key, rest, err := der.Read(bitString[1:])
	if err != nil || len(rest) != 0 || !seq(key) {
		return 0
	}
	kids, err := der.Children(key.Content)
	if err != nil || len(kids) != 2 || kids[0].Tag != der.TagInteger || kids[0].Class != der.ClassUniversal {
		return 0
	}
	n := kids[0].Content
	for len(n) > 0 && n[0] == 0 {
		n = n[1:]
	}
	if len(n) == 0 {
		return 0
	}
	return (len(n)-1)*8 + bits.Len8(n[0])
}

func basicConstraintsCA(extsWrapper []byte) bool {
	list, rest, err := der.Read(extsWrapper)
	if err != nil || len(rest) != 0 || !seq(list) {
		return false
	}
	exts, err := der.Children(list.Content)
	if err != nil {
		return false
	}
	for _, ext := range exts {
		if !seq(ext) {
			continue
		}
		f, err := der.Children(ext.Content)
		if err != nil || len(f) < 2 || f[0].Tag != der.TagOID {
			continue
		}
		if oid, _ := der.OID(f[0].Content); oid != oidBasicConstraints {
			continue
		}
		val := f[len(f)-1]
		if val.Tag != der.TagOctetString {
			return false
		}
		bc, rest, err := der.Read(val.Content)
		if err != nil || len(rest) != 0 || !seq(bc) {
			return false
		}
		kids, err := der.Children(bc.Content)
		if err != nil || len(kids) == 0 {
			return false
		}
		return kids[0].Class == der.ClassUniversal && kids[0].Tag == der.TagBoolean &&
			len(kids[0].Content) == 1 && kids[0].Content[0] != 0
	}
	return false
}

func parseTime(e der.Element) (time.Time, error) {
	if e.Class != der.ClassUniversal {
		return time.Time{}, errInvalid
	}
	s := string(e.Content)
	switch e.Tag {
	case der.TagUTCTime:
		for _, layout := range []string{"060102150405Z", "0601021504Z"} {
			if t, err := time.Parse(layout, s); err == nil {
				// X.509 の規則: 2桁年は 50 以上が 19xx、未満が 20xx
				if t.Year() >= 2050 {
					t = t.AddDate(-100, 0, 0)
				}
				return t.UTC(), nil
			}
		}
	case der.TagGeneralizedTime:
		if t, err := time.Parse("20060102150405Z", s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, errInvalid
}

var attrNames = map[string]string{
	"2.5.4.3": "CN", "2.5.4.4": "SN", "2.5.4.5": "serialNumber", "2.5.4.6": "C", "2.5.4.7": "L",
	"2.5.4.8": "ST", "2.5.4.9": "street", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.12": "title",
	"2.5.4.42": "GN", "1.2.840.113549.1.9.1": "emailAddress", "0.9.2342.19200300.100.1.25": "DC",
	"0.9.2342.19200300.100.1.1": "UID",
}

// NameString は識別名を "C=JP, O=Example, CN=host" の形にする（符号化された順）。
func NameString(name der.Element) (string, error) {
	rdns, err := der.Children(name.Content)
	if err != nil {
		return "", err
	}
	var parts []string
	total := 0
	for _, rdn := range rdns {
		if rdn.Class != der.ClassUniversal || rdn.Tag != der.TagSet {
			return "", errInvalid
		}
		atvs, err := der.Children(rdn.Content)
		if err != nil {
			return "", err
		}
		var multi []string
		for _, atv := range atvs {
			kv, err := der.Children(atv.Content)
			if err != nil || !seq(atv) || len(kv) != 2 || kv[0].Tag != der.TagOID {
				return "", errInvalid
			}
			oid, err := der.OID(kv[0].Content)
			if err != nil {
				return "", err
			}
			key := oid
			if n, ok := attrNames[oid]; ok {
				key = n
			}
			s := key + "=" + escapeValue(valueString(kv[1]))
			total += len(s)
			if total > maxNameLen {
				return strings.Join(parts, ", ") + ", ...", nil
			}
			multi = append(multi, s)
		}
		parts = append(parts, strings.Join(multi, "+"))
	}
	return strings.Join(parts, ", "), nil
}

func valueString(e der.Element) string {
	if e.Class != der.ClassUniversal {
		return "#" + hex.EncodeToString(e.Content)
	}
	var s string
	switch e.Tag {
	case der.TagUTF8String, der.TagPrintableString, der.TagIA5String:
		s = string(e.Content)
	case der.TagT61String: // 実運用では Latin-1 として使われる
		r := make([]rune, len(e.Content))
		for i, b := range e.Content {
			r[i] = rune(b)
		}
		s = string(r)
	case der.TagBMPString:
		u := make([]uint16, 0, len(e.Content)/2)
		for i := 0; i+1 < len(e.Content); i += 2 {
			u = append(u, uint16(e.Content[i])<<8|uint16(e.Content[i+1]))
		}
		s = string(utf16.Decode(u))
	case der.TagUniversalString:
		var r []rune
		for i := 0; i+3 < len(e.Content); i += 4 {
			r = append(r, rune(uint32(e.Content[i])<<24|uint32(e.Content[i+1])<<16|uint32(e.Content[i+2])<<8|uint32(e.Content[i+3])))
		}
		s = string(r)
	default:
		return "#" + hex.EncodeToString(e.Content)
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "?")
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			return '?'
		}
		return r
	}, s)
}

func escapeValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`,+"\<>;=`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
