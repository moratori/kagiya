// Package keymat は鍵素材のファイル（証明書、CSR、各形式の秘密鍵・公開鍵、SSH 鍵）から
// インベントリに必要なメタデータだけを取り出す。
//
// 秘密鍵については形式・アルゴリズム・鍵長・暗号化の有無と、ファイルに含まれる公開成分から
// 計算した公開鍵の指紋だけを扱う。秘密成分を使った計算や、秘密成分のハッシュ計算は行わない。
package keymat

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"regexp"
	"strings"

	"kagiya/internal/parse/der"
	"kagiya/internal/parse/x509cert"
)

// Item はファイルから見つかった鍵素材1つ。
type Item struct {
	Kind   string // certificate | csr | private-key | public-key
	Format string // x509 | pkcs10 | pkcs1 | pkcs8 | pkcs8-encrypted | sec1 | dsa-traditional | openssh | spki | pkcs1-public | ssh-public | unknown
	Index  int    // ファイル内での順番
	Cert   *x509cert.Certificate
	CSR    *CSR
	Key    *Key
}

type CSR struct {
	Subject               string
	SignatureAlgorithmOID string
	Key                   Key
	SHA256                string // CSR 全体（DER）の SHA-256
}

type Key struct {
	AlgOID         string
	CurveOID       string
	SSHType        string // SSH 鍵の種別名（ssh-ed25519 など）
	Bits           int
	SPKISHA256     string // SubjectPublicKeyInfo の SHA-256（証明書との対応付け用）。公開成分が得られない場合は空
	SSHFingerprint string // ssh-keygen -l と同じ形式（SHA256:...）
	Encrypted      bool
	Enc            *Encryption
}

// Encryption は秘密鍵の保護方式。
type Encryption struct {
	SchemeOID  string // PBES2 など
	KDFOID     string
	PRFOID     string
	CipherOID  string
	Name       string // OID を持たない方式の名前（PEM の DEK-Info、OpenSSH の暗号名）
	KDFName    string
	Iterations int
}

const (
	oidRSA       = "1.2.840.113549.1.1.1"
	oidDSA       = "1.2.840.10040.4.1"
	oidEC        = "1.2.840.10045.2.1"
	oidEd25519   = "1.3.101.112"
	oidPBES2     = "1.2.840.113549.1.5.13"
	oidHMACSHA1  = "1.2.840.113549.2.7" // PBKDF2 の PRF 省略時の既定（RFC 8018）
	maxItems     = 100_000
	opensshMagic = "openssh-key-v1\x00"
)

var (
	namePattern = regexp.MustCompile(`^[A-Za-z0-9@._+-]{1,64}$`)
	sshCurves   = map[string]struct {
		oid  string
		bits int
	}{
		"nistp256": {"1.2.840.10045.3.1.7", 256},
		"nistp384": {"1.3.132.0.34", 384},
		"nistp521": {"1.3.132.0.35", 521},
	}
)

// Parse はファイル名と内容から鍵素材を取り出す。failed は、鍵素材らしいのに解析できなかった個数。
func Parse(name string, data []byte) (items []Item, failed int) {
	base := strings.ToLower(name[strings.LastIndexAny(name, `/\`)+1:])
	switch {
	case bytes.Contains(data, []byte("-----BEGIN ")):
		items, failed = parsePEM(data)
	case strings.HasPrefix(base, "authorized_keys") || strings.HasPrefix(base, "known_hosts") || strings.HasSuffix(base, ".pub"):
		items, failed = parseSSHLines(data)
	case len(data) > 0 && data[0] == 0x30:
		var ok bool
		if items, ok = parseDER(data); !ok {
			failed = 1
		}
	}
	for i := range items {
		items[i].Index = i
	}
	return items, failed
}

func parsePEM(data []byte) (items []Item, failed int) {
	rest := data
	for len(items) < maxItems {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "PKCS7" {
			if certs, ok := parsePKCS7(block.Bytes); ok {
				items = append(items, certs...)
			} else {
				failed++
			}
			continue
		}
		it, ok, relevant := parsePEMBlock(block)
		switch {
		case !relevant:
		case ok:
			items = append(items, it)
		default:
			failed++
		}
	}
	return items, failed
}

func parsePEMBlock(b *pem.Block) (it Item, ok, relevant bool) {
	legacyEnc := legacyPEMEncryption(b)
	privKey := func(format, algOID string, parse func([]byte) (Key, bool)) (Item, bool, bool) {
		if legacyEnc != nil { // 本体は暗号文なので中身は読まない
			return Item{Kind: "private-key", Format: format, Key: &Key{AlgOID: algOID, Encrypted: true, Enc: legacyEnc}}, true, true
		}
		k, ok := parse(b.Bytes)
		return Item{Kind: "private-key", Format: format, Key: &k}, ok, true
	}
	switch b.Type {
	case "CERTIFICATE", "X509 CERTIFICATE":
		c, err := x509cert.Parse(b.Bytes)
		return Item{Kind: "certificate", Format: "x509", Cert: c}, err == nil, true
	case "TRUSTED CERTIFICATE":
		// OpenSSL の信頼設定付き証明書: 証明書の後ろに補助データが続く。先頭の要素だけを読む。
		raw := b.Bytes
		if first, _, err := der.Read(raw); err == nil {
			raw = first.Raw
		}
		c, err := x509cert.Parse(raw)
		return Item{Kind: "certificate", Format: "x509", Cert: c}, err == nil, true
	case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
		r, ok := parseCSR(b.Bytes)
		return Item{Kind: "csr", Format: "pkcs10", CSR: &r}, ok, true
	case "PRIVATE KEY":
		return privKey("pkcs8", "", parsePKCS8)
	case "ENCRYPTED PRIVATE KEY":
		k, ok := parseEncryptedPKCS8(b.Bytes)
		return Item{Kind: "private-key", Format: "pkcs8-encrypted", Key: &k}, ok, true
	case "RSA PRIVATE KEY":
		return privKey("pkcs1", oidRSA, parsePKCS1)
	case "EC PRIVATE KEY":
		return privKey("sec1", oidEC, func(d []byte) (Key, bool) { return parseSEC1(d, "") })
	case "DSA PRIVATE KEY":
		return privKey("dsa-traditional", oidDSA, parseDSATraditional)
	case "OPENSSH PRIVATE KEY":
		k, ok := parseOpenSSHPrivate(b.Bytes)
		return Item{Kind: "private-key", Format: "openssh", Key: &k}, ok, true
	case "PUBLIC KEY":
		k, ok := parseSPKIBytes(b.Bytes)
		return Item{Kind: "public-key", Format: "spki", Key: &k}, ok, true
	case "RSA PUBLIC KEY":
		k, ok := parsePKCS1Public(b.Bytes)
		return Item{Kind: "public-key", Format: "pkcs1-public", Key: &k}, ok, true
	}
	if strings.HasSuffix(b.Type, "PRIVATE KEY") {
		// 未対応の形式でも、秘密鍵が存在すること自体は記録する。
		return Item{Kind: "private-key", Format: "unknown", Key: &Key{Encrypted: legacyEnc != nil, Enc: legacyEnc}}, true, true
	}
	return Item{}, false, false
}

// legacyPEMEncryption は PEM ヘッダによる従来型の暗号化（Proc-Type / DEK-Info）を読む。
func legacyPEMEncryption(b *pem.Block) *Encryption {
	if !strings.Contains(b.Headers["Proc-Type"], "ENCRYPTED") {
		return nil
	}
	name, _, _ := strings.Cut(b.Headers["DEK-Info"], ",")
	name = strings.TrimSpace(name)
	if !namePattern.MatchString(name) {
		name = ""
	}
	return &Encryption{Name: name}
}

func isSeq(e der.Element) bool {
	return e.Class == der.ClassUniversal && e.Tag == der.TagSequence && e.Constructed
}

func isInt(e der.Element) bool { return e.Class == der.ClassUniversal && e.Tag == der.TagInteger }

func top(data []byte) ([]der.Element, bool) {
	e, rest, err := der.Read(data)
	if err != nil || len(rest) != 0 || !isSeq(e) {
		return nil, false
	}
	kids, err := der.Children(e.Content)
	return kids, err == nil
}

func keyFromSPKI(spkiDER []byte) (Key, bool) {
	e, rest, err := der.Read(spkiDER)
	if err != nil || len(rest) != 0 {
		return Key{}, false
	}
	pk, err := x509cert.ParseSPKI(e)
	if err != nil {
		return Key{}, false
	}
	return Key{AlgOID: pk.AlgOID, CurveOID: pk.CurveOID, Bits: pk.Bits, SPKISHA256: pk.SPKISHA256}, true
}

func parseSPKIBytes(data []byte) (Key, bool) { return keyFromSPKI(data) }

func rsaSPKI(n, e []byte) []byte {
	return der.EncodeSequence(
		der.EncodeSequence(der.EncodeOID(oidRSA), der.Encode(0x05, nil)),
		der.EncodeBitString(der.EncodeSequence(der.EncodeUint(n), der.EncodeUint(e))),
	)
}

// parsePKCS1 は RSAPrivateKey を読む。使うのは公開成分（モジュラスと公開指数）だけ。
func parsePKCS1(data []byte) (Key, bool) {
	kids, ok := top(data)
	if !ok || len(kids) < 9 {
		return Key{}, false
	}
	for _, k := range kids[:9] {
		if !isInt(k) {
			return Key{}, false
		}
	}
	return keyFromSPKI(rsaSPKI(kids[1].Content, kids[2].Content))
}

func parsePKCS1Public(data []byte) (Key, bool) {
	kids, ok := top(data)
	if !ok || len(kids) != 2 || !isInt(kids[0]) || !isInt(kids[1]) {
		return Key{}, false
	}
	return keyFromSPKI(rsaSPKI(kids[0].Content, kids[1].Content))
}

// parseSEC1 は ECPrivateKey を読む。曲線は鍵自身のパラメータ、なければ外側（PKCS#8）の指定を使う。
func parseSEC1(data []byte, outerCurve string) (Key, bool) {
	kids, ok := top(data)
	if !ok || len(kids) < 2 || !isInt(kids[0]) || kids[1].Tag != der.TagOctetString {
		return Key{}, false
	}
	k := Key{AlgOID: oidEC, CurveOID: outerCurve}
	var pub []byte
	for _, e := range kids[2:] {
		if e.Class != der.ClassContext || !e.Constructed {
			continue
		}
		inner, rest, err := der.Read(e.Content)
		if err != nil || len(rest) != 0 || inner.Class != der.ClassUniversal {
			continue
		}
		switch {
		case e.Tag == 0 && inner.Tag == der.TagOID:
			if oid, err := der.OID(inner.Content); err == nil {
				k.CurveOID = oid
			}
		case e.Tag == 1 && inner.Tag == der.TagBitString && len(inner.Content) > 1 && inner.Content[0] == 0:
			pub = inner.Content[1:]
		}
	}
	if pub != nil && k.CurveOID != "" {
		if curve := der.EncodeOID(k.CurveOID); curve != nil {
			spki := der.EncodeSequence(der.EncodeSequence(der.EncodeOID(oidEC), curve), der.EncodeBitString(pub))
			if pk, ok := keyFromSPKI(spki); ok {
				k.SPKISHA256 = pk.SPKISHA256
			}
		}
	}
	return k, true
}

// parseDSATraditional は OpenSSL 従来形式の DSA 秘密鍵（version, p, q, g, y, x）を読む。
func parseDSATraditional(data []byte) (Key, bool) {
	kids, ok := top(data)
	if !ok || len(kids) != 6 {
		return Key{}, false
	}
	for _, k := range kids {
		if !isInt(k) {
			return Key{}, false
		}
	}
	spki := der.EncodeSequence(
		der.EncodeSequence(der.EncodeOID(oidDSA), der.EncodeSequence(kids[1].Raw, kids[2].Raw, kids[3].Raw)),
		der.EncodeBitString(kids[4].Raw),
	)
	return keyFromSPKI(spki)
}

// parsePKCS8 は暗号化されていない PrivateKeyInfo / OneAsymmetricKey を読む。
func parsePKCS8(data []byte) (Key, bool) {
	kids, ok := top(data)
	if !ok || len(kids) < 3 || !isInt(kids[0]) || !isSeq(kids[1]) || kids[2].Tag != der.TagOctetString {
		return Key{}, false
	}
	oid, params, err := x509cert.AlgorithmIdentifier(kids[1])
	if err != nil {
		return Key{}, false
	}
	k := Key{AlgOID: oid}
	switch oid {
	case oidRSA:
		if inner, ok := parsePKCS1(kids[2].Content); ok {
			return inner, true
		}
	case oidEC:
		curve := ""
		if params != nil && params.Class == der.ClassUniversal && params.Tag == der.TagOID {
			curve, _ = der.OID(params.Content)
		}
		if inner, ok := parseSEC1(kids[2].Content, curve); ok {
			return inner, true
		}
		k.CurveOID = curve
	case oidDSA:
		if params != nil && isSeq(*params) {
			if pqg, err := der.Children(params.Content); err == nil && len(pqg) >= 1 && isInt(pqg[0]) {
				k.Bits = x509cert.UintBits(pqg[0].Content)
			}
		}
	}
	// 公開鍵を含む形式（OneAsymmetricKey の [1]）なら、そこから指紋を得る。
	for _, e := range kids[3:] {
		if e.Class == der.ClassContext && e.Tag == 1 && !e.Constructed && len(e.Content) > 1 && e.Content[0] == 0 {
			if pk, ok := keyFromSPKI(der.EncodeSequence(kids[1].Raw, der.EncodeBitString(e.Content[1:]))); ok {
				k.SPKISHA256 = pk.SPKISHA256
			}
		}
	}
	return k, true
}

// parseEncryptedPKCS8 は EncryptedPrivateKeyInfo から保護方式だけを読む（復号はしない）。
func parseEncryptedPKCS8(data []byte) (Key, bool) {
	kids, ok := top(data)
	if !ok || len(kids) != 2 || !isSeq(kids[0]) || kids[1].Tag != der.TagOctetString {
		return Key{}, false
	}
	enc, ok := ParsePBE(kids[0])
	if !ok {
		return Key{}, false
	}
	return Key{Encrypted: true, Enc: &enc}, true
}

// ParsePBE はパスワードベース暗号の AlgorithmIdentifier から方式・反復回数を読む。
func ParsePBE(algID der.Element) (Encryption, bool) {
	oid, params, err := x509cert.AlgorithmIdentifier(algID)
	if err != nil {
		return Encryption{}, false
	}
	enc := Encryption{SchemeOID: oid}
	if params == nil || !isSeq(*params) {
		return enc, true
	}
	p, err := der.Children(params.Content)
	if err != nil {
		return enc, true
	}
	if oid != oidPBES2 {
		// PBES1 / PKCS#12 PBE: パラメータは { salt, iterations }
		if len(p) == 2 && isInt(p[1]) {
			enc.Iterations = smallInt(p[1].Content)
		}
		return enc, true
	}
	if len(p) != 2 || !isSeq(p[0]) || !isSeq(p[1]) {
		return enc, true
	}
	var kdfParams *der.Element
	if enc.KDFOID, kdfParams, err = x509cert.AlgorithmIdentifier(p[0]); err != nil {
		return enc, true
	}
	enc.CipherOID, _, _ = x509cert.AlgorithmIdentifier(p[1])
	if kdfParams != nil && isSeq(*kdfParams) {
		if kp, err := der.Children(kdfParams.Content); err == nil {
			for i, e := range kp {
				switch {
				case i == 1 && isInt(e):
					enc.Iterations = smallInt(e.Content)
				case i >= 2 && isSeq(e):
					enc.PRFOID, _, _ = x509cert.AlgorithmIdentifier(e)
				}
			}
			if enc.PRFOID == "" && len(kp) >= 2 && isInt(kp[1]) {
				enc.PRFOID = oidHMACSHA1
			}
		}
	}
	return enc, true
}

func smallInt(b []byte) int {
	if len(b) == 0 || len(b) > 4 || b[0]&0x80 != 0 {
		return 0
	}
	n := 0
	for _, c := range b {
		n = n<<8 | int(c)
	}
	return n
}

func parseCSR(data []byte) (CSR, bool) {
	kids, ok := top(data)
	if !ok || len(kids) != 3 || !isSeq(kids[0]) || !isSeq(kids[1]) {
		return CSR{}, false
	}
	info, err := der.Children(kids[0].Content)
	if err != nil || len(info) < 3 || !isInt(info[0]) || !isSeq(info[1]) || !isSeq(info[2]) {
		return CSR{}, false
	}
	var r CSR
	if r.Subject, err = x509cert.NameString(info[1]); err != nil {
		return CSR{}, false
	}
	if r.SignatureAlgorithmOID, _, err = x509cert.AlgorithmIdentifier(kids[1]); err != nil {
		return CSR{}, false
	}
	pk, err := x509cert.ParseSPKI(info[2])
	if err != nil {
		return CSR{}, false
	}
	r.Key = Key{AlgOID: pk.AlgOID, CurveOID: pk.CurveOID, Bits: pk.Bits, SPKISHA256: pk.SPKISHA256}
	sum := sha256.Sum256(data)
	r.SHA256 = hex.EncodeToString(sum[:])
	return r, true
}

const oidSignedData = "1.2.840.113549.1.7.2"

// parsePKCS7 は PKCS#7 SignedData（証明書の束、.p7b）から証明書を取り出す。署名は検証しない。
func parsePKCS7(data []byte) ([]Item, bool) {
	kids, ok := top(data)
	if !ok || len(kids) != 2 || kids[0].Tag != der.TagOID || kids[1].Class != der.ClassContext || kids[1].Tag != 0 {
		return nil, false
	}
	if oid, err := der.OID(kids[0].Content); err != nil || oid != oidSignedData {
		return nil, false
	}
	sd, ok := top(kids[1].Content)
	if !ok || len(sd) < 3 {
		return nil, false
	}
	var items []Item
	for _, e := range sd[3:] {
		if e.Class != der.ClassContext || e.Tag != 0 || !e.Constructed {
			continue
		}
		certs, err := der.Children(e.Content)
		if err != nil {
			return nil, false
		}
		for _, c := range certs {
			if len(items) >= maxItems {
				break
			}
			if cert, err := x509cert.Parse(c.Raw); err == nil {
				items = append(items, Item{Kind: "certificate", Format: "x509", Cert: cert})
			}
		}
	}
	return items, true
}

// parseDER は PEM に包まれていない DER を、構造から種類を判定して読む。
func parseDER(data []byte) ([]Item, bool) {
	if c, err := x509cert.Parse(data); err == nil {
		return []Item{{Kind: "certificate", Format: "x509", Cert: c}}, true
	}
	kids, ok := top(data)
	if !ok || len(kids) < 2 {
		return nil, false
	}
	if kids[0].Tag == der.TagOID && kids[0].Class == der.ClassUniversal {
		return parsePKCS7(data)
	}
	switch {
	case isInt(kids[0]) && len(kids) >= 3 && isSeq(kids[1]) && kids[2].Tag == der.TagOctetString:
		if k, ok := parsePKCS8(data); ok {
			return []Item{Item{Kind: "private-key", Format: "pkcs8", Key: &k}}, true
		}
	case isSeq(kids[0]) && len(kids) == 2 && kids[1].Tag == der.TagOctetString && kids[1].Class == der.ClassUniversal:
		if k, ok := parseEncryptedPKCS8(data); ok {
			return []Item{Item{Kind: "private-key", Format: "pkcs8-encrypted", Key: &k}}, true
		}
	case isSeq(kids[0]) && len(kids) == 2 && kids[1].Tag == der.TagBitString && kids[1].Class == der.ClassUniversal:
		if k, ok := parseSPKIBytes(data); ok {
			return []Item{Item{Kind: "public-key", Format: "spki", Key: &k}}, true
		}
	case isSeq(kids[0]) && len(kids) == 3 && isSeq(kids[1]) && kids[2].Tag == der.TagBitString:
		if r, ok := parseCSR(data); ok {
			return []Item{Item{Kind: "csr", Format: "pkcs10", CSR: &r}}, true
		}
	case isInt(kids[0]) && len(kids) >= 9:
		if k, ok := parsePKCS1(data); ok {
			return []Item{Item{Kind: "private-key", Format: "pkcs1", Key: &k}}, true
		}
	case isInt(kids[0]) && kids[1].Tag == der.TagOctetString:
		if k, ok := parseSEC1(data, ""); ok {
			return []Item{Item{Kind: "private-key", Format: "sec1", Key: &k}}, true
		}
	}
	return nil, false
}

// ---- SSH ----

// sshString は SSH のワイヤ形式の文字列（4バイト長＋内容）を1つ読む。
func sshString(b []byte) (s, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

// keyFromSSHBlob は SSH 公開鍵のブロブを読む。
func keyFromSSHBlob(blob []byte) (Key, bool) {
	typ, rest, ok := sshString(blob)
	if !ok || !namePattern.Match(typ) {
		return Key{}, false
	}
	sum := sha256.Sum256(blob)
	k := Key{SSHType: string(typ), SSHFingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])}
	setSPKI := func(spki []byte) {
		if pk, ok := keyFromSPKI(spki); ok {
			k.SPKISHA256 = pk.SPKISHA256
		}
	}
	switch {
	case k.SSHType == "ssh-rsa":
		e, rest, ok1 := sshString(rest)
		n, _, ok2 := sshString(rest)
		if !ok1 || !ok2 {
			return Key{}, false
		}
		k.AlgOID, k.Bits = oidRSA, x509cert.UintBits(n)
		setSPKI(rsaSPKI(n, e))
	case k.SSHType == "ssh-ed25519":
		pub, _, ok := sshString(rest)
		if !ok || len(pub) != 32 {
			return Key{}, false
		}
		k.AlgOID, k.Bits = oidEd25519, 256
		setSPKI(der.EncodeSequence(der.EncodeSequence(der.EncodeOID(oidEd25519)), der.EncodeBitString(pub)))
	case strings.HasPrefix(k.SSHType, "ecdsa-sha2-"):
		curve, rest, ok1 := sshString(rest)
		q, _, ok2 := sshString(rest)
		c, known := sshCurves[string(curve)]
		if !ok1 || !ok2 {
			return Key{}, false
		}
		k.AlgOID = oidEC
		if known {
			k.CurveOID, k.Bits = c.oid, c.bits
			setSPKI(der.EncodeSequence(der.EncodeSequence(der.EncodeOID(oidEC), der.EncodeOID(c.oid)), der.EncodeBitString(q)))
		}
	case k.SSHType == "ssh-dss":
		p, _, ok := sshString(rest)
		if !ok {
			return Key{}, false
		}
		k.AlgOID, k.Bits = oidDSA, x509cert.UintBits(p)
	}
	return k, true
}

// parseOpenSSHPrivate は OpenSSH 形式の秘密鍵を読む。公開鍵は暗号化の有無にかかわらず平文で含まれる。
func parseOpenSSHPrivate(data []byte) (Key, bool) {
	if !bytes.HasPrefix(data, []byte(opensshMagic)) {
		return Key{}, false
	}
	b := data[len(opensshMagic):]
	cipher, b, ok1 := sshString(b)
	kdf, b, ok2 := sshString(b)
	kdfOpts, b, ok3 := sshString(b)
	if !ok1 || !ok2 || !ok3 || len(b) < 4 || !namePattern.Match(cipher) || !namePattern.Match(kdf) {
		return Key{}, false
	}
	if binary.BigEndian.Uint32(b) < 1 {
		return Key{}, false
	}
	pub, _, ok := sshString(b[4:])
	if !ok {
		return Key{}, false
	}
	k, ok := keyFromSSHBlob(pub)
	if !ok {
		return Key{}, false
	}
	if string(cipher) != "none" {
		k.Encrypted = true
		k.Enc = &Encryption{Name: string(cipher), KDFName: string(kdf)}
		if _, r, ok := sshString(kdfOpts); ok && len(r) == 4 { // bcrypt: salt, rounds
			k.Enc.Iterations = int(binary.BigEndian.Uint32(r))
		}
	}
	return k, true
}

func sshKeyType(s string) bool {
	return strings.HasPrefix(s, "ssh-") || strings.HasPrefix(s, "ecdsa-sha2-") || strings.HasPrefix(s, "sk-") ||
		strings.HasPrefix(s, "rsa-sha2-")
}

// parseSSHLines は1行1鍵の形式（*.pub、authorized_keys、known_hosts）を読む。
// オプションやホスト名の部分は読み捨て、「種別名 Base64」の並びだけを見る。
func parseSSHLines(data []byte) (items []Item, failed int) {
	// 1 行ずつ切り出す（全体を行に分けた並びは作らない）
	for len(data) > 0 {
		var line []byte
		line, data, _ = bytes.Cut(data, []byte("\n"))
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' || len(items) >= maxItems {
			continue
		}
		if len(line) > 64*1024 {
			failed++
			continue
		}
		f := strings.Fields(string(line))
		found := false
		for i := 0; i+1 < len(f) && !found; i++ {
			if !sshKeyType(f[i]) {
				continue
			}
			blob, err := base64.StdEncoding.DecodeString(f[i+1])
			if err != nil {
				continue
			}
			if k, ok := keyFromSSHBlob(blob); ok && k.SSHType == f[i] {
				items = append(items, Item{Kind: "public-key", Format: "ssh-public", Key: &k})
				found = true
			}
		}
		if !found {
			failed++
		}
	}
	return items, failed
}
