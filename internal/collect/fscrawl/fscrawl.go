// Package fscrawl は、走査で見つかったファイルから証明書・鍵・CSR・キーストアを集めるコレクタ。
package fscrawl

import (
	"bytes"
	"kagiya/internal/collect/jars"
	"strconv"
	"strings"
	"time"

	"kagiya/internal/inventory"
	"kagiya/internal/model"
	"kagiya/internal/parse/keymat"
	"kagiya/internal/parse/keystore"
	"kagiya/internal/parse/x509cert"
	"kagiya/internal/safefs"
)

const (
	collector = "fscrawl"

	maxKeyFileSize   = 1 << 20 // 証明書・鍵として読む上限
	maxStoreFileSize = 8 << 20 // キーストアとして読む上限
	maxSniffSize     = 16 << 10
)

var (
	// 鍵素材を含み得る拡張子
	keyExts = map[string]bool{
		".pem": true, ".crt": true, ".cer": true, ".cert": true, ".der": true, ".key": true,
		".csr": true, ".req": true, ".pub": true, ".p7b": true, ".p7c": true,
	}
	storeExts = map[string]bool{
		".p12": true, ".pfx": true, ".jks": true, ".jceks": true, ".keystore": true, ".truststore": true, ".ks": true,
		// Bouncy Castle 形式
		".bks": true, ".uber": true, ".bcfks": true, ".bcfips": true, ".fks": true,
	}
	// 拡張子を持たない、よくある名前
	keyNames = map[string]bool{
		"id_rsa": true, "id_dsa": true, "id_ecdsa": true, "id_ed25519": true, "identity": true, "cacerts": true,
	}
	oidRSA = "1.2.840.113549.1.1.1"
	oidDSA = "1.2.840.10040.4.1"
)

type Collector struct {
	b *inventory.Builder
	// 探索で見つかった JAR（.jar / .war / .ear）。中身は、探索の後で別のコレクタ（jars）が読む
	archives     []string
	archivesMore int // 上限を超えて、覚えなかった数
}

// maxArchives は、覚えておく JAR の数の上限。
const maxArchives = 20000

// Archives は、探索で見つかった JAR のパスと、上限を超えて覚えなかった数を返す。
func (c *Collector) Archives() ([]string, int) { return c.archives, c.archivesMore }

func New(b *inventory.Builder) *Collector { return &Collector{b: b} }

// candidate は、ファイル名と大きさから読む価値があるかと、読み取りの上限を決める。
func candidate(name string, size int64) (limit int64, ok bool) {
	lower := strings.ToLower(name)
	ext := ""
	if i := strings.LastIndexByte(lower, '.'); i > 0 {
		ext = lower[i:]
	}
	switch {
	case storeExts[ext] || lower == "cacerts":
		return maxStoreFileSize, true
	case keyExts[ext] || keyNames[lower]:
		return maxKeyFileSize, true
	case strings.HasPrefix(lower, "authorized_keys") || strings.HasPrefix(lower, "known_hosts"):
		return maxKeyFileSize, true
	case strings.HasPrefix(lower, "ssh_host_") && strings.HasSuffix(lower, "_key"):
		return maxKeyFileSize, true
	case ext == "" && size <= maxSniffSize:
		// 拡張子のない小さなファイルは、中身が PEM かどうかを見る（秘密鍵は拡張子なしで置かれることが多い）。
		return maxSniffSize, true
	}
	return 0, false
}

// Visit は通常ファイル1つを調べる（safefs.Walker の visit として渡す）。
func (c *Collector) Visit(e *safefs.Entry) error {
	if jars.IsArchive(e.Name) {
		if len(c.archives) < maxArchives {
			c.archives = append(c.archives, e.Path)
		} else {
			c.archivesMore++
		}
		return nil
	}
	limit, ok := candidate(e.Name, e.Size)
	if !ok {
		return nil
	}
	data, err := e.ReadLimited(limit)
	if err != nil {
		return nil // スキップは記録済み
	}
	lower := strings.ToLower(e.Name)
	sniffOnly := !strings.Contains(strings.TrimPrefix(lower, "."), ".") && !keyNames[lower] &&
		!strings.HasPrefix(lower, "authorized_keys") && !strings.HasPrefix(lower, "known_hosts") &&
		!(strings.HasPrefix(lower, "ssh_host_") && strings.HasSuffix(lower, "_key"))
	if sniffOnly && !bytes.Contains(data, []byte("-----BEGIN ")) {
		return nil
	}
	if store, ok := keystore.Parse(data); ok {
		c.addKeystore(store, e.Path)
		return nil
	}
	items, failed := keymat.Parse(e.Name, data)
	for _, it := range items {
		loc := model.Location{Kind: "file", Path: e.Path, Index: it.Index}
		switch it.Kind {
		case "certificate":
			c.b.Occur(c.certificate(it.Cert), collector, loc, nil)
		case "csr":
			c.b.Occur(c.csr(it.CSR), collector, loc, nil)
		case "private-key", "public-key":
			c.b.Occur(c.key(it, e.Path), collector, loc, c.keyDetail(it))
		}
	}
	if failed > 0 {
		c.b.Skip(safefs.Skip{Path: e.Path, Reason: "parse-error", Detail: strconv.Itoa(failed) + " item(s) could not be parsed"})
	}
	return nil
}

func (c *Collector) certificate(cert *x509cert.Certificate) string {
	id := "cert:sha256:" + cert.FingerprintSHA256
	c.b.Asset(id, func() model.Asset {
		return model.Asset{Type: "certificate", Certificate: &model.Certificate{
			Subject: cert.Subject, Issuer: cert.Issuer, Serial: cert.SerialHex,
			NotBefore: cert.NotBefore.Format(time.RFC3339), NotAfter: cert.NotAfter.Format(time.RFC3339),
			IsCA: cert.IsCA, SelfSigned: cert.SelfSigned,
			SignatureAlgorithm: c.b.AlgorithmByOID(cert.SignatureAlgorithmOID),
			PublicKey: model.PublicKey{
				Algorithm:         c.keyAlgorithm(cert.PublicKeyAlgorithmOID, cert.CurveOID, "", cert.RSABits),
				FingerprintSHA256: cert.PublicKeyFingerprintSHA256,
			},
			FingerprintSHA256: cert.FingerprintSHA256,
		}}
	})
	return id
}

func (c *Collector) csr(r *keymat.CSR) string {
	id := "csr:sha256:" + r.SHA256
	c.b.Asset(id, func() model.Asset {
		return model.Asset{Type: "csr", CSR: &model.CSR{
			Subject:            r.Subject,
			SignatureAlgorithm: c.b.AlgorithmByOID(r.SignatureAlgorithmOID),
			PublicKey: model.PublicKey{
				Algorithm:         c.keyAlgorithm(r.Key.AlgOID, r.Key.CurveOID, "", r.Key.Bits),
				FingerprintSHA256: r.Key.SPKISHA256,
			},
		}}
	})
	return id
}

// keyAlgorithm は鍵のアルゴリズム資産を決める。RSA・DSA は鍵長、EC は曲線で区別する。
func (c *Collector) keyAlgorithm(algOID, curveOID, sshType string, bits int) string {
	switch {
	case (algOID == oidRSA || algOID == oidDSA) && bits > 0:
		return c.b.AlgorithmWithBits(algOID, bits)
	case curveOID != "":
		return c.b.AlgorithmByOID(curveOID)
	case algOID != "":
		return c.b.AlgorithmByOID(algOID)
	case sshType != "":
		return c.b.AlgorithmByName("ssh", sshType)
	}
	return ""
}

// key は鍵の資産 ID を決めて登録する。同じ鍵は形式が違っても同じ資産になるよう、公開鍵の指紋を優先する。
// 公開成分が得られない鍵（暗号化された鍵など）は、内容ではなく場所から ID を作る。
func (c *Collector) key(it keymat.Item, path string) string {
	k := it.Key
	prefix := "key:private:"
	if it.Kind == "public-key" {
		prefix = "key:public:"
	}
	var id string
	switch {
	case k.SPKISHA256 != "":
		id = prefix + "spki-sha256:" + k.SPKISHA256
	case k.SSHFingerprint != "":
		id = prefix + "ssh:" + k.SSHFingerprint
	default:
		id = prefix + inventory.LocationID(path, it.Index)
	}
	a := c.b.Asset(id, func() model.Asset {
		return model.Asset{Type: it.Kind, Key: &model.Key{
			Algorithm:               c.keyAlgorithm(k.AlgOID, k.CurveOID, k.SSHType, k.Bits),
			PublicFingerprintSHA256: k.SPKISHA256,
		}}
	})
	if a.Key.SSHFingerprint == "" {
		a.Key.SSHFingerprint = k.SSHFingerprint
	}
	return id
}

func (c *Collector) keyDetail(it keymat.Item) *model.Detail {
	d := &model.Detail{Format: it.Format}
	if it.Kind == "private-key" {
		enc := it.Key.Encrypted
		d.Encrypted = &enc
		if it.Key.Enc != nil {
			scheme := "openssl" // PEM の DEK-Info は OpenSSL の暗号名
			if it.Format == "openssh" {
				scheme = "ssh"
			}
			d.Protection = c.protection(*it.Key.Enc, scheme)
		}
	}
	return d
}

func (c *Collector) protection(e keymat.Encryption, nameScheme string) *model.Protection {
	p := &model.Protection{
		Scheme:     c.b.AlgorithmByOID(e.SchemeOID),
		KDF:        c.b.AlgorithmByOID(e.KDFOID),
		PRF:        c.b.AlgorithmByOID(e.PRFOID),
		Cipher:     c.b.AlgorithmByOID(e.CipherOID),
		Iterations: e.Iterations,
	}
	if p.Cipher == "" {
		p.Cipher = c.b.AlgorithmByName(nameScheme, e.Name)
	}
	if p.KDF == "" && e.KDFName != "" && e.KDFName != "none" {
		p.KDF = c.b.AlgorithmByName(nameScheme, e.KDFName)
	}
	return p
}

func (c *Collector) addKeystore(s *keystore.Store, path string) {
	id := "keystore:" + inventory.LocationID(path, 0)
	c.b.Asset(id, func() model.Asset {
		ks := &model.Keystore{
			Format: s.Format,
			Entries: map[string]int{
				"private_keys": s.Entries.PrivateKeys, "trusted_certificates": s.Entries.TrustedCerts,
				"certificates": s.Entries.Certificates, "secret_keys": s.Entries.SecretKeys, "other": s.Entries.Other,
			},
			Unreadable: s.Opaque, PartiallyRead: s.Truncated,
		}
		if s.MAC != nil {
			ks.Integrity = &model.Integrity{Algorithm: c.b.AlgorithmByOID(s.MAC.DigestOID), Iterations: s.MAC.Iterations}
			if ks.Integrity.Algorithm == "" {
				ks.Integrity.Algorithm = c.b.AlgorithmByName("java", s.MAC.Name)
			}
		}
		for _, sec := range s.Containers {
			ms := model.Section{Encrypted: sec.Encrypted}
			if sec.Enc != nil {
				ms.Protection = c.protection(*sec.Enc, "openssl")
			}
			ks.Sections = append(ks.Sections, ms)
		}
		for _, kp := range s.KeyProtections {
			ks.KeyProtections = append(ks.KeyProtections, *c.protection(kp, "openssl"))
		}
		return model.Asset{Type: "keystore", Keystore: ks}
	})
	c.b.Occur(id, collector, model.Location{Kind: "file", Path: path}, &model.Detail{Format: s.Format})
	for i, cert := range s.Certs {
		c.b.Occur(c.certificate(cert), collector, model.Location{Kind: "file", Path: path, Index: i, Container: s.Format}, nil)
	}
}
