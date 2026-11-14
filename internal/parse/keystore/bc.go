package keystore

import (
	"encoding/binary"

	"kagiya/internal/parse/der"
	"kagiya/internal/parse/keymat"
	"kagiya/internal/parse/x509cert"
)

// このファイルは、Bouncy Castle 形式のキーストア（BKS / UBER / BCFKS）の読み取り。
// 形式は、検証ラボで実物の Bouncy Castle（bcprov-jdk18on 1.87）と keytool で作ったキーストアで確かめた。
//
//	BKS  : 版（4 バイト。新しいものは 2、古いものは 1）、ソルトの長さと中身、反復回数、エントリの並び、0、HMAC-SHA1。
//	       エントリは「種類（1 バイト）、別名、日時（8 バイト）、証明書チェーン、中身」。
//	       証明書のエントリ（種類 1）は暗号化されておらず、パスワードなしで読める。鍵のエントリ（種類 4）は暗号化されている。
//	UBER : 版（1）、ソルト、反復回数。その後ろは、全体が暗号化されている（証明書も読めない）。
//	BCFKS: ASN.1。PBES2 で暗号化されたデータと、完全性の検査の値。証明書を含めて全体が暗号化されている。

const (
	bcMaxSalt       = 64
	bcMaxIterations = 10_000_000
	bcMaxAlias      = 1024
	bcMaxChain      = 64
	bcMaxBlob       = 1 << 24
	oidBCFKSPBES2   = "1.2.840.113549.1.5.13"

	bksCertificate = 1 // エントリの種類
	bksKey         = 2
	bksSecret      = 3
	bksSealed      = 4
)

// parseBouncyCastle は、BKS と UBER を読む。どちらでもなければ ok = false。
func parseBouncyCastle(data []byte) (*Store, bool) {
	if len(data) < 12 {
		return nil, false
	}
	version := binary.BigEndian.Uint32(data)
	if version != 1 && version != 2 {
		return nil, false
	}
	r := &reader{b: data}
	r.take(4)
	salt := r.u32()
	if salt < 1 || salt > bcMaxSalt {
		return nil, false
	}
	r.take(salt)
	iterations := r.u32()
	if r.bad || iterations < 1 || iterations > bcMaxIterations {
		return nil, false
	}
	body := r.b
	s := &Store{Format: "bks", MAC: &MAC{Name: "hmac-sha1", Iterations: iterations}}
	if entries, ok := s.bksEntries(body); ok && entries > 0 {
		return s, true
	}
	// 版 1 で、エントリの並びとして読めないものは UBER（全体が暗号化されている）。短すぎるものは対象にしない
	if version == 1 && len(body) >= 32 {
		return &Store{Format: "uber", Opaque: true}, true
	}
	return nil, false
}

// bksEntries は、BKS のエントリの並びを読む。並びとして読めた数を返す。最初のエントリから読めなければ ok = false。
func (s *Store) bksEntries(body []byte) (n int, ok bool) {
	r := &reader{b: body}
	cert := func() bool {
		kind := r.take(r.u16()) // 証明書の種類（"X.509"）
		size := r.u32()
		if r.bad || len(kind) == 0 || len(kind) > 32 || size > bcMaxBlob {
			r.bad = true
			return false
		}
		raw := r.take(size)
		if r.bad {
			return false
		}
		if c, err := x509cert.Parse(raw); err == nil {
			s.Certs = append(s.Certs, c)
		}
		return true
	}
	for n < maxEntries {
		tag := r.take(1)
		if r.bad {
			break
		}
		if tag[0] == 0 {
			return n, true // 並びの終わり。この後ろは HMAC
		}
		if tag[0] > bksSealed {
			if n == 0 {
				return 0, false
			}
			break
		}
		alias := r.u16()
		if alias > bcMaxAlias {
			r.bad = true
		}
		r.take(alias) // 別名（出力しない）
		r.take(8)     // 作成日時
		chain := r.u32()
		if r.bad || chain > bcMaxChain {
			r.bad = true
			break
		}
		for i := 0; i < chain; i++ {
			if !cert() {
				break
			}
		}
		if r.bad {
			break
		}
		switch tag[0] {
		case bksCertificate:
			if !cert() {
				break
			}
			s.Entries.TrustedCerts++
		case bksSecret, bksSealed:
			size := r.u32()
			if size > bcMaxBlob {
				r.bad = true
				break
			}
			r.take(size) // 暗号化された鍵
			if r.bad {
				break
			}
			s.Opaque = true
			// 証明書チェーンを持つものは秘密鍵、持たないものは共通鍵
			if chain > 0 {
				s.Entries.PrivateKeys++
			} else {
				s.Entries.SecretKeys++
			}
		default:
			// 暗号化されていない鍵のエントリ（種類 2）は、長さを持つ形ではないので、ここで打ち切る
			s.Entries.Other++
			s.Truncated = true
			return n + 1, true
		}
		if r.bad {
			break
		}
		n++
	}
	if n == 0 {
		return 0, false
	}
	s.Truncated = true
	return n, true
}

// parseBCFKS は、BCFKS を読む。先頭が「PBES2 で暗号化されたデータ」でなければ ok = false。
func parseBCFKS(data []byte) (*Store, bool) {
	top, rest, err := der.Read(data)
	if err != nil || len(rest) != 0 {
		return nil, false
	}
	parts, ok := seqChildren(top)
	if !ok || len(parts) != 2 {
		return nil, false
	}
	enc, ok := seqChildren(parts[0])
	if !ok || len(enc) != 2 {
		return nil, false
	}
	alg, ok := seqChildren(enc[0])
	if !ok || len(alg) == 0 || oidOf(alg[0]) != oidBCFKSPBES2 {
		return nil, false
	}
	s := &Store{Format: "bcfks", Opaque: true}
	if e, ok := keymat.ParsePBE(enc[0]); ok {
		s.addKeyProtection(e)
	}
	return s, true
}
