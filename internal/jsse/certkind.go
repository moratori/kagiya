// このファイルは、サーバーの証明書の種類による、暗号スイートの絞り込み。

package jsse

import "strings"

// renegotiationMarker は、再ネゴシエーションの印。JDK は暗号スイートの一覧に入れて報告するが、暗号スイートではない。
const renegotiationMarker = "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"

// CertificateKind は、TLS 1.2 以下のスイートの名前から、サーバーの証明書に求める鍵の種類（"RSA"、"EC"、"DSA"）を返す。
// 証明書によらないスイート（認証なしのもの、TLS 1.3 のもの）と、決められないものは、空を返す。
func CertificateKind(suite string) string {
	kx, _, ok := strings.Cut(suite, "_WITH_")
	if !ok {
		return ""
	}
	kx = strings.TrimPrefix(strings.TrimPrefix(kx, "TLS_"), "SSL_")
	switch {
	case strings.HasSuffix(kx, "ECDSA"):
		return "EC"
	case strings.HasSuffix(kx, "DSS") || strings.HasPrefix(kx, "DHE_DSS") || strings.HasPrefix(kx, "DH_DSS"):
		return "DSA"
	case strings.HasPrefix(kx, "RSA") || strings.HasSuffix(kx, "_RSA") || strings.Contains(kx, "_RSA_"):
		return "RSA"
	}
	return ""
}

// SplitByCertificate は、スイートの一覧を、TLS 1.2 以下のものと TLS 1.3 のものに分け、TLS 1.2 以下のものを、サーバーの証明書で使えるものに絞る。
// 並びは保つ。再ネゴシエーションの印は、どちらにも入れない。
//
// kinds は、サーバーが持つ証明書の鍵の種類。nil は「種類が分からない」を表し、その場合は、RSA の証明書の場合と EC の証明書の場合に
// 使えるものを合わせる（DSA の証明書でしか使えないものは、入れない。docs/confidence.md の 6.5 節）。
func SplitByCertificate(suites []string, kinds map[string]bool) (tls12, tls13 []string) {
	for _, s := range suites {
		switch need := CertificateKind(s); {
		case s == renegotiationMarker:
		case tls13Only(s):
			tls13 = append(tls13, s)
		case need == "": // 証明書によらない
			tls12 = append(tls12, s)
		case kinds == nil && need != "DSA", kinds[need]:
			tls12 = append(tls12, s)
		}
	}
	return tls12, tls13
}
