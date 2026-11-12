// Package tlseffective は、OpenSSL を使う TLS サーバーが実際に使える暗号スイートを求める。
//
// アプリ（nginx、Apache httpd など）によらない共通の部品。アプリごとの事情（設定のどの記載が効くか、既定の暗号文字列、
// DH パラメータを持つか）は呼び出し側が入力として渡す。ここでは次の順に絞り込む。
//
//  1. 暗号文字列を、その版の OpenSSL と同じ手順で展開する（tlsciphers）。
//  2. セキュリティレベルで使えるものに絞る。レベルは、暗号文字列の指定 > システムの openssl.cnf > ライブラリの既定の順で決まる。
//  3. アプリ側の追加の設定（事前共有鍵の PSK、SRP）が要るものを除く。
//  4. サーバーの証明書の種類に合う認証方式のものに絞る。
//  5. DH パラメータがなければ、DHE（一時的な DH 鍵交換）のものを除く。
//
// この手順で求めた結果が、実際に起動した nginx と Apache httpd が受け入れるスイートと一致することを、テストで確かめている。
package tlseffective

import (
	"strings"

	"kagiya/internal/ruleset"
	"kagiya/internal/tlsciphers"
)

// Cert は、サーバーの証明書の種類。
type Cert struct {
	Key       string // 鍵の種類: RSA | EC | DSA | other
	Signature string // 証明書の署名の種類: RSA | ECDSA | DSA | other
}

type Input struct {
	Table        *ruleset.CipherTable
	CipherString string
	Profile      *string  // 「PROFILE=SYSTEM」が指す暗号文字列。読めていなければ nil
	SystemLevel  int      // システムの openssl.cnf が決めるセキュリティレベル。なければ負
	SystemTLS13  []string // システムの openssl.cnf が決める TLS 1.3 のスイート。なければ nil
	Certs        []Cert
	CertsKnown   bool // 証明書の種類が分かっている
	DHE          bool // DH パラメータがあり、DHE を使える
	DHEKnown     bool
}

type Output struct {
	Suites      []string // TLS 1.2 以下のスイート（優先順）
	TLS13       []string // TLS 1.3 のスイート（優先順）。TLS 1.3 が有効な場合に使われる
	Level       int      // 適用したセキュリティレベル。レベルのない版は -1
	LevelSource string   // cipher-string | system | library-default。レベルのない版は空
	Ignored     []string // この版が知らないために無視された語
	Unfiltered  []string // 情報がなくてできなかった絞り込み（certificates、dh-parameters）
}

// Resolve は、サーバーが実際に使える暗号スイートを求める。暗号文字列を展開できない場合は tlsciphers のエラーを返す。
func Resolve(in Input) (Output, error) {
	out := Output{Level: -1}
	x, err := tlsciphers.Expand(in.Table, in.CipherString, in.Profile)
	out.Ignored = x.Ignored
	if err != nil {
		return out, err
	}
	suites := x.Suites
	if in.Table.SecurityLevels && in.Table.DefaultLevel != nil {
		switch {
		case x.Level >= 0:
			out.Level, out.LevelSource = x.Level, "cipher-string"
		case in.SystemLevel >= 0:
			out.Level, out.LevelSource = in.SystemLevel, "system"
		default:
			out.Level, out.LevelSource = *in.Table.DefaultLevel, "library-default"
		}
		suites, _ = tlsciphers.Usable(in.Table, suites, out.Level)
	}
	attrs := make(map[string]ruleset.CipherSuite, len(in.Table.Suites))
	for _, c := range in.Table.Suites {
		attrs[c.Name] = c
	}
	hasDH := false
	for _, n := range suites {
		c := attrs[n]
		if needsAppSetup(c) {
			continue
		}
		if in.CertsKnown && !certOK(c, in.Certs) {
			continue
		}
		if c.Kx == "DH" {
			if in.DHEKnown && !in.DHE {
				continue
			}
			hasDH = true
		}
		out.Suites = append(out.Suites, n)
	}
	if !in.CertsKnown {
		out.Unfiltered = append(out.Unfiltered, "certificates")
	}
	if !in.DHEKnown && hasDH {
		out.Unfiltered = append(out.Unfiltered, "dh-parameters")
	}

	// TLS 1.3 のスイートは暗号文字列では決まらない。システムの設定があればそれ、なければライブラリの既定。
	known := make(map[string]ruleset.CipherSuite, len(in.Table.TLS13))
	for _, c := range in.Table.TLS13 {
		known[c.Name] = c
	}
	base := in.SystemTLS13
	if base == nil {
		base = tlsciphers.DefaultTLS13(in.Table)
	}
	for _, n := range base {
		c, ok := known[n]
		if !ok {
			out.Ignored = append(out.Ignored, n)
			continue
		}
		if out.Level >= 0 && (c.Level == nil || out.Level > *c.Level) {
			continue
		}
		out.TLS13 = append(out.TLS13, n)
	}
	return out, nil
}

// needsAppSetup は、アプリ側の追加の設定（事前共有鍵、SRP の検証情報）がないと使えないスイートかを返す。
func needsAppSetup(c ruleset.CipherSuite) bool {
	return strings.Contains(c.Kx, "PSK") || strings.Contains(c.Kx, "SRP") || c.Au == "PSK" || c.Au == "SRP"
}

// certOK は、サーバーの証明書でこのスイートの認証ができるかを返す。
func certOK(c ruleset.CipherSuite, certs []Cert) bool {
	has := func(key, sig string) bool {
		for _, x := range certs {
			if x.Key == key && (sig == "" || x.Signature == sig) {
				return true
			}
		}
		return false
	}
	switch c.Kx {
	case "ECDH/RSA": // 固定の ECDH。EC の証明書（RSA で署名されたもの）が要る
		return has("EC", "RSA")
	case "ECDH/ECDSA":
		return has("EC", "ECDSA")
	}
	switch c.Au {
	case "None":
		return true // 匿名（証明書を使わない）
	case "RSA":
		return has("RSA", "")
	case "ECDSA":
		return has("EC", "")
	case "DSS":
		return has("DSA", "")
	}
	return false
}
