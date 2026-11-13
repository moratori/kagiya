// Package jsse は、Java の TLS（JSSE）が受け入れるプロトコル、暗号スイート、鍵交換のグループを、Java を動かさずに求める。
//
// JDK が対応しているもの（パッケージ版ごとの実測の表）から、セキュリティの設定（jdk.tls.disabledAlgorithms）で
// 無効にされたものを除く。解釈のしかたは、検証ラボで実物の JDK の結果をすべて再現することを確かめたものだけを実装している。
// 実測で確かめていない書き方は、推測で当てはめず、「求められない」として理由を返す。
package jsse

import (
	"regexp"
	"strconv"
	"strings"

	"kagiya/internal/ruleset"
)

// Input は、解釈の対象になる設定値。
type Input struct {
	Disabled    string            // jdk.tls.disabledAlgorithms の値
	Properties  map[string]string // 「include 名前」で取り込まれる、ほかのセキュリティの設定値
	NamedGroups string            // システムプロパティ jdk.tls.namedGroups の値（指定がなければ空）
}

// Result は、求めた結果。
type Result struct {
	Protocols []string // サーバーで既定で有効なプロトコル
	Suites    []string // サーバーで既定で有効な暗号スイート（JDK の並び）
	Supported []string // アプリが明示的に有効にできる暗号スイート（無効にされたものを除く。プロトコルによる絞り込みはしない）
	Groups13  []string // TLS 1.3 で受け入れる鍵交換のグループ（本体での正式な名前）
	Groups12  []string // TLS 1.2 以下の ECDHE で受け入れる鍵交換のグループ
	// 空でなければ、鍵交換のグループは求められない（理由）。このとき Groups13 と Groups12 は空
	GroupsBlocker string
}

// Constraints は、無効にする方式の設定を解釈したもの。
type Constraints struct {
	table    *ruleset.JDKTable
	names    map[string]bool // 名前だけの項目（小文字）
	patterns []string        // 名前のパターン（小文字。「*」は任意の文字列）
	limits   map[string]int  // 「EC keySize < 384」の形の条件: 種類（大文字）→ 下限
	blocker  string          // 空でなければ、グループを求められない理由
}

const scsv = "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"

const maxIncludeDepth = 4

var keySizePattern = regexp.MustCompile(`^(\w+)\s+keySize\s*(<=|>=|==|!=|<|>)\s*(\d+)$`)

// Parse は、jdk.tls.disabledAlgorithms の値を解釈する。props は、include で取り込まれるほかの設定値。
func Parse(t *ruleset.JDKTable, disabled string, props map[string]string) *Constraints {
	c := &Constraints{table: t, names: map[string]bool{}, limits: map[string]int{}}
	c.add(disabled, props, 0)
	return c
}

func (c *Constraints) block(reason string) {
	if c.blocker == "" {
		c.blocker = reason
	}
}

func (c *Constraints) add(text string, props map[string]string, depth int) {
	for _, item := range strings.Split(text, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		words := strings.Fields(item)
		if words[0] == "include" && len(words) == 2 {
			v, ok := props[words[1]]
			switch {
			case depth >= maxIncludeDepth:
				c.block("the include in jdk.tls.disabledAlgorithms is nested too deep")
			case !ok:
				c.block("jdk.tls.disabledAlgorithms includes " + words[1] + ", which is not set")
			default:
				c.add(v, props, depth+1)
			}
			continue
		}
		if len(words) > 1 {
			// 条件つきの項目。鍵長の条件はグループに及ぶ（「<」だけを実測で確かめている）。
			// それ以外（用途の条件など）は、プロトコル、スイート、グループの一覧に影響しない（既定の設定に含まれ、実測と一致している）
			if m := keySizePattern.FindStringSubmatch(item); m != nil {
				kind := strings.ToUpper(m[1])
				if kind != "EC" && kind != "DH" {
					continue
				}
				n, err := strconv.Atoi(m[3])
				if m[2] != "<" || err != nil {
					c.block("the key size constraint \"" + item + "\" uses a form that has not been measured")
					continue
				}
				if n > c.limits[kind] {
					c.limits[kind] = n
				}
			}
			continue
		}
		if strings.Contains(item, "*") {
			if c.table.Wildcard {
				c.patterns = append(c.patterns, strings.ToLower(item))
			}
			continue // 名前のパターンを解釈しない版では、その項目は何も無効にしない
		}
		c.names[strings.ToLower(item)] = true
	}
}

// globMatch は、「*」を任意の文字列として、名前の全体がパターンに当たるかを返す。
func globMatch(pattern, name string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == name
	}
	if !strings.HasPrefix(name, parts[0]) {
		return false
	}
	name = name[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, p := range parts[1 : len(parts)-1] {
		i := strings.Index(name, p)
		if i < 0 {
			return false
		}
		name = name[i+len(p):]
	}
	return strings.HasSuffix(name, last)
}

func (c *Constraints) nameDisabled(name string) bool {
	l := strings.ToLower(name)
	if c.names[l] {
		return true
	}
	for _, p := range c.patterns {
		if globMatch(p, l) {
			return true
		}
	}
	return false
}

func (c *Constraints) suiteDisabled(suite string) bool {
	if c.nameDisabled(suite) {
		return true
	}
	for _, part := range decompose(suite) {
		if c.names[strings.ToLower(part)] {
			return true
		}
	}
	return false
}

// ProtocolAllowed は、そのプロトコルが無効にされていないかを返す。
func (c *Constraints) ProtocolAllowed(protocol string) bool { return !c.nameDisabled(protocol) }

// SuiteAllowed は、その暗号スイートを、この JDK が知っていて、かつ無効にされていないかを返す
// （アプリの設定に書かれたスイートを絞り込むのに使う。プロトコルによる絞り込みはしない）。
func (c *Constraints) SuiteAllowed(suite string) bool {
	for _, s := range c.table.Suites {
		if s.Name == suite {
			return !c.suiteDisabled(suite)
		}
	}
	return false
}

// スイートの名前の部品 → 無効にする方式と照合する語。JDK がスイートを分解して照合するのを再現したもので、
// どの語が効くかは、場面を変えた実測（名前、鍵交換、暗号、ハッシュを 1 つずつ無効にした結果）で確かめている。
var (
	kxWords = map[string][]string{
		"RSA": {"RSA"}, "RSA_EXPORT": {"RSA", "RSA_EXPORT"},
		"DH_RSA": {"RSA", "DH", "DiffieHellman", "DH_RSA"}, "DH_DSS": {"DSA", "DSS", "DH", "DiffieHellman", "DH_DSS"},
		"DHE_DSS": {"DSA", "DSS", "DH", "DHE", "DiffieHellman", "DHE_DSS"}, "DHE_RSA": {"RSA", "DH", "DHE", "DiffieHellman", "DHE_RSA"},
		"DH_anon":    {"ANON", "DH", "DiffieHellman", "DH_ANON"},
		"ECDH_ECDSA": {"ECDH", "ECDSA", "ECDH_ECDSA"}, "ECDH_RSA": {"ECDH", "RSA", "ECDH_RSA"},
		"ECDHE_ECDSA": {"ECDHE", "ECDSA", "ECDHE_ECDSA"}, "ECDHE_RSA": {"ECDHE", "RSA", "ECDHE_RSA"},
		"ECDH_anon": {"ANON", "ECDH", "ECDH_ANON"},
		"KRB5":      {"KRB5"}, "KRB5_EXPORT": {"KRB5_EXPORT"},
		"DHE_DSS_EXPORT": {"DSA", "DSS", "DH", "DHE", "DiffieHellman", "DHE_DSS_EXPORT"},
		"DHE_RSA_EXPORT": {"RSA", "DH", "DHE", "DiffieHellman", "DHE_RSA_EXPORT"},
		"DH_anon_EXPORT": {"ANON", "DH", "DiffieHellman", "DH_ANON_EXPORT"},
	}
	encWords = map[string][]string{
		"NULL": {"C_NULL", "NULL"}, "RC2_CBC_40": {"RC2_CBC_40", "RC2", "CBC"}, "RC4_40": {"RC4_40", "RC4"}, "RC4_128": {"RC4_128", "RC4"},
		"DES40_CBC": {"DES40_CBC", "DES_CBC_40", "DES", "CBC", "NoPadding"}, "DES_CBC_40": {"DES_CBC_40", "DES40_CBC", "DES", "CBC", "NoPadding"},
		"DES_CBC": {"DES_CBC", "DES", "CBC", "NoPadding"}, "3DES_EDE_CBC": {"3DES_EDE_CBC", "DESede", "CBC", "NoPadding"},
		"AES_128_CBC": {"AES_128_CBC", "AES", "CBC", "NoPadding"}, "AES_256_CBC": {"AES_256_CBC", "AES", "CBC", "NoPadding"},
		"AES_128_GCM": {"AES_128_GCM", "AES", "GCM", "NoPadding"}, "AES_256_GCM": {"AES_256_GCM", "AES", "GCM", "NoPadding"},
		"CHACHA20_POLY1305": {"CHACHA20_POLY1305", "ChaCha20-Poly1305"},
	}
	macWords = map[string][]string{
		"NULL": {"M_NULL"}, "MD5": {"MD5", "HmacMD5"}, "SHA": {"SHA1", "SHA-1", "HmacSHA1"},
		"SHA256": {"SHA256", "SHA-256", "HmacSHA256"}, "SHA384": {"SHA384", "SHA-384", "HmacSHA384"},
	}
	// 名前の末尾（MAC またはハッシュ）。長いものから照合する
	macSuffixes = []string{"SHA256", "SHA384", "NULL", "MD5", "SHA"}
)

func isAEAD(enc string) bool {
	return strings.Contains(enc, "GCM") || strings.Contains(enc, "POLY1305") || strings.Contains(enc, "CCM")
}

// decompose は、暗号スイートの名前を、無効にする方式と照合する語に分ける。
func decompose(suite string) []string {
	var out []string
	rest := suite
	if i := strings.Index(suite, "_WITH_"); i >= 0 && (strings.HasPrefix(suite, "TLS_") || strings.HasPrefix(suite, "SSL_")) {
		kx := suite[4:i]
		rest = suite[i+len("_WITH_"):]
		if w, ok := kxWords[kx]; ok {
			out = append(out, w...)
		} else {
			out = append(out, kx)
		}
	} else {
		rest = strings.TrimPrefix(suite, "TLS_") // TLS 1.3 のスイート（鍵交換と認証を含まない）
	}
	enc, last := rest, ""
	for _, m := range macSuffixes {
		if strings.HasSuffix(rest, "_"+m) {
			enc, last = rest[:len(rest)-len(m)-1], m
			break
		}
	}
	if w, ok := encWords[enc]; ok {
		out = append(out, w...)
	} else {
		out = append(out, enc)
	}
	if last != "" {
		if !isAEAD(enc) {
			out = append(out, macWords[last]...)
		} else if last == "SHA256" || last == "SHA384" {
			out = append(out, macWords[last]...) // 認証付き暗号のスイートでは、末尾はハッシュ（同じ語で照合される）
		}
	}
	return out
}

func tls13Only(suite string) bool { return !strings.Contains(suite, "_WITH_") }

// needsTLS12 は、TLS 1.2 でしか使えないスイート（認証付き暗号、または SHA-256 / SHA-384 の MAC）かを返す。
func needsTLS12(suite string) bool {
	return strings.Contains(suite, "_GCM") || strings.Contains(suite, "_CCM") || strings.Contains(suite, "_POLY1305") ||
		strings.HasSuffix(suite, "_SHA256") || strings.HasSuffix(suite, "_SHA384")
}

// Resolve は、表と設定値から、既定で受け入れるプロトコル、暗号スイート、鍵交換のグループを求める。
func Resolve(t *ruleset.JDKTable, in Input) Result {
	c := Parse(t, in.Disabled, in.Properties)
	var r Result
	on := map[string]bool{}
	for _, p := range t.Protocols {
		if p.Default && c.ProtocolAllowed(p.Name) {
			r.Protocols = append(r.Protocols, p.Name)
			on[p.Name] = true
		}
	}
	old := on["TLSv1.2"] || on["TLSv1.1"] || on["TLSv1"] || on["SSLv3"] // TLS 1.2 以下のどれかが有効
	for _, s := range t.Suites {
		if s.Name == scsv {
			// 再ネゴシエーションの印。無効化の対象外で、既定の一覧には TLS 1.2 以下のどれかが有効なときだけ入る
			r.Supported = append(r.Supported, s.Name)
			if s.Default && old {
				r.Suites = append(r.Suites, s.Name)
			}
			continue
		}
		if c.suiteDisabled(s.Name) {
			continue
		}
		r.Supported = append(r.Supported, s.Name)
		if !s.Default {
			continue
		}
		switch {
		case tls13Only(s.Name):
			if !on["TLSv1.3"] {
				continue
			}
		case !old, needsTLS12(s.Name) && !on["TLSv1.2"]:
			continue
		}
		r.Suites = append(r.Suites, s.Name)
	}
	r.Groups13, r.Groups12, r.GroupsBlocker = c.groups(in.NamedGroups, on, old)
	return r
}

func (c *Constraints) groups(named string, on map[string]bool, old bool) (g13, g12 []string, blocker string) {
	if c.blocker != "" {
		return nil, nil, c.blocker
	}
	var want map[string]bool
	if strings.TrimSpace(named) != "" {
		known := map[string]bool{}
		for _, g := range c.table.Groups {
			known[strings.ToLower(g.JSSE)] = true
		}
		unusable := map[string]bool{}
		for _, n := range c.table.UnusableGroups {
			unusable[strings.ToLower(n)] = true
		}
		want = map[string]bool{}
		for _, n := range strings.Split(named, ",") {
			n = strings.ToLower(strings.TrimSpace(n))
			if n == "" {
				continue
			}
			if unusable[n] {
				continue // 名前を挙げても、その版が受け入れなかったグループ（実測）
			}
			if !known[n] {
				// 既定では受け入れないグループを足す指定。その版がそのグループを使えるかは測っていない
				return nil, nil, "jdk.tls.namedGroups names a group that is not in the measured table: " + n
			}
			want[n] = true
		}
	}
	for _, g := range c.table.Groups {
		if want != nil && !want[strings.ToLower(g.JSSE)] {
			continue
		}
		if c.table.DisableGroupsByName && c.nameDisabled(g.JSSE) {
			continue
		}
		if kind, bits, ok := strings.Cut(g.Key, " "); ok {
			if n, err := strconv.Atoi(bits); err == nil && n < c.limits[kind] {
				continue
			}
		}
		if g.TLS13 && on["TLSv1.3"] {
			g13 = append(g13, g.Name)
		}
		// TLS 1.2 以下の鍵交換（ECDHE）のグループは、TLS 1.2 以下のどれかが有効なら受け入れる（実測）
		if g.TLS12 && old {
			g12 = append(g12, g.Name)
		}
	}
	return g13, g12, ""
}
