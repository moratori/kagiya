package ruleset

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// PolicyRef は、評価の根拠にした文書。
type PolicyRef struct {
	ID    string `yaml:"id"`
	Title string `yaml:"title"`
	URL   string `yaml:"url"`
	Note  string `yaml:"note"` // その文書のどこに何が書かれているか
}

// PolicyMatch は、規則が当たる条件。
type PolicyMatch struct {
	Names     []string `yaml:"names"`     // 名前（「*」は任意の文字列）。catalog ではカタログの ID
	Family    []string `yaml:"family"`    // catalog のみ: アルゴリズムファミリ
	Primitive []string `yaml:"primitive"` // catalog のみ: 種別
	MinBits   int      `yaml:"min_bits"`  // catalog のみ: 鍵長の下限（鍵長が分かっている場合にだけ当たる）
	MaxBits   int      `yaml:"max_bits"`  // catalog のみ: 鍵長の上限
}

// PolicyRule は、評価の規則1つ。根拠（Refs）が必須。
type PolicyRule struct {
	ID        string      `yaml:"id"`
	Scheme    string      `yaml:"scheme"`
	Match     PolicyMatch `yaml:"match"`
	Role      string      `yaml:"role"`
	Quantum   string      `yaml:"quantum"`
	Classical string      `yaml:"classical"`
	Tags      []string    `yaml:"tags"`
	Summary   string      `yaml:"summary"`
	Refs      []string    `yaml:"refs"`
}

// Policy は評価ポリシー。見つかった暗号を、量子計算機に対する評価と、現在の計算機に対する評価の2軸で判定する。
type Policy struct {
	ID         string       `yaml:"id"`
	Title      string       `yaml:"title"`
	Version    string       `yaml:"version"`
	References []PolicyRef  `yaml:"references"`
	Rules      []PolicyRule `yaml:"rules"`
}

type policyFile struct {
	Policy *Policy `yaml:"policy"`
}

// 評価の値と、厳しさの順（大きいほど厳しい）。1つの対象に複数の規則が当たったら、軸ごとに最も厳しいものを採る。
var (
	QuantumRank   = map[string]int{"vulnerable": 6, "unknown": 5, "reduced": 4, "hybrid": 3, "resistant": 2, "not-targeted": 1}
	ClassicalRank = map[string]int{"weak": 4, "legacy": 3, "unknown": 2, "ok": 1}

	policySchemes = map[string]bool{"catalog": true, "tls-kx": true, "tls-au": true, "tls-enc": true, "tls-mac": true,
		"tls-protocol": true, "tls-group": true, "ssh-kex": true, "ssh-key": true, "ssh-cipher": true, "ssh-mac": true}
	policyRoles = map[string]bool{"": true, "key-establishment": true, "signature": true, "public-key": true,
		"encryption": true, "hash": true, "mac": true, "kdf": true, "protocol": true}
)

func (rs *RuleSet) addPolicy(p *Policy, ids map[string]bool) error {
	if p == nil || !idPattern.MatchString(p.ID) || p.Title == "" || len(p.Title) > 256 || !pkgVersionPattern.MatchString(p.Version) {
		return errors.New("policy needs an id, a title and a version")
	}
	where := "policy " + p.ID
	if ids["policy\x00"+p.ID] {
		return fmt.Errorf("%s: duplicate policy", where)
	}
	ids["policy\x00"+p.ID] = true
	if len(p.References) == 0 {
		return fmt.Errorf("%s: at least one reference is required", where)
	}
	refs := map[string]bool{}
	for _, r := range p.References {
		if !idPattern.MatchString(r.ID) || refs[r.ID] || r.Title == "" || len(r.Title) > 512 || len(r.Note) > 2048 ||
			!strings.HasPrefix(r.URL, "https://") || len(r.URL) > 512 || strings.ContainsAny(r.URL, " \t\r\n\"'<>") {
			return fmt.Errorf("%s: invalid reference %q (an id, a title and an https URL are required)", where, r.ID)
		}
		refs[r.ID] = true
	}
	if len(p.Rules) == 0 || len(p.Rules) > 5000 {
		return fmt.Errorf("%s: invalid number of rules", where)
	}
	seen := map[string]bool{}
	for _, r := range p.Rules {
		if !idPattern.MatchString(r.ID) || seen[r.ID] {
			return fmt.Errorf("%s: invalid or duplicate rule id %q", where, r.ID)
		}
		seen[r.ID] = true
		rule := where + ": rule " + r.ID
		if !policySchemes[r.Scheme] || !policyRoles[r.Role] {
			return fmt.Errorf("%s: unknown scheme or role", rule)
		}
		if r.Quantum == "" && r.Classical == "" {
			return fmt.Errorf("%s: a verdict (quantum or classical) is required", rule)
		}
		if (r.Quantum != "" && QuantumRank[r.Quantum] == 0) || (r.Classical != "" && ClassicalRank[r.Classical] == 0) {
			return fmt.Errorf("%s: unknown verdict value", rule)
		}
		if r.Summary == "" || len(r.Summary) > 1024 {
			return fmt.Errorf("%s: a summary is required", rule)
		}
		if len(r.Refs) == 0 {
			return fmt.Errorf("%s: at least one reference is required", rule)
		}
		for _, id := range r.Refs {
			if !refs[id] {
				return fmt.Errorf("%s: unknown reference %q", rule, id)
			}
		}
		for _, t := range r.Tags {
			if !idPattern.MatchString(t) {
				return fmt.Errorf("%s: invalid tag", rule)
			}
		}
		m := r.Match
		if len(m.Names) == 0 && len(m.Family) == 0 && len(m.Primitive) == 0 && m.MinBits == 0 && m.MaxBits == 0 {
			return fmt.Errorf("%s: the match condition is empty", rule)
		}
		if r.Scheme != "catalog" && (len(m.Family) > 0 || len(m.Primitive) > 0 || m.MinBits != 0 || m.MaxBits != 0) {
			return fmt.Errorf("%s: family, primitive and key length can be used only with the catalog scheme", rule)
		}
		if m.MinBits < 0 || m.MaxBits < 0 || (m.MaxBits != 0 && m.MinBits > m.MaxBits) {
			return fmt.Errorf("%s: invalid key length range", rule)
		}
		for _, n := range m.Names {
			if n == "" || len(n) > 128 {
				return fmt.Errorf("%s: invalid name", rule)
			}
			if _, err := path.Match(n, "x"); err != nil {
				return fmt.Errorf("%s: invalid name pattern %q", rule, n)
			}
		}
	}
	rs.Policies = append(rs.Policies, p)
	return nil
}

// Policy は、ID で評価ポリシーを返す。
func (rs *RuleSet) Policy(id string) (*Policy, bool) {
	for _, p := range rs.Policies {
		if p.ID == id {
			return p, true
		}
	}
	return nil, false
}

// SuiteAttributes は、暗号スイートの名前から属性（鍵交換、認証、暗号化、MAC）を返す。
// 同じ名前のスイートは、どの版の対応表でも同じ属性を持つ（テストで確かめている）。
func (rs *RuleSet) SuiteAttributes(name string) (CipherSuite, bool) {
	for _, tb := range rs.CipherTables {
		for _, list := range [][]CipherSuite{tb.Suites, tb.TLS13} {
			for _, s := range list {
				if s.Name == name {
					return s, true
				}
			}
		}
	}
	return CipherSuite{}, false
}
