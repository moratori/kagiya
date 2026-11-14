// このファイルは、Tomcat の TLS の対応表の読み込みと検索。

package ruleset

import (
	"errors"
	"fmt"
	"regexp"
)

// TomcatSuite は、Tomcat が持つ暗号スイートの表の 1 行。
type TomcatSuite struct {
	Name  string   `yaml:"name"`  // Tomcat の表での名前（標準名）
	ID    string   `yaml:"id"`    // TLS での番号
	JSSE  []string `yaml:"jsse"`  // Java での名前（SSL_ と TLS_ の 2 つを持つものがある）
	Words []string `yaml:"words"` // このスイートを指す語（OpenSSL での名前など）
}

// TomcatTable は、Tomcat のあるパッケージ版での、TLS の設定の既定値と、暗号指定の語の表。出典が必須。
type TomcatTable struct {
	Server   string        `yaml:"server"`
	Upstream string        `yaml:"upstream"`
	Builds   []CipherBuild `yaml:"builds"`
	// ciphers を書かないときの暗号指定
	DefaultCiphers string `yaml:"default_ciphers"`
	// protocols の「all」が指すプロトコル（書かないときの既定でもある）
	ProtocolsAll []string `yaml:"protocols_all"`
	// TLS 1.3 のスイートを別の属性（ciphersuites）で指定する版かどうかと、その既定
	CipherSuitesAttribute bool     `yaml:"ciphersuites_attribute"`
	DefaultCipherSuites   []string `yaml:"default_ciphersuites"`
	// 暗号指定の @STRENGTH の後ろに書かれた要素を読まない版かどうか
	StrengthEnds bool `yaml:"strength_ends"`
	// Tomcat Native に求める最小の版（系列ごと）
	NativeRequired []string         `yaml:"native_required"`
	Suites         []TomcatSuite    `yaml:"suites"`
	Classes        map[string][]int `yaml:"classes"` // 複数のスイートを指す語 → suites の中の位置

	words map[string][]int // 語 → suites の中の位置（読み込み時に作る）
}

var (
	// 暗号指定に書ける語（HIGH、kRSA、TLSv1.2、ECDHE-RSA-AES128-GCM-SHA256 など）
	tomcatWordPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$`)
	tomcatVersionPattern = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`)
	tomcatCiphersPattern = regexp.MustCompile(`^[A-Za-z0-9_.:!+@=, -]+$`)
)

func (rs *RuleSet) addTomcatTable(t *TomcatTable, ids map[string]bool) error {
	if t == nil || !idPattern.MatchString(t.Server) || !tomcatVersionPattern.MatchString(t.Upstream) {
		return errors.New("Tomcat table needs a server and an upstream version")
	}
	where := "Tomcat table for " + t.Server + " " + t.Upstream
	if err := checkBuilds("tomcat", t.Server, t.Upstream, t.Builds, ids); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	if len(t.DefaultCiphers) > 1024 || !tomcatCiphersPattern.MatchString(t.DefaultCiphers) {
		return fmt.Errorf("%s: invalid default_ciphers", where)
	}
	if len(t.ProtocolsAll) == 0 || len(t.ProtocolsAll) > 16 {
		return fmt.Errorf("%s: invalid number of protocols", where)
	}
	for _, p := range t.ProtocolsAll {
		if !suiteNamePattern.MatchString(p) {
			return fmt.Errorf("%s: invalid protocol %q", where, p)
		}
	}
	if len(t.NativeRequired) > 4 {
		return fmt.Errorf("%s: invalid native_required", where)
	}
	for _, v := range t.NativeRequired {
		if !tomcatVersionPattern.MatchString(v) {
			return fmt.Errorf("%s: invalid native_required %q", where, v)
		}
	}
	if len(t.Suites) == 0 || len(t.Suites) > 1000 {
		return fmt.Errorf("%s: invalid number of suites", where)
	}
	t.words = map[string][]int{}
	names, jsse := map[string]bool{}, map[string]bool{}
	for i, s := range t.Suites {
		if !suiteNamePattern.MatchString(s.Name) || names[s.Name] || !suiteIDPattern.MatchString(s.ID) || len(s.JSSE) == 0 || len(s.JSSE) > 4 || len(s.Words) > 16 {
			return fmt.Errorf("%s: invalid or duplicate suite %q", where, s.Name)
		}
		names[s.Name] = true
		for _, j := range s.JSSE {
			if !suiteNamePattern.MatchString(j) {
				return fmt.Errorf("%s: suite %s: invalid Java name %q", where, s.Name, j)
			}
			jsse[j] = true
		}
		for _, w := range s.Words {
			if !tomcatWordPattern.MatchString(w) {
				return fmt.Errorf("%s: suite %s: invalid word %q", where, s.Name, w)
			}
			t.words[w] = append(t.words[w], i)
		}
	}
	if len(t.Classes) > 1000 {
		return fmt.Errorf("%s: too many classes", where)
	}
	for w, idx := range t.Classes {
		if !tomcatWordPattern.MatchString(w) {
			return fmt.Errorf("%s: invalid word %q", where, w)
		}
		if _, dup := t.words[w]; dup {
			return fmt.Errorf("%s: word %q is both a class and a name of a suite", where, w)
		}
		seen := map[int]bool{}
		for _, i := range idx {
			if i < 0 || i >= len(t.Suites) || seen[i] {
				return fmt.Errorf("%s: word %q: invalid position %d", where, w, i)
			}
			seen[i] = true
		}
	}
	for w, idx := range t.Classes {
		t.words[w] = idx
	}
	if !t.CipherSuitesAttribute && len(t.DefaultCipherSuites) > 0 {
		return fmt.Errorf("%s: default_ciphersuites without ciphersuites_attribute", where)
	}
	if t.CipherSuitesAttribute && (len(t.DefaultCipherSuites) == 0 || len(t.DefaultCipherSuites) > 16) {
		return fmt.Errorf("%s: invalid default_ciphersuites", where)
	}
	for _, n := range t.DefaultCipherSuites {
		if !jsse[n] {
			return fmt.Errorf("%s: default_ciphersuites: %q is not in the table", where, n)
		}
	}
	rs.TomcatTables = append(rs.TomcatTables, t)
	return nil
}

// Word は、暗号指定の語が指すスイート（suites の中の位置）を返す。語は大文字小文字を区別する。
// 返したスライスは書き換えないこと。
func (t *TomcatTable) Word(w string) ([]int, bool) {
	idx, ok := t.words[w]
	return idx, ok
}

// TomcatTableFor は、Tomcat のパッケージ版に対応する対応表と、その実測元を返す。
// 引き方と補間の条件は、暗号スイートの対応表（CipherTableFor）と同じ。
func (rs *RuleSet) TomcatTableFor(server, pkg, version string) (t *TomcatTable, build CipherBuild, exact, ok bool) {
	i, build, exact, ok := findBuild(server, pkg, version, len(rs.TomcatTables), func(i int) (string, string, []CipherBuild) {
		tb := rs.TomcatTables[i]
		return tb.Server, tb.Upstream, tb.Builds
	})
	if !ok {
		return nil, CipherBuild{}, false, false
	}
	return rs.TomcatTables[i], build, exact, true
}
