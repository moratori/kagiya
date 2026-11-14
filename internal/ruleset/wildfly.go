// このファイルは、WildFly の対応表（暗号の指定の解釈に使う表と、測った版）。

package ruleset

// ElytronSuite は、Elytron の表にあるスイート 1 つ。
type ElytronSuite struct {
	Name     string   `yaml:"name"`
	OpenSSL  []string `yaml:"openssl"`
	Kx       string   `yaml:"kx"`
	Auth     string   `yaml:"auth"`
	Enc      string   `yaml:"enc"`
	Mac      string   `yaml:"mac"`
	Protocol string   `yaml:"protocol"`
	Level    string   `yaml:"level"`
	Export   bool     `yaml:"export"`
	Bits     int      `yaml:"bits"`
}

// ElytronAlias は、スイートの別名。
type ElytronAlias struct {
	Name   string `yaml:"name"`
	Target string `yaml:"target"`
}

// WildFlyVersion は、測った WildFly の版。
type WildFlyVersion struct {
	Version     string `yaml:"version"`
	SHA256      string `yaml:"sha256"`
	LegacyRealm bool   `yaml:"legacy_realm"`
}

// WildFlyTable は、WildFly の対応表。出典が必須。
type WildFlyTable struct {
	Source                        Source           `yaml:"source"`
	ElytronTableSHA256            string           `yaml:"elytron_table_sha256"`
	DefaultCipherSuiteFilter      string           `yaml:"default_cipher_suite_filter"`
	DefaultProtocols              []string         `yaml:"default_protocols"`
	TLS13RequiresCipherSuiteNames bool             `yaml:"tls13_requires_cipher_suite_names"`
	LegacyDefaultProtocols        []string         `yaml:"legacy_default_protocols"`
	Versions                      []WildFlyVersion `yaml:"versions"`
	Aliases                       []ElytronAlias   `yaml:"aliases"`
	Suites                        []ElytronSuite   `yaml:"suites"`
	TLS13                         []ElytronSuite   `yaml:"tls13"`
}

// WildFlyFor は、WildFly の版に対応する表を返す。
func (rs *RuleSet) WildFlyFor(version string) (*WildFlyTable, WildFlyVersion, bool) {
	return nil, WildFlyVersion{}, false
}

func (rs *RuleSet) addWildFlyTable(t *WildFlyTable, ids map[string]bool) error { return nil }
