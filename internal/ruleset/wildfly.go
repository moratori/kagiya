// このファイルは、WildFly の対応表（暗号の指定の解釈に使う表と、測った版）。

package ruleset

import (
	"errors"
	"fmt"
	"regexp"
)

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

var (
	wildflyVersionPattern  = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.Final$`)
	elytronAttrPattern     = regexp.MustCompile(`^[A-Za-z0-9]{1,24}$`)
	elytronProtocolPattern = regexp.MustCompile(`^(SSLv[23]|TLSv1(\.[123])?)$`)
)

// WildFlyFor は、WildFly の版に対応する表を返す。測った版だけを返す（近い版の表で補うことはしない）。
func (rs *RuleSet) WildFlyFor(version string) (*WildFlyTable, WildFlyVersion, bool) {
	for _, t := range rs.WildFlyTables {
		for _, v := range t.Versions {
			if v.Version == version {
				return t, v, true
			}
		}
	}
	return nil, WildFlyVersion{}, false
}

func (rs *RuleSet) addWildFlyTable(t *WildFlyTable, ids map[string]bool) error {
	if t == nil || len(t.Versions) == 0 || len(t.Versions) > 2000 {
		return errors.New("WildFly table needs versions")
	}
	where := "WildFly table for " + t.Versions[0].Version
	if err := checkSources([]Source{t.Source}); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	if !sha256Pattern.MatchString(t.ElytronTableSHA256) {
		return fmt.Errorf("%s: invalid elytron_table_sha256", where)
	}
	for _, v := range t.Versions {
		if !wildflyVersionPattern.MatchString(v.Version) || !sha256Pattern.MatchString(v.SHA256) {
			return fmt.Errorf("%s: invalid version %q or its checksum", where, v.Version)
		}
		key := "wildfly\x00" + v.Version
		if ids[key] {
			return fmt.Errorf("%s: duplicate version %s", where, v.Version)
		}
		ids[key] = true
	}
	if t.DefaultCipherSuiteFilter == "" || len(t.DefaultCipherSuiteFilter) > 256 || !tomcatCiphersPattern.MatchString(t.DefaultCipherSuiteFilter) {
		return fmt.Errorf("%s: invalid default_cipher_suite_filter", where)
	}
	for _, list := range [][]string{t.DefaultProtocols, t.LegacyDefaultProtocols} {
		if len(list) == 0 || len(list) > 8 {
			return fmt.Errorf("%s: default protocols are required", where)
		}
		for _, p := range list {
			if !elytronProtocolPattern.MatchString(p) {
				return fmt.Errorf("%s: invalid protocol %q", where, p)
			}
		}
	}
	if len(t.Suites) == 0 || len(t.Suites) > 2000 || len(t.TLS13) == 0 || len(t.TLS13) > 64 || len(t.Aliases) > 256 {
		return fmt.Errorf("%s: suites are required", where)
	}
	names := map[string]bool{}
	check := func(list []ElytronSuite, tls13 bool) error {
		for _, s := range list {
			if !suiteNamePattern.MatchString(s.Name) || names[s.Name] {
				return fmt.Errorf("%s: invalid or duplicate suite %q", where, s.Name)
			}
			names[s.Name] = true
			if len(s.OpenSSL) == 0 || len(s.OpenSSL) > 4 {
				return fmt.Errorf("%s: suite %s: OpenSSL names are required", where, s.Name)
			}
			for _, n := range s.OpenSSL {
				if !suiteNamePattern.MatchString(n) {
					return fmt.Errorf("%s: suite %s: invalid OpenSSL name %q", where, s.Name, n)
				}
			}
			for _, a := range []string{s.Kx, s.Auth, s.Enc, s.Mac, s.Level} {
				if !elytronAttrPattern.MatchString(a) {
					return fmt.Errorf("%s: suite %s: invalid attribute %q", where, s.Name, a)
				}
			}
			if !elytronProtocolPattern.MatchString(s.Protocol) || (s.Protocol == "TLSv1.3") != tls13 || s.Bits < 0 || s.Bits > 4096 {
				return fmt.Errorf("%s: suite %s: invalid protocol or bits", where, s.Name)
			}
		}
		return nil
	}
	if err := check(t.Suites, false); err != nil {
		return err
	}
	suites := map[string]bool{}
	for n := range names {
		suites[n] = true
	}
	if err := check(t.TLS13, true); err != nil {
		return err
	}
	for _, a := range t.Aliases {
		if !suiteNamePattern.MatchString(a.Name) || names[a.Name] || !suites[a.Target] {
			return fmt.Errorf("%s: invalid alias %q", where, a.Name)
		}
		names[a.Name] = true
	}
	rs.WildFlyTables = append(rs.WildFlyTables, t)
	return nil
}
