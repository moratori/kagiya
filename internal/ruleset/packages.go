// このファイルは、記録対象のパッケージ名の定義の読み込みと検索。

package ruleset

import (
	"fmt"
	"strings"
)

// PackageRule は、結果に記録するパッケージとその役割の定義。出典（Sources）が必須。
type PackageRule struct {
	Role    string   `yaml:"role"`
	Names   []string `yaml:"names"`
	Sources []Source `yaml:"sources"`
}

type pkgPrefix struct{ prefix, role string }

type packagesFile struct {
	Packages []PackageRule `yaml:"packages"`
}

func (rs *RuleSet) addPackageRule(pr PackageRule) error {
	if !idPattern.MatchString(pr.Role) {
		return fmt.Errorf("invalid package role %q", pr.Role)
	}
	if len(pr.Names) == 0 {
		return fmt.Errorf("package role %q: no names", pr.Role)
	}
	if err := checkSources(pr.Sources); err != nil {
		return fmt.Errorf("package role %q: %w", pr.Role, err)
	}
	for _, n := range pr.Names {
		if !pkgNamePattern.MatchString(n) {
			return fmt.Errorf("package role %q: invalid name %q", pr.Role, n)
		}
		if _, dup := rs.pkgExact[n]; dup {
			return fmt.Errorf("package role %q: name %q is already assigned", pr.Role, n)
		}
		rs.pkgExact[n] = pr.Role
		if strings.HasSuffix(n, "*") {
			rs.pkgPrefixes = append(rs.pkgPrefixes, pkgPrefix{strings.TrimSuffix(n, "*"), pr.Role})
		}
	}
	rs.Packages = append(rs.Packages, pr)
	return nil
}

// PackageRole はパッケージ名から役割を返す（完全一致を優先し、次に最も長い前方一致）。対象外なら空。
func (rs *RuleSet) PackageRole(name string) string {
	if strings.HasSuffix(name, "*") {
		return ""
	}
	if r, ok := rs.pkgExact[name]; ok {
		return r
	}
	best, role := -1, ""
	for _, p := range rs.pkgPrefixes {
		if strings.HasPrefix(name, p.prefix) && len(p.prefix) > best {
			best, role = len(p.prefix), p.role
		}
	}
	return role
}
