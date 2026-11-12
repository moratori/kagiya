// このファイルは、アプリのパッケージ版ごとの既定値表の読み込みと検索（版が完全一致しない場合の補間を含む）。

package ruleset

import (
	"fmt"
	"regexp"
	"strings"
)

// DefaultSet は、あるアプリの、あるパッケージ版での既定値（設定に記載がないときの値）。
// 既定値は上流の版だけでは決まらず、ディストリのパッケージ版ごとに違うため、パッケージ版をキーにする。出典が必須。
type DefaultSet struct {
	App     string            `yaml:"app"`
	Package string            `yaml:"package"`
	Version string            `yaml:"version"` // rpm は「バージョン-リリース」、dpkg は Version の全体
	Source  Source            `yaml:"source"`
	Values  map[string]string `yaml:"values"` // 項目名 → カンマ区切りの値
}

type defaultsFile struct {
	Defaults []DefaultSet `yaml:"defaults"`
}

var (
	pkgVersionPattern   = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.:+~_-]{0,127}$`)
	defaultValuePattern = regexp.MustCompile(`^[A-Za-z0-9@._,*:!+=-]+$`)
)

func (rs *RuleSet) addDefaults(d DefaultSet, ids map[string]bool) error {
	if !idPattern.MatchString(d.App) || !pkgNamePattern.MatchString(d.Package) || strings.HasSuffix(d.Package, "*") || !pkgVersionPattern.MatchString(d.Version) {
		return fmt.Errorf("invalid default set (app %q, package %q, version %q)", d.App, d.Package, d.Version)
	}
	key := "default\x00" + d.App + "\x00" + d.Package + "\x00" + d.Version
	if ids[key] {
		return fmt.Errorf("duplicate default set for %s %s %s", d.App, d.Package, d.Version)
	}
	ids[key] = true
	if err := checkSources([]Source{d.Source}); err != nil {
		return fmt.Errorf("defaults for %s %s: %w", d.Package, d.Version, err)
	}
	if len(d.Values) == 0 {
		return fmt.Errorf("defaults for %s %s: no values", d.Package, d.Version)
	}
	for k, v := range d.Values {
		if !idPattern.MatchString(k) || len(v) > 32768 || !defaultValuePattern.MatchString(v) {
			return fmt.Errorf("defaults for %s %s: invalid value for %q", d.Package, d.Version, k)
		}
	}
	rs.Defaults = append(rs.Defaults, d)
	return nil
}

// AppDefaults は、アプリのパッケージ版に対応する既定値と、その出典を返す。完全に一致する版だけを返す（近い版では代用しない）。
func (rs *RuleSet) AppDefaults(app, pkg, version string) (map[string][]string, Source, bool) {
	for _, d := range rs.Defaults {
		if d.App == app && d.Package == pkg && d.Version == version {
			out := make(map[string][]string, len(d.Values))
			for k, v := range d.Values {
				out[k] = strings.Split(v, ",")
			}
			return out, d.Source, true
		}
	}
	return nil, Source{}, false
}

// AppDefaultsFor は、アプリのパッケージ版に対応する既定値と、実測した版、その出典を返す。
//
//   - 実測した版そのものがあれば、それを返す（exact = true）。
//   - なければ、パッケージ名・上流の版・ディストリの系列がすべて同じ実測版の既定値で補間する（exact = false）。
//     リリース番号だけが違う版（エラータ）を想定している。呼び出し側は、補間であることを結果に残し、確度を下げること。
//   - それ以外は返さない（同じ上流版でもディストリの系列が違えば既定値は違い得るので、代用しない）。
func (rs *RuleSet) AppDefaultsFor(app, pkg, version string) (values map[string][]string, measured string, src Source, exact, ok bool) {
	if version == "" {
		return nil, "", Source{}, false, false
	}
	if v, s, found := rs.AppDefaults(app, pkg, version); found {
		return v, version, s, true, true
	}
	up, tag := upstreamOf(version), distroTag(version)
	if tag == "" {
		return nil, "", Source{}, false, false
	}
	for _, d := range rs.Defaults {
		if d.App == app && d.Package == pkg && upstreamOf(d.Version) == up && distroTag(d.Version) == tag {
			v, s, _ := rs.AppDefaults(app, pkg, d.Version)
			return v, d.Version, s, false, true
		}
	}
	return nil, "", Source{}, false, false
}
