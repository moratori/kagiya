package ruleset

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// CipherSuite は、対応表の1行（暗号スイート1つ）。
type CipherSuite struct {
	Name     string `yaml:"name"`     // OpenSSL での名前
	Standard string `yaml:"standard"` // 標準名（RFC の名前）
	ID       string `yaml:"id"`
	Protocol string `yaml:"protocol"` // このスイートが使える最小のプロトコル
	Kx       string `yaml:"kx"`
	Au       string `yaml:"au"`
	Enc      string `yaml:"enc"`
	Mac      string `yaml:"mac"`
	// @STRENGTH の並べ替えを再現する値。表示の鍵長と違うことがある（並び順を決める以外の意味はない）。
	Strength int `yaml:"strength"`
	// 使える最大のセキュリティレベル。nil は、アプリ側の追加の設定（PSK や SRP）がないと使えないか、レベルのない版。
	Level    *int   `yaml:"level"`
	Default  bool   `yaml:"default"`  // 既定（DEFAULT）に含まれる
	Keywords string `yaml:"keywords"` // このスイートを指す語（空白区切り）
}

// CipherBuild は、対応表を実測したパッケージ版と、その出典。
type CipherBuild struct {
	Package string `yaml:"package"`
	Version string `yaml:"version"` // rpm は「バージョン-リリース」、dpkg は Version の全体
	Source  Source `yaml:"source"`
}

// CipherTable は、暗号ライブラリのあるパッケージ版での暗号スイートの対応表。
// 暗号文字列がどのスイートに展開されるかは、上流の版だけでは決まらず、ディストリのパッケージ版ごとに違う。出典が必須。
type CipherTable struct {
	Library        string        `yaml:"library"`
	Upstream       string        `yaml:"upstream"` // 上流の版（補間できる範囲の判定に使う）
	Builds         []CipherBuild `yaml:"builds"`
	StandardNames  bool          `yaml:"standard_names"`  // 暗号文字列に標準名を書けるか
	SecurityLevels bool          `yaml:"security_levels"` // セキュリティレベルの仕組みがあるか
	DefaultLevel   *int          `yaml:"default_level"`   // 指定がないときのレベル
	ProfileSystem  string        `yaml:"profile_system"`  // 「PROFILE=SYSTEM」で読まれるファイル（RHEL 系のみ）
	TLS13          []CipherSuite `yaml:"tls13"`           // TLS 1.3 のスイート（暗号文字列の対象外）。既定に入っていないものも含む
	Suites         []CipherSuite `yaml:"suites"`          // TLS 1.2 以下のスイート。並びはライブラリ内部の並び
}

type cipherFile struct {
	CipherTables []*CipherTable `yaml:"cipher_tables"`
}

var (
	suiteNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$`)
	suiteAttrPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./-]{0,31}(\([0-9]{1,4}\))?$`)
	suiteIDPattern   = regexp.MustCompile(`^0x[0-9A-F]{2}(,0x[0-9A-F]{2}){1,2}$`)
	upstreamPattern  = regexp.MustCompile(`^[0-9][0-9A-Za-z.]{0,31}$`)
	distroTagPattern = regexp.MustCompile(`\.el[0-9]+|ubuntu|deb[0-9]+`)
)

func (rs *RuleSet) addCipherTable(t *CipherTable, ids map[string]bool) error {
	if t == nil || !idPattern.MatchString(t.Library) || !upstreamPattern.MatchString(t.Upstream) {
		return errors.New("cipher table needs a library and an upstream version")
	}
	where := "cipher table for " + t.Library + " " + t.Upstream
	if err := checkBuilds("cipher", t.Library, t.Upstream, t.Builds, ids); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	if !t.SecurityLevels && t.DefaultLevel != nil {
		return fmt.Errorf("%s: default_level needs security_levels", where)
	}
	if t.DefaultLevel != nil && (*t.DefaultLevel < 0 || *t.DefaultLevel > 5) {
		return fmt.Errorf("%s: invalid default_level", where)
	}
	if t.SecurityLevels && t.DefaultLevel == nil {
		return fmt.Errorf("%s: security_levels needs default_level", where)
	}
	if t.ProfileSystem != "" && !cleanAbsPath(t.ProfileSystem) {
		return fmt.Errorf("%s: profile_system must be a clean absolute path", where)
	}
	if len(t.Suites) == 0 || len(t.Suites) > 2000 || len(t.TLS13) > 100 {
		return fmt.Errorf("%s: invalid number of suites", where)
	}
	names := map[string]bool{}
	keywords := map[string]bool{}
	check := func(s CipherSuite, tls13 bool) error {
		if !suiteNamePattern.MatchString(s.Name) || (s.Standard != "" && !suiteNamePattern.MatchString(s.Standard)) || !suiteIDPattern.MatchString(s.ID) {
			return fmt.Errorf("%s: invalid suite %q", where, s.Name)
		}
		for _, a := range []string{s.Protocol, s.Kx, s.Au, s.Enc, s.Mac} {
			if !suiteAttrPattern.MatchString(a) {
				return fmt.Errorf("%s: suite %s: invalid attribute", where, s.Name)
			}
		}
		if names[s.Name] {
			return fmt.Errorf("%s: duplicate suite %s", where, s.Name)
		}
		names[s.Name] = true
		if s.Strength < 0 || s.Strength > 4096 {
			return fmt.Errorf("%s: suite %s: invalid strength", where, s.Name)
		}
		if s.Level != nil && (!t.SecurityLevels || *s.Level < 0 || *s.Level > 5) {
			return fmt.Errorf("%s: suite %s: invalid level", where, s.Name)
		}
		if tls13 != (s.Protocol == "TLSv1.3") || (tls13 && s.Keywords != "") {
			return fmt.Errorf("%s: suite %s is in the wrong list", where, s.Name)
		}
		for _, k := range strings.Fields(s.Keywords) {
			if !suiteNamePattern.MatchString(k) {
				return fmt.Errorf("%s: suite %s: invalid keyword", where, s.Name)
			}
			keywords[k] = true
		}
		return nil
	}
	for _, s := range t.TLS13 {
		if err := check(s, true); err != nil {
			return err
		}
	}
	for _, s := range t.Suites {
		if err := check(s, false); err != nil {
			return err
		}
	}
	// 語とスイート名が同じだと、暗号文字列の中でどちらを指すか決められない。
	for k := range keywords {
		if names[k] {
			return fmt.Errorf("%s: %q is both a keyword and a suite name", where, k)
		}
	}
	rs.CipherTables = append(rs.CipherTables, t)
	return nil
}

// upstreamOf は、パッケージ版から上流の版を取り出す（エポックと、リリース以降を落とす）。
func upstreamOf(version string) string {
	if i := strings.IndexByte(version, ':'); i >= 0 {
		version = version[i+1:]
	}
	if i := strings.IndexByte(version, '-'); i >= 0 {
		version = version[:i]
	}
	return version
}

// distroTag は、パッケージ版からディストリの系列（.el9、ubuntu、deb13 など）を取り出す。分からなければ空。
func distroTag(version string) string {
	if i := strings.IndexByte(version, '-'); i >= 0 {
		return distroTagPattern.FindString(version[i:])
	}
	return ""
}

// CipherTableFor は、暗号ライブラリのパッケージ版に対応する対応表と、その実測元を返す。
//
//   - 実測した版そのものがあれば、それを返す（exact = true）。
//   - なければ、パッケージ名・上流の版・ディストリの系列がすべて同じ実測版の表で補間する（exact = false）。
//     リリース番号だけが違う版（エラータ）を想定している。呼び出し側は、補間であることを結果に残し、確度を下げること。
//   - それ以外は返さない（上流の版やディストリが違う表では代用しない）。
func (rs *RuleSet) CipherTableFor(library, pkg, version string) (t *CipherTable, build CipherBuild, exact, ok bool) {
	i, build, exact, ok := findBuild(library, pkg, version, len(rs.CipherTables), func(i int) (string, string, []CipherBuild) {
		tb := rs.CipherTables[i]
		return tb.Library, tb.Upstream, tb.Builds
	})
	if !ok {
		return nil, CipherBuild{}, false, false
	}
	return rs.CipherTables[i], build, exact, true
}

// findBuild は、パッケージ版ごとの実測の表（暗号スイート、鍵交換のグループ）から、導入されている版に対応するものを探す。
// 実測した版そのものがあれば exact = true。なければ、パッケージ名・上流の版・ディストリの系列が同じ実測版で補間する。
func findBuild(library, pkg, version string, n int, at func(i int) (library, upstream string, builds []CipherBuild)) (index int, build CipherBuild, exact, ok bool) {
	if version == "" {
		return 0, CipherBuild{}, false, false
	}
	for i := 0; i < n; i++ {
		lib, _, builds := at(i)
		if lib != library {
			continue
		}
		for _, b := range builds {
			if b.Package == pkg && b.Version == version {
				return i, b, true, true
			}
		}
	}
	up, tag := upstreamOf(version), distroTag(version)
	if tag == "" {
		return 0, CipherBuild{}, false, false
	}
	for i := 0; i < n; i++ {
		lib, upstream, builds := at(i)
		if lib != library || upstream != up {
			continue
		}
		for _, b := range builds {
			if b.Package == pkg && distroTag(b.Version) == tag {
				return i, b, false, true
			}
		}
	}
	return 0, CipherBuild{}, false, false
}

// checkBuilds は、表を実測したパッケージ版の一覧を検証する（出典が必須。同じ版を2つの表に載せない）。
func checkBuilds(kind, library, upstream string, builds []CipherBuild, ids map[string]bool) error {
	if len(builds) == 0 {
		return errors.New("at least one build (package version with its source) is required")
	}
	for _, b := range builds {
		if !pkgNamePattern.MatchString(b.Package) || strings.HasSuffix(b.Package, "*") || !pkgVersionPattern.MatchString(b.Version) {
			return fmt.Errorf("invalid build (package %q, version %q)", b.Package, b.Version)
		}
		if upstreamOf(b.Version) != upstream {
			return fmt.Errorf("build %s %s does not belong to this upstream version", b.Package, b.Version)
		}
		key := kind + "\x00" + library + "\x00" + b.Package + "\x00" + b.Version
		if ids[key] {
			return fmt.Errorf("duplicate build %s %s", b.Package, b.Version)
		}
		ids[key] = true
		if err := checkSources([]Source{b.Source}); err != nil {
			return fmt.Errorf("build %s %s: %w", b.Package, b.Version, err)
		}
	}
	return nil
}
