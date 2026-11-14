// このファイルは、アプリケーションと暗号ライブラリの定義（バイナリ、版の文字列、設定項目）の読み込みと検索。

package ruleset

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// AppRule はサーバーアプリケーションの定義（どのバイナリか、版をどう読むか）。出典が必須。
type AppRule struct {
	ID             string   `yaml:"id"`
	Binaries       []string `yaml:"binaries"`
	Modules        []string `yaml:"modules"` // 実行時に読み込まれ、暗号ライブラリにリンクしているモジュール
	VersionPattern string   `yaml:"version_pattern"`
	Packages       []string `yaml:"packages"` // このアプリを含むパッケージ名（優先順）

	// 設定の読み取り
	Grammar     string          `yaml:"grammar"`      // 設定ファイルの文法（sshd | nginx | apache | haproxy | stunnel | postfix | postgresql | dovecot | mycnf | jdk）
	ConfigFiles []string        `yaml:"config_files"` // 設定ファイルの候補（先に見つかったものを使う）
	Units       []string        `yaml:"units"`        // systemd のユニット名（有効化状態と起動引数を読む）
	Direction   string          `yaml:"direction"`    // 通信の方向: inbound（受信）| outbound（送信）
	Directives  []DirectiveRule `yaml:"directives"`   // 結果に記録してよい設定項目（許可リスト）
	// DefaultReferences は、設定に記載がないときにアプリが使う既定のファイル（鍵など）。
	DefaultReferences []DefaultReference `yaml:"default_references"`
	Sources           []Source           `yaml:"sources"`

	re *regexp.Regexp
}

// DirectiveRule は、設定ファイルから記録する項目の定義。
type DirectiveRule struct {
	Name      string `yaml:"name"`
	Parameter string `yaml:"parameter"` // 結果での項目名（アプリをまたいで揃える）
	// Type は値の種類。種類ごとの検証を通った値だけを記録する。
	//   algorithm-list（カンマ区切り）| colon-list（コロン区切り）| cipher-string | words（空白区切り）|
	//   flag（on / off）| listen（待ち受け）| path | int | int-list
	Type      string `yaml:"type"`
	Multi     bool   `yaml:"multi"`     // 複数回書けて、すべてが有効になる項目
	Direction string `yaml:"direction"` // この項目だけ通信の方向が違う場合（上流への接続の設定など）
}

type DefaultReference struct {
	Parameter string   `yaml:"parameter"`
	Paths     []string `yaml:"paths"`
}

var directiveTypes = map[string]bool{
	"algorithm-list": true, "colon-list": true, "cipher-string": true, "words": true, "flag": true, "listen": true,
	"path": true, "int": true, "int-list": true,
}

// Directive は、キーワード（大文字小文字を区別しない）に対応する項目の定義を返す。
func (a AppRule) Directive(keyword string) (DirectiveRule, bool) {
	for _, d := range a.Directives {
		if strings.EqualFold(d.Name, keyword) {
			return d, true
		}
	}
	return DirectiveRule{}, false
}

// LibraryRule は暗号ライブラリの定義。出典が必須。
type LibraryRule struct {
	ID             string   `yaml:"id"`
	SONames        []string `yaml:"sonames"`
	VersionPattern string   `yaml:"version_pattern"`
	Packages       []string `yaml:"packages"`
	// ConfigFiles は、このライブラリのシステム全体の設定ファイルの候補（先に見つかったものを使う）。
	ConfigFiles []string `yaml:"config_files"`
	// SystemDefaultKeys は、システム既定の設定として結果に記録してよい項目名（許可リスト）。
	SystemDefaultKeys []string `yaml:"system_default_keys"`
	Sources           []Source `yaml:"sources"`

	re *regexp.Regexp
}

type appFile struct {
	App AppRule `yaml:"app"`
}

type libraryFile struct {
	Library LibraryRule `yaml:"library"`
}

var directiveNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)

var settingKeyPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9.]{0,63}$`)

var versionValue = regexp.MustCompile(`^[0-9][0-9A-Za-z.+~:_-]{0,63}$`)

// compileVersionPattern は版文字列のパターンを検証する。取り出す部分（括弧）はちょうど1つ。
func compileVersionPattern(p string) (*regexp.Regexp, error) {
	if p == "" {
		return nil, nil
	}
	if len(p) > 256 {
		return nil, errors.New("version_pattern is too long")
	}
	re, err := regexp.Compile(p)
	if err != nil {
		return nil, errors.New("version_pattern is not a valid regular expression")
	}
	if re.NumSubexp() != 1 {
		return nil, errors.New("version_pattern must have exactly one capture group")
	}
	return re, nil
}

// matchVersion はバイト列からパターンに合う版を探し、重複を除いて返す。
// 取り出した値は版として妥当な文字だけからなるものに限る（ファイルの内容が出力に紛れ込むのを防ぐ）。
func matchVersion(re *regexp.Regexp, b []byte) []string {
	if re == nil {
		return nil
	}
	var out []string
	for _, m := range re.FindAllSubmatch(b, 64) {
		v := string(m[1])
		if !versionValue.MatchString(v) {
			continue
		}
		dup := false
		for _, o := range out {
			dup = dup || o == v
		}
		if !dup {
			out = append(out, v)
		}
	}
	return out
}

func (a AppRule) MatchVersion(b []byte) []string { return matchVersion(a.re, b) }

func (l LibraryRule) MatchVersion(b []byte) []string { return matchVersion(l.re, b) }

// MatchName は、名前がパターン（完全一致、または末尾 * の前方一致）のどれかに合うかを返す。
func MatchName(patterns []string, name string) bool {
	for _, p := range patterns {
		if p == name || (strings.HasSuffix(p, "*") && strings.HasPrefix(name, strings.TrimSuffix(p, "*"))) {
			return true
		}
	}
	return false
}

func checkNames(names []string) error {
	for _, n := range names {
		if !pkgNamePattern.MatchString(n) {
			return fmt.Errorf("invalid name %q", n)
		}
	}
	return nil
}

func (rs *RuleSet) addApp(a AppRule, ids map[string]bool) error {
	if !idPattern.MatchString(a.ID) {
		return fmt.Errorf("invalid app id %q", a.ID)
	}
	if ids["app\x00"+a.ID] {
		return fmt.Errorf("duplicate app id %q", a.ID)
	}
	ids["app\x00"+a.ID] = true
	if err := checkSources(a.Sources); err != nil {
		return fmt.Errorf("app %q: %w", a.ID, err)
	}
	if len(a.Binaries) == 0 {
		return fmt.Errorf("app %q: no binaries", a.ID)
	}
	for _, p := range append(append([]string{}, a.Binaries...), a.Modules...) {
		if !cleanAbsPath(p) {
			return fmt.Errorf("app %q: path %q must be a clean absolute path", a.ID, p)
		}
	}
	if err := checkNames(a.Packages); err != nil {
		return fmt.Errorf("app %q: %w", a.ID, err)
	}
	for _, p := range a.ConfigFiles {
		if !cleanAbsPath(p) {
			return fmt.Errorf("app %q: path %q must be a clean absolute path", a.ID, p)
		}
	}
	if a.Grammar != "" && a.Grammar != "sshd" && a.Grammar != "nginx" && a.Grammar != "apache" && a.Grammar != "haproxy" && a.Grammar != "stunnel" && a.Grammar != "postfix" && a.Grammar != "postgresql" && a.Grammar != "dovecot" && a.Grammar != "mycnf" && a.Grammar != "jdk" && a.Grammar != "tomcat" {
		return fmt.Errorf("app %q: unknown grammar %q", a.ID, a.Grammar)
	}
	if a.Direction != "" && a.Direction != "inbound" && a.Direction != "outbound" {
		return fmt.Errorf("app %q: direction must be inbound or outbound", a.ID)
	}
	if err := checkNames(a.Units); err != nil {
		return fmt.Errorf("app %q: %w", a.ID, err)
	}
	for _, d := range a.Directives {
		if !directiveNamePattern.MatchString(d.Name) || !idPattern.MatchString(d.Parameter) || !directiveTypes[d.Type] ||
			(d.Direction != "" && d.Direction != "inbound" && d.Direction != "outbound") {
			return fmt.Errorf("app %q: invalid directive definition %q", a.ID, d.Name)
		}
	}
	for _, r := range a.DefaultReferences {
		if !idPattern.MatchString(r.Parameter) || len(r.Paths) == 0 {
			return fmt.Errorf("app %q: invalid default reference", a.ID)
		}
		for _, p := range r.Paths {
			if !cleanAbsPath(p) {
				return fmt.Errorf("app %q: path %q must be a clean absolute path", a.ID, p)
			}
		}
	}
	re, err := compileVersionPattern(a.VersionPattern)
	if err != nil {
		return fmt.Errorf("app %q: %w", a.ID, err)
	}
	a.re = re
	rs.Apps = append(rs.Apps, a)
	return nil
}

func (rs *RuleSet) addLibrary(l LibraryRule, ids map[string]bool) error {
	if !idPattern.MatchString(l.ID) {
		return fmt.Errorf("invalid library id %q", l.ID)
	}
	if ids["lib\x00"+l.ID] {
		return fmt.Errorf("duplicate library id %q", l.ID)
	}
	ids["lib\x00"+l.ID] = true
	if err := checkSources(l.Sources); err != nil {
		return fmt.Errorf("library %q: %w", l.ID, err)
	}
	if len(l.SONames) == 0 {
		return fmt.Errorf("library %q: no sonames", l.ID)
	}
	if err := checkNames(append(append([]string{}, l.SONames...), l.Packages...)); err != nil {
		return fmt.Errorf("library %q: %w", l.ID, err)
	}
	for _, p := range l.ConfigFiles {
		if !cleanAbsPath(p) {
			return fmt.Errorf("library %q: path %q must be a clean absolute path", l.ID, p)
		}
	}
	for _, k := range l.SystemDefaultKeys {
		if !settingKeyPattern.MatchString(k) {
			return fmt.Errorf("library %q: invalid setting name %q", l.ID, k)
		}
	}
	re, err := compileVersionPattern(l.VersionPattern)
	if err != nil {
		return fmt.Errorf("library %q: %w", l.ID, err)
	}
	l.re = re
	rs.Libraries = append(rs.Libraries, l)
	return nil
}

// LibraryForSOName は、共有ライブラリ名に対応する暗号ライブラリの定義を返す。
func (rs *RuleSet) LibraryForSOName(soname string) (LibraryRule, bool) {
	for _, l := range rs.Libraries {
		if MatchName(l.SONames, soname) {
			return l, true
		}
	}
	return LibraryRule{}, false
}
