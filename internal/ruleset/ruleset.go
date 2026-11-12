// Package ruleset は検出ルール（データのみ）の読み込み・検証・書き出しを行う。
// ルールは内包のものを既定とし、外部ディレクトリは引数で明示された場合だけ呼び出し側が渡す。
package ruleset

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"kagiya/rules"
)

const (
	Format = "kagiya-rules/v0"

	maxFileSize = 1 << 20
	maxFiles    = 1000
	maxDepth    = 16
	maxNodes    = 200_000
)

// Algorithm は暗号カタログの1エントリ。
type Algorithm struct {
	ID         string              `yaml:"id"`
	Family     string              `yaml:"family"`
	Primitive  string              `yaml:"primitive"`
	KeyBits    int                 `yaml:"key_bits"`
	Aliases    map[string][]string `yaml:"aliases"`
	References []string            `yaml:"references"`
}

// RuleSet は読み込み・検証済みのルール一式。
type RuleSet struct {
	Version    string
	SHA256     string // 全ファイルの内容から計算したハッシュ（結果 JSON に記録する）
	Algorithms []Algorithm
	Stores     []Store

	Packages  []PackageRule
	Apps      []AppRule
	Libraries []LibraryRule
	Defaults  []DefaultSet

	CipherTables []*CipherTable

	byAlias     map[string]int
	storePaths  map[string]string // パス → ストア ID
	pkgExact    map[string]string // パッケージ名 → 役割
	pkgPrefixes []pkgPrefix
}

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

// Store は証明書ストアの場所の定義。出典（Sources）が必須。
type Store struct {
	ID      string   `yaml:"id"`
	Paths   []string `yaml:"paths"`
	Sources []Source `yaml:"sources"`
}

// Source は、ルールの内容を実物で確認した出典。
type Source struct {
	Image string `yaml:"image"` // ダイジェスト付きのコンテナイメージ
	OS    string `yaml:"os"`
	Note  string `yaml:"note"`
}

type storesFile struct {
	Stores []Store `yaml:"stores"`
}

// File はルールファイル1つ（書き出し用）。Path は `/` 区切りの相対パス。
type File struct {
	Path string
	Data []byte
}

type manifest struct {
	Format  string `yaml:"format"`
	Version string `yaml:"version"`
}

type catalogFile struct {
	Algorithms []Algorithm `yaml:"algorithms"`
}

var (
	idPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	aliasPattern = regexp.MustCompile(`^[A-Za-z0-9._/+:@()-]{1,64}$`)
	textPattern  = regexp.MustCompile(`^[A-Za-z0-9 ._/+:@()-]{1,64}$`)

	pkgNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]{0,63}\*?$`)
	imagePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9./_-]{0,127}@sha256:[0-9a-f]{64}$`)

	primitives = map[string]bool{
		"public-key": true, "signature": true, "hash": true, "block-cipher": true, "stream-cipher": true,
		"aead": true, "mac": true, "kdf": true, "kem": true, "key-exchange": true, "curve": true,
		"rng": true, "other": true,
	}
)

// Builtin は内包ルールを読み込む。
func Builtin() (*RuleSet, error) { return Load(rules.FS) }

// BuiltinFiles は内包ルールのファイル一覧を返す（`rules export` 用）。
func BuiltinFiles() ([]File, error) { return readAll(rules.FS) }

func readAll(fsys fs.FS) ([]File, error) {
	var files []File
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s: not a regular file", p)
		}
		if strings.HasSuffix(p, ".go") {
			return nil // 内包用の Go ソース
		}
		if len(files) >= maxFiles {
			return errors.New("too many rule files")
		}
		f, err := fsys.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
		if err != nil {
			return err
		}
		if len(data) > maxFileSize {
			return fmt.Errorf("%s: rule file is too large", p)
		}
		files = append(files, File{Path: p, Data: data})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

// Load はルール一式を読み込み、全体を検証する。1つでも問題があればエラーを返す。
func Load(fsys fs.FS) (*RuleSet, error) {
	files, err := readAll(fsys)
	if err != nil {
		return nil, err
	}
	rs := &RuleSet{byAlias: map[string]int{}, storePaths: map[string]string{}, pkgExact: map[string]string{}}
	h := sha256.New()
	seenManifest := false
	ids := map[string]bool{}
	for _, f := range files {
		fmt.Fprintf(h, "%s\x00%d\x00", f.Path, len(f.Data))
		h.Write(f.Data)
		switch {
		case f.Path == "manifest.yaml":
			var m manifest
			if err := decodeStrict(f.Data, &m); err != nil {
				return nil, fmt.Errorf("%s: %w", f.Path, err)
			}
			if m.Format != Format {
				return nil, fmt.Errorf("%s: unsupported rule format %q (want %q)", f.Path, m.Format, Format)
			}
			if !textPattern.MatchString(m.Version) {
				return nil, fmt.Errorf("%s: missing or invalid version", f.Path)
			}
			rs.Version = m.Version
			seenManifest = true
		case strings.HasPrefix(f.Path, "catalog/") && strings.HasSuffix(f.Path, ".yaml") && strings.Count(f.Path, "/") == 1:
			var c catalogFile
			if err := decodeStrict(f.Data, &c); err != nil {
				return nil, fmt.Errorf("%s: %w", f.Path, err)
			}
			for _, a := range c.Algorithms {
				if err := rs.add(a, ids); err != nil {
					return nil, fmt.Errorf("%s: %w", f.Path, err)
				}
			}
		case f.Path == "os/stores.yaml":
			var s storesFile
			if err := decodeStrict(f.Data, &s); err != nil {
				return nil, fmt.Errorf("%s: %w", f.Path, err)
			}
			for _, st := range s.Stores {
				if err := rs.addStore(st, ids); err != nil {
					return nil, fmt.Errorf("%s: %w", f.Path, err)
				}
			}
		case strings.HasPrefix(f.Path, "apps/") && strings.HasSuffix(f.Path, ".yaml") && strings.Count(f.Path, "/") == 1:
			var af appFile
			if err := decodeStrict(f.Data, &af); err != nil {
				return nil, fmt.Errorf("%s: %w", f.Path, err)
			}
			if err := rs.addApp(af.App, ids); err != nil {
				return nil, fmt.Errorf("%s: %w", f.Path, err)
			}
		case strings.HasPrefix(f.Path, "libraries/") && strings.HasSuffix(f.Path, ".yaml") && strings.Count(f.Path, "/") == 1:
			var lf libraryFile
			if err := decodeStrict(f.Data, &lf); err != nil {
				return nil, fmt.Errorf("%s: %w", f.Path, err)
			}
			if err := rs.addLibrary(lf.Library, ids); err != nil {
				return nil, fmt.Errorf("%s: %w", f.Path, err)
			}
		case strings.HasPrefix(f.Path, "defaults/") && strings.HasSuffix(f.Path, ".yaml") && strings.Count(f.Path, "/") == 1:
			var df defaultsFile
			if err := decodeStrict(f.Data, &df); err != nil {
				return nil, fmt.Errorf("%s: %w", f.Path, err)
			}
			for _, d := range df.Defaults {
				if err := rs.addDefaults(d, ids); err != nil {
					return nil, fmt.Errorf("%s: %w", f.Path, err)
				}
			}
		case strings.HasPrefix(f.Path, "ciphers/") && strings.HasSuffix(f.Path, ".yaml") && strings.Count(f.Path, "/") == 1:
			var cf cipherFile
			if err := decodeStrict(f.Data, &cf); err != nil {
				return nil, fmt.Errorf("%s: %w", f.Path, err)
			}
			for _, t := range cf.CipherTables {
				if err := rs.addCipherTable(t, ids); err != nil {
					return nil, fmt.Errorf("%s: %w", f.Path, err)
				}
			}
		case f.Path == "os/packages.yaml":
			var pf packagesFile
			if err := decodeStrict(f.Data, &pf); err != nil {
				return nil, fmt.Errorf("%s: %w", f.Path, err)
			}
			for _, pr := range pf.Packages {
				if err := rs.addPackageRule(pr); err != nil {
					return nil, fmt.Errorf("%s: %w", f.Path, err)
				}
			}
		default:
			return nil, fmt.Errorf("%s: unexpected file in rule directory", f.Path)
		}
	}
	if !seenManifest {
		return nil, errors.New("manifest.yaml is missing")
	}
	if len(rs.Algorithms) == 0 {
		return nil, errors.New("the algorithm catalog is empty")
	}
	rs.SHA256 = hex.EncodeToString(h.Sum(nil))
	return rs, nil
}

func (rs *RuleSet) add(a Algorithm, ids map[string]bool) error {
	if !idPattern.MatchString(a.ID) {
		return fmt.Errorf("invalid algorithm id %q", a.ID)
	}
	if ids[a.ID] {
		return fmt.Errorf("duplicate algorithm id %q", a.ID)
	}
	ids[a.ID] = true
	if !textPattern.MatchString(a.Family) {
		return fmt.Errorf("algorithm %q: missing or invalid family", a.ID)
	}
	if !primitives[a.Primitive] {
		return fmt.Errorf("algorithm %q: unknown primitive %q", a.ID, a.Primitive)
	}
	if a.KeyBits < 0 || a.KeyBits > 1<<20 {
		return fmt.Errorf("algorithm %q: invalid key_bits", a.ID)
	}
	for _, r := range a.References {
		if !textPattern.MatchString(r) {
			return fmt.Errorf("algorithm %q: invalid reference", a.ID)
		}
	}
	idx := len(rs.Algorithms)
	for scheme, names := range a.Aliases {
		if !idPattern.MatchString(scheme) {
			return fmt.Errorf("algorithm %q: invalid alias scheme %q", a.ID, scheme)
		}
		for _, n := range names {
			if !aliasPattern.MatchString(n) {
				return fmt.Errorf("algorithm %q: invalid alias %q", a.ID, n)
			}
			k := aliasKey(scheme, n)
			if _, dup := rs.byAlias[k]; dup {
				return fmt.Errorf("algorithm %q: alias %s:%s is already used", a.ID, scheme, n)
			}
			rs.byAlias[k] = idx
		}
	}
	rs.Algorithms = append(rs.Algorithms, a)
	return nil
}

func aliasKey(scheme, name string) string {
	return scheme + "\x00" + strings.ToLower(name)
}

// LookupAlias は命名体系（oid, jca, ...）と名前からカタログのエントリを引く。大文字小文字は区別しない。
func (rs *RuleSet) LookupAlias(scheme, name string) (Algorithm, bool) {
	i, ok := rs.byAlias[aliasKey(scheme, name)]
	if !ok {
		return Algorithm{}, false
	}
	return rs.Algorithms[i], true
}

// decodeStrict は YAML を厳格に読む: 単一文書のみ、アンカー／エイリアス禁止（展開爆発の防止）、
// 深さ・ノード数に上限、未知のキーは拒否。
func decodeStrict(data []byte, out any) error {
	var root yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&root); err != nil {
		return errors.New("invalid YAML: " + yamlErrorKind(err))
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("multiple YAML documents are not allowed")
	}
	count := 0
	if err := checkNode(&root, 0, &count); err != nil {
		return err
	}
	strict := yaml.NewDecoder(bytes.NewReader(data))
	strict.KnownFields(true)
	if err := strict.Decode(out); err != nil {
		return errors.New("invalid rule: " + yamlErrorKind(err))
	}
	return nil
}

func checkNode(n *yaml.Node, depth int, count *int) error {
	*count++
	if *count > maxNodes {
		return errors.New("too many YAML nodes")
	}
	if depth > maxDepth {
		return errors.New("YAML nesting is too deep")
	}
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return fmt.Errorf("line %d: YAML anchors and aliases are not allowed", n.Line)
	}
	for _, c := range n.Content {
		if err := checkNode(c, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}

// yamlErrorKind はパーサのエラーから、入力の断片を含み得る部分を落として位置と種別だけを残す。
var yamlLine = regexp.MustCompile(`line \d+`)

func yamlErrorKind(err error) string {
	msg := err.Error()
	kind := "syntax or type error"
	if strings.Contains(msg, "not found in type") {
		kind = "unknown key"
	}
	if loc := yamlLine.FindString(msg); loc != "" {
		return kind + " at " + loc
	}
	return kind
}

func cleanAbsPath(p string) bool {
	if len(p) < 2 || len(p) > 1024 || p[0] != '/' || strings.HasSuffix(p, "/") || strings.ContainsAny(p, "\x00\n\r") {
		return false
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

func (rs *RuleSet) addStore(s Store, ids map[string]bool) error {
	if !idPattern.MatchString(s.ID) {
		return fmt.Errorf("invalid store id %q", s.ID)
	}
	key := "store\x00" + s.ID
	if ids[key] {
		return fmt.Errorf("duplicate store id %q", s.ID)
	}
	ids[key] = true
	if len(s.Paths) == 0 {
		return fmt.Errorf("store %q: no paths", s.ID)
	}
	// 出典のない定義は受け付けない。
	if err := checkSources(s.Sources); err != nil {
		return fmt.Errorf("store %q: %w", s.ID, err)
	}
	for _, p := range s.Paths {
		if !cleanAbsPath(p) {
			return fmt.Errorf("store %q: path %q must be a clean absolute path", s.ID, p)
		}
		if _, dup := rs.storePaths[p]; dup {
			return fmt.Errorf("store %q: path %q is already assigned to a store", s.ID, p)
		}
		rs.storePaths[p] = s.ID
	}
	rs.Stores = append(rs.Stores, s)
	return nil
}

// StoreFor は、パスが属する証明書ストアの ID を返す（最も深い定義が優先）。どれにも属さなければ空。
func (rs *RuleSet) StoreFor(path string) string {
	for p := path; len(p) > 1; {
		if id, ok := rs.storePaths[p]; ok {
			return id
		}
		i := strings.LastIndexByte(p, '/')
		if i <= 0 {
			break
		}
		p = p[:i]
	}
	return ""
}

// StorePaths は定義されているストアの場所の一覧（整列済み）。
func (rs *RuleSet) StorePaths() []string {
	out := make([]string, 0, len(rs.storePaths))
	for p := range rs.storePaths {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// checkSources は出典の記載を検証する。出典のない定義は受け付けない。
func checkSources(sources []Source) error {
	if len(sources) == 0 {
		return errors.New("at least one source (image digest and OS) is required")
	}
	for _, src := range sources {
		if !imagePattern.MatchString(src.Image) {
			return errors.New("source image must be given with its digest (name@sha256:...)")
		}
		if src.OS == "" || len(src.OS) > 128 || len(src.Note) > 1024 {
			return errors.New("source needs an OS name")
		}
	}
	return nil
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

// AppRule はサーバーアプリケーションの定義（どのバイナリか、版をどう読むか）。出典が必須。
type AppRule struct {
	ID             string   `yaml:"id"`
	Binaries       []string `yaml:"binaries"`
	Modules        []string `yaml:"modules"` // 実行時に読み込まれ、暗号ライブラリにリンクしているモジュール
	VersionPattern string   `yaml:"version_pattern"`
	Packages       []string `yaml:"packages"` // このアプリを含むパッケージ名（優先順）

	// 設定の読み取り
	Grammar     string          `yaml:"grammar"`      // 設定ファイルの文法（sshd | nginx | apache）
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

var directiveNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.]{0,63}$`)

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

func (a AppRule) MatchVersion(b []byte) []string     { return matchVersion(a.re, b) }
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
	if a.Grammar != "" && a.Grammar != "sshd" && a.Grammar != "nginx" && a.Grammar != "apache" {
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
	defaultValuePattern = regexp.MustCompile(`^[A-Za-z0-9@._,*-]+$`)
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
