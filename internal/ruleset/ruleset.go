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

	byAlias map[string]int
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
	rs := &RuleSet{byAlias: map[string]int{}}
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
