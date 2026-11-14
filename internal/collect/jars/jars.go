// Package jars は、JAR（.jar / .war / .ear）から、同梱されている暗号ライブラリを拾うコレクタ。
//
// 読むのは、JAR の中身の一覧（ファイル名）だけ。同梱ライブラリは、決まった置き場（BOOT-INF/lib/、WEB-INF/lib/、lib/）にある
// JAR の名前から、ライブラリと版を特定する（定義は rules/libraries/java-*.yaml）。入れ子の JAR も、クラスファイルも開かない。
// 分かるのは「どのライブラリの、どの版が置かれているか」までで、アプリがそれをどう使っているかは分からない。
package jars

import (
	"strings"

	"kagiya/internal/inventory"
	"kagiya/internal/model"
	"kagiya/internal/parse/jarfile"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

const (
	defaultMaxArchives = 2000 // 1 回のスキャンで開く JAR の数の上限
	versionSource      = "file-name"
)

// 中身の一覧を読むときの上限（エントリは読まないので、エントリの大きさの上限は使わない）。
var listLimits = jarfile.Limits{MaxArchiveSize: 2 << 30, MaxEntries: 200000, MaxNameLen: 1024}

// 同梱ライブラリの置き場（JAR の中のディレクトリ）。実行できる JAR（Spring Boot）、WAR、EAR や配布物の形。
var libDirs = []string{"BOOT-INF/lib/", "WEB-INF/lib/", "lib/"}

type Collector struct {
	Opener  *safefs.Opener
	Builder *inventory.Builder
	Rules   *ruleset.RuleSet
	// 開く JAR の数の上限（0 なら既定）
	MaxArchives int
}

// IsArchive は、ファイル名が対象の形式（.jar / .war / .ear）かを返す。
func IsArchive(name string) bool {
	lower := strings.ToLower(name)
	for _, ext := range []string{".jar", ".war", ".ear"} {
		if len(lower) > len(ext) && strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// Collect は、見つかった JAR（絶対パス）を順に調べる。
func (c *Collector) Collect(paths []string) {
	max := c.MaxArchives
	if max <= 0 {
		max = defaultMaxArchives
	}
	for i, p := range paths {
		if i >= max {
			c.Builder.Skip(safefs.Skip{Path: p, Reason: "limit", Detail: "more archives than the limit; this and the following ones are not opened"})
			break
		}
		c.Builder.Guard(p, "reading an archive", func() { c.archive(p) })
	}
}

func (c *Collector) archive(p string) {
	// JAR そのものが暗号ライブラリ（単体で置かれたもの）
	// ディスク上のパスなので、区切りは / と \\ のどちらもありうる（ファイルの扱いは safefs に任せ、ここではパスの文字列だけを見る）
	c.library(p, p[strings.LastIndexAny(p, "/\\")+1:], "")

	f, err := c.Opener.Open(p)
	if err != nil {
		return // スキップは記録済み
	}
	defer f.Close()
	a, err := jarfile.Open(f, f.Size(), listLimits)
	if err != nil {
		c.Builder.Skip(safefs.Skip{Path: p, Reason: "parse-error", Detail: "the archive cannot be read: " + err.Error()})
		return
	}
	if len(a.Problems) > 0 {
		c.Builder.Skip(safefs.Skip{Path: p, Reason: "parse-error", Detail: a.Problems[0]})
	}
	for _, e := range a.Entries {
		if e.Dir {
			continue
		}
		for _, dir := range libDirs {
			// 置き場の直下にあるものだけ
			if name, ok := strings.CutPrefix(e.Name, dir); ok && !strings.Contains(name, "/") {
				c.library(p+"!/"+e.Name, name, p)
				break
			}
		}
	}
}

// library は、ファイル名が暗号ライブラリの定義に合えば、コンポーネントとして記録する。
func (c *Collector) library(location, file, bundledIn string) {
	rule, artifact, version, ok := c.Rules.JavaLibraryForFile(file)
	if !ok {
		return
	}
	comp := c.Builder.Component("lib:"+rule.ID+":"+location, func() model.Component {
		return model.Component{Kind: "library", Name: rule.ID, Path: location}
	})
	if version != "" {
		comp.Version = &model.ComponentVersion{Value: version, Source: versionSource}
	}
	if r, ok := rule.PQC.For(artifact, version); ok {
		comp.PQC = &model.ComponentPQC{Supported: r.Supported, NotSupported: r.NotSupported, Unknown: r.Unknown, Basis: r.Basis}
	}
	notes := []string{"artifact " + artifact + " (identified from the file name; the contents of the file are not read)"}
	if bundledIn != "" {
		notes = append(notes, "bundled in "+bundledIn)
	}
	comp.Notes = notes
}
