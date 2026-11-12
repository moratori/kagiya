// Package bins は、サーバーアプリケーションのバイナリと、それがリンクしている暗号ライブラリを特定するコレクタ。
//
// 実際に使われる暗号は「アプリの設定 ＞ OS の暗号ポリシー ＞ ライブラリの既定値」で決まるため、
// どのライブラリのどの版が使われるかを知ることが、既定値を解決する前提になる。
// ldd や readelf などのコマンドは実行せず、ファイル形式を直接読む。逆アセンブルは行わない。
package bins

import (
	"errors"
	"io"
	"strings"

	"kagiya/internal/inventory"
	"kagiya/internal/model"
	"kagiya/internal/parse/elfdyn"
	"kagiya/internal/parse/ldcache"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

const (
	maxCacheSize = 16 << 20
	maxScanSize  = 256 << 20 // 版文字列を探す範囲の上限
	scanChunk    = 1 << 20
	scanOverlap  = 256 // 版文字列がチャンクの境目にまたがっても見つかるようにする
)

type Collector struct {
	Prefix  string // テスト用。通常は空
	Opener  *safefs.Opener
	Builder *inventory.Builder
	Rules   *ruleset.RuleSet

	cache       []ldcache.Entry
	cacheLoaded bool
}

// Collect は、ルールにあるアプリケーションのバイナリを順に調べる。
func (c *Collector) Collect() {
	for _, app := range c.Rules.Apps {
		for _, bin := range app.Binaries {
			c.application(app, bin)
		}
	}
}

// open はリンクを辿って実体を開く。見つからない・読めない場合は ok=false。
func (c *Collector) open(path string) (f *safefs.File, real string, ok bool) {
	real, err := c.Opener.Resolve(path)
	if err != nil {
		return nil, "", false
	}
	f, err = c.Opener.Open(real)
	if err != nil {
		return nil, "", false
	}
	return f, real, true
}

func (c *Collector) application(app ruleset.AppRule, bin string) {
	f, real, ok := c.open(c.Prefix + bin)
	if !ok {
		return
	}
	defer f.Close()
	info, err := elfdyn.Read(f, f.Size())
	if errors.Is(err, elfdyn.ErrNotELF) {
		return // ELF ではない（スクリプトや、他の OS の実行形式）。対象外。
	}
	if err != nil {
		c.Builder.Skip(safefs.Skip{Path: real, Reason: "parse-error", Detail: "malformed ELF file"})
		return
	}
	comp := c.Builder.Component("app:"+app.ID+":"+real, func() model.Component {
		return model.Component{Kind: "application", Name: app.ID, Path: real, Package: c.packageFor(app.Packages)}
	})
	comp.Version, comp.Notes = c.version(f, app.MatchVersion, comp.Notes)
	c.links(comp, real, info, "needed", "")

	for _, mod := range app.Modules {
		mf, mreal, ok := c.open(c.Prefix + mod)
		if !ok {
			continue
		}
		minfo, err := elfdyn.Read(mf, mf.Size())
		mf.Close()
		if err != nil || minfo.Class != info.Class || minfo.Machine != info.Machine {
			continue
		}
		c.links(comp, mreal, minfo, "module", mreal)
	}
}

// links は、バイナリが必要とする共有ライブラリのうち、暗号ライブラリの定義に合うものを解決して記録する。
func (c *Collector) links(comp *model.Component, binPath string, info *elfdyn.Info, via, module string) {
	for _, soname := range info.Needed {
		rule, ok := c.Rules.LibraryForSOName(soname)
		if !ok {
			continue
		}
		link := model.Link{SOName: soname, Via: via, Module: module, ResolvedBy: "unresolved"}
		if path, how, ok := c.resolve(binPath, info, soname); ok {
			link.Path, link.ResolvedBy = path, how
			link.Component = c.library(rule, path)
		}
		comp.Links = append(comp.Links, link)
	}
}

func (c *Collector) library(rule ruleset.LibraryRule, real string) string {
	id := "lib:" + rule.ID + ":" + real
	c.Builder.Component(id, func() model.Component {
		comp := model.Component{Kind: "library", Name: rule.ID, Path: real, Package: c.packageFor(rule.Packages)}
		if f, err := c.Opener.Open(real); err == nil {
			comp.Version, comp.Notes = c.version(f, rule.MatchVersion, nil)
			f.Close()
		}
		return comp
	})
	return id
}

// packageFor は、記録済みのパッケージから、名前のパターンに合う最初のものを返す（パターンの順が優先順）。
func (c *Collector) packageFor(patterns []string) *model.PackageRef {
	for _, pat := range patterns {
		for _, p := range c.Builder.Packages() {
			if ruleset.MatchName([]string{pat}, p.Name) {
				return &model.PackageRef{Name: p.Name, Epoch: p.Epoch, Version: p.Version, Release: p.Release}
			}
		}
	}
	return nil
}

// version はファイル全体から版文字列を探す。異なる版が複数見つかった場合は、どれとも決めずに注記を残す。
func (c *Collector) version(f *safefs.File, match func([]byte) []string, notes []string) (*model.ComponentVersion, []string) {
	var found []string
	size := f.Size()
	if size > maxScanSize {
		size = maxScanSize
		notes = append(notes, "version: only the first part of the file was searched")
	}
	buf := make([]byte, scanOverlap+scanChunk)
	keep := 0
	for off := int64(0); off < size; {
		n, err := f.ReadAt(buf[keep:], off)
		if n <= 0 {
			break
		}
		if rest := size - off; int64(n) > rest {
			n = int(rest)
		}
		window := buf[:keep+n]
		for _, v := range match(window) {
			dup := false
			for _, o := range found {
				dup = dup || o == v
			}
			if !dup && len(found) < 8 {
				found = append(found, v)
			}
		}
		off += int64(n)
		keep = scanOverlap
		if len(window) < keep {
			keep = len(window)
		}
		copy(buf, window[len(window)-keep:])
		if err == io.EOF {
			break
		}
	}
	switch len(found) {
	case 0:
		return nil, notes
	case 1:
		return &model.ComponentVersion{Value: found[0], Source: "binary-string"}, notes
	}
	return nil, append(notes, "version: several different version strings were found ("+strings.Join(found, ", ")+")")
}

// resolve は、動的リンカと同じ順序で共有ライブラリの実体を探す。
//  1. RPATH（RUNPATH がない場合のみ） 2. RUNPATH 3. /etc/ld.so.cache 4. 既定のディレクトリ
//
// 環境変数 LD_LIBRARY_PATH は読まない（稼働中プロセスの環境は調べない方針のため）。
// 候補は、要求元と同じ種類（32/64bit、アーキテクチャ）の ELF であるものだけを採る。
func (c *Collector) resolve(binPath string, info *elfdyn.Info, soname string) (path, how string, ok bool) {
	try := func(candidate string) (string, bool) {
		f, real, ok := c.open(candidate)
		if !ok {
			return "", false
		}
		defer f.Close()
		li, err := elfdyn.Read(f, f.Size())
		if err != nil || li.Class != info.Class || li.Machine != info.Machine {
			return "", false
		}
		return real, true
	}
	if strings.Contains(soname, "/") {
		return "", "", false
	}
	origin := binPath[:strings.LastIndexByte(binPath, '/')]
	search := func(dirs []string, how string) (string, string, bool) {
		for _, d := range dirs {
			switch {
			case strings.HasPrefix(d, "$ORIGIN"):
				d = origin + strings.TrimPrefix(d, "$ORIGIN")
			case strings.HasPrefix(d, "${ORIGIN}"):
				d = origin + strings.TrimPrefix(d, "${ORIGIN}")
			case strings.Contains(d, "$") || !strings.HasPrefix(d, "/"):
				continue // $LIB などは解釈しない
			default:
				d = c.Prefix + d
			}
			if d = cleanPath(d); d == "" {
				continue
			}
			if real, ok := try(d + "/" + soname); ok {
				return real, how, true
			}
		}
		return "", "", false
	}
	if len(info.RunPath) == 0 {
		if p, h, ok := search(info.RPath, "rpath"); ok {
			return p, h, true
		}
	}
	if p, h, ok := search(info.RunPath, "runpath"); ok {
		return p, h, true
	}
	for _, e := range c.ldCache() {
		if e.Name != soname {
			continue
		}
		if real, ok := try(c.Prefix + e.Path); ok {
			return real, "ld.so.cache", true
		}
	}
	defaults := []string{"/lib", "/usr/lib"}
	if info.Class == 64 {
		defaults = []string{"/lib64", "/usr/lib64", "/lib", "/usr/lib"}
	}
	return search(defaults, "default-path")
}

// cleanPath は "a/../b" や "//" を含むパスを正規化する（絶対パスのみ）。正規化できなければ空。
func cleanPath(p string) string {
	if !strings.HasPrefix(p, "/") {
		return ""
	}
	var out []string
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "", ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	if len(out) == 0 {
		return ""
	}
	return "/" + strings.Join(out, "/")
}

func (c *Collector) ldCache() []ldcache.Entry {
	if c.cacheLoaded {
		return c.cache
	}
	c.cacheLoaded = true
	f, _, ok := c.open(c.Prefix + "/etc/ld.so.cache")
	if !ok {
		return nil
	}
	defer f.Close()
	if f.Size() > maxCacheSize {
		return nil
	}
	data, err := io.ReadAll(io.NewSectionReader(f, 0, f.Size()))
	if err != nil {
		return nil
	}
	entries, err := ldcache.Parse(data)
	if err != nil {
		c.Builder.Skip(safefs.Skip{Path: c.Prefix + "/etc/ld.so.cache", Reason: "parse-error", Detail: "library cache could not be read"})
		return nil
	}
	c.cache = entries
	return entries
}
