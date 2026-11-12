// Package pkgs は、OS のパッケージ管理データベースから導入済みパッケージの版を集めるコレクタ。
// アプリやライブラリの既定値はディストリのパッケージ版ごとに異なるため、版の特定の基礎になる。
// rpm や dpkg のコマンドは実行しない。
package pkgs

import (
	"io"

	"kagiya/internal/inventory"
	"kagiya/internal/model"
	"kagiya/internal/parse/pkgdb"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

type Collector struct {
	Prefix  string // テスト用。通常は空（実際のパスをそのまま読む）
	Opener  *safefs.Opener
	Builder *inventory.Builder
	Rules   *ruleset.RuleSet
}

// データベースの置き場所。出典: 設計書 13章「Phase 1b に向けて実物から採取した事実」
// （RHEL 8.10 は /var/lib/rpm/Packages、RHEL 9.9 は /var/lib/rpm/rpmdb.sqlite、Ubuntu は /var/lib/dpkg/status）。
// /usr/lib/sysimage/rpm は、rpm のデータベースをそこへ移したディストリ向けの候補。
var candidates = []struct{ path, manager, format string }{
	{"/var/lib/rpm/Packages", "rpm", "bdb"},
	{"/var/lib/rpm/rpmdb.sqlite", "rpm", "sqlite"},
	{"/usr/lib/sysimage/rpm/Packages", "rpm", "bdb"},
	{"/usr/lib/sysimage/rpm/rpmdb.sqlite", "rpm", "sqlite"},
	{"/var/lib/dpkg/status", "dpkg", "status"},
}

// Collect は候補の場所を順に調べ、見つかったデータベースを読む。
func (c *Collector) Collect() {
	for _, cand := range candidates {
		path := c.Prefix + cand.path
		f, err := c.Opener.Open(path)
		if err != nil {
			continue // 存在しない、または記録済みのスキップ
		}
		var pkgs []pkgdb.Package
		var failed int
		usedWAL := false
		switch cand.format {
		case "bdb":
			pkgs, failed, err = pkgdb.ReadRPMBDB(f, f.Size())
		case "sqlite":
			var wal io.ReaderAt
			var walSize int64
			if w, werr := c.Opener.Open(path + "-wal"); werr == nil {
				defer w.Close()
				wal, walSize = w, w.Size()
				usedWAL = walSize > 32
			}
			pkgs, failed, err = pkgdb.ReadRPMSQLite(f, f.Size(), wal, walSize)
		case "status":
			var all []pkgdb.Package
			all, err = pkgdb.ParseDpkgStatus(io.NewSectionReader(f, 0, f.Size()))
			for _, p := range all {
				if p.Installed {
					pkgs = append(pkgs, p)
				}
			}
		}
		f.Close()
		if err != nil {
			c.Builder.Skip(safefs.Skip{Path: path, Reason: "parse-error", Detail: "package database could not be read"})
			continue
		}
		c.Builder.AddPackageDatabase(model.PackageDatabase{
			Manager: cand.manager, Format: cand.format, Path: path,
			Packages: len(pkgs), Unparsed: failed, WAL: usedWAL,
		})
		for _, p := range pkgs {
			role := c.Rules.PackageRole(p.Name)
			if role == "" {
				continue
			}
			src := p.SourceRPM
			if cand.manager == "dpkg" {
				src = p.SourceName
			}
			c.Builder.AddPackage(model.Package{
				Manager: cand.manager, Name: p.Name, Epoch: p.Epoch, Version: p.Version, Release: p.Release,
				Arch: p.Arch, Source: src, Role: role,
			})
		}
	}
}
