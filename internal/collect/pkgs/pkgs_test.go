//go:build unix

package pkgs

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kagiya/internal/inventory"
	"kagiya/internal/logx"
	"kagiya/internal/model"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

func place(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Ext(src) == ".gz" {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if data, err = io.ReadAll(zr); err != nil {
			t.Fatal(err)
		}
	}
	os.MkdirAll(filepath.Dir(dst), 0o755)
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func collect(t *testing.T, prefix string) *model.Inventory {
	t.Helper()
	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	b := inventory.NewBuilder(rs, logx.New(io.Discard, time.Now))
	(&Collector{Prefix: prefix, Opener: &safefs.Opener{OnSkip: b.Skip}, Builder: b, Rules: rs}).Collect()
	return b.Inventory()
}

func byName(inv *model.Inventory) map[string]model.Package {
	m := map[string]model.Package{}
	for _, p := range inv.Packages {
		m[p.Name] = p
	}
	return m
}

const td = "../../parse/pkgdb/testdata/"

func TestCollectRPMBerkeleyDB(t *testing.T) {
	prefix, _ := filepath.EvalSymlinks(t.TempDir())
	place(t, td+"rpm-bdb-el8/Packages.gz", prefix+"/var/lib/rpm/Packages")
	inv := collect(t, prefix)
	if len(inv.PackageDatabases) != 1 {
		t.Fatalf("databases = %+v", inv.PackageDatabases)
	}
	db := inv.PackageDatabases[0]
	if db.Manager != "rpm" || db.Format != "bdb" || db.Path != prefix+"/var/lib/rpm/Packages" || db.Packages != 5 || db.Unparsed != 0 {
		t.Errorf("database = %+v", db)
	}
	pk := byName(inv)
	// 記録するのは暗号に関係するパッケージだけ（httpd-filesystem などは件数にだけ数える）
	o := pk["openssl-libs"]
	if o.Manager != "rpm" || o.Epoch != 1 || o.Version != "1.1.1k" || o.Release != "18.el8_6" || o.Role != "crypto-library" || o.Source != "openssl-1.1.1k-18.el8_6.src.rpm" {
		t.Errorf("openssl-libs = %+v", o)
	}
	if pk["openssh-server"].Role != "ssh" || pk["openssh-server"].Version != "8.0p1" || pk["openssh-server"].Release != "34.el8_10" {
		t.Errorf("openssh-server = %+v", pk["openssh-server"])
	}
	if pk["ca-certificates"].Role != "trust-store" {
		t.Errorf("ca-certificates = %+v", pk["ca-certificates"])
	}
	if _, ok := pk["httpd-filesystem"]; ok {
		t.Error("packages without a role must not be listed")
	}
}

func TestCollectRPMSQLiteUsesWAL(t *testing.T) {
	prefix, _ := filepath.EvalSymlinks(t.TempDir())
	place(t, td+"rpm-sqlite-wal/rpmdb.sqlite.gz", prefix+"/var/lib/rpm/rpmdb.sqlite")
	place(t, td+"rpm-sqlite-wal/rpmdb.sqlite-wal.gz", prefix+"/var/lib/rpm/rpmdb.sqlite-wal")
	inv := collect(t, prefix)
	if len(inv.PackageDatabases) != 1 || inv.PackageDatabases[0].Format != "sqlite" || inv.PackageDatabases[0].Packages != 3 {
		t.Fatalf("databases = %+v (the WAL holds a deletion: 3 packages, not 4)", inv.PackageDatabases)
	}
	if !inv.PackageDatabases[0].WAL {
		t.Error("the use of a write-ahead log must be recorded")
	}
}

func TestCollectDpkg(t *testing.T) {
	prefix, _ := filepath.EvalSymlinks(t.TempDir())
	place(t, td+"dpkg-ubuntu2404/status.excerpt", prefix+"/var/lib/dpkg/status")
	inv := collect(t, prefix)
	if len(inv.PackageDatabases) != 1 || inv.PackageDatabases[0].Manager != "dpkg" || inv.PackageDatabases[0].Packages != 4 {
		t.Fatalf("databases = %+v (4 installed; nginx-common has only its config files left)", inv.PackageDatabases)
	}
	pk := byName(inv)
	if p := pk["libssl3t64"]; p.Role != "crypto-library" || p.Version != "3.0.13-0ubuntu3.16" || p.Source != "openssl" {
		t.Errorf("libssl3t64 = %+v", p)
	}
	if p := pk["openssh-server"]; p.Role != "ssh" || p.Version != "1:9.6p1-3ubuntu13.20" {
		t.Errorf("openssh-server = %+v", p)
	}
	if _, ok := pk["nginx-common"]; ok {
		t.Error("a removed package (config files only) must not be listed as installed")
	}
	if _, ok := pk["libc6"]; ok {
		t.Error("libc6 has no crypto role")
	}
}

func TestCollectNothingFound(t *testing.T) {
	prefix, _ := filepath.EvalSymlinks(t.TempDir())
	inv := collect(t, prefix)
	if len(inv.PackageDatabases) != 0 || len(inv.Packages) != 0 || len(inv.Skipped) != 0 {
		t.Errorf("inv = %+v", inv)
	}
}

func TestCollectCorruptDatabaseIsReported(t *testing.T) {
	prefix, _ := filepath.EvalSymlinks(t.TempDir())
	os.MkdirAll(prefix+"/var/lib/rpm", 0o755)
	os.WriteFile(prefix+"/var/lib/rpm/rpmdb.sqlite", []byte("this is not a database"), 0o644)
	inv := collect(t, prefix)
	if len(inv.Skipped) != 1 || inv.Skipped[0].Reason != "parse-error" {
		t.Errorf("skipped = %+v", inv.Skipped)
	}
}
