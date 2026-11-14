//go:build unix

package jars

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kagiya/internal/inventory"
	"kagiya/internal/logx"
	"kagiya/internal/model"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

func jar(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, data := range entries {
		f, err := w.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		f.Write(data)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func collect(t *testing.T, files map[string][]byte, max int) (string, *model.Inventory) {
	t.Helper()
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	var paths []string
	for name, data := range files {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	b := inventory.NewBuilder(rs, logx.New(io.Discard, time.Now))
	c := &Collector{Opener: &safefs.Opener{OnSkip: b.Skip}, Builder: b, Rules: rs}
	if max > 0 {
		c.MaxArchives = max
	}
	c.Collect(paths)
	return dir, b.Inventory()
}

func libs(inv *model.Inventory) map[string]model.Component {
	out := map[string]model.Component{}
	for _, c := range inv.Components {
		if c.Kind == "library" {
			out[c.Path] = c
		}
	}
	return out
}

// 実行できる JAR の中の同梱ライブラリを、ファイル名から拾う。入れ子の JAR は開かない。単体で置かれた JAR も拾う。
func TestBundledLibraries(t *testing.T) {
	inner := jar(t, map[string][]byte{"BOOT-INF/lib/bcpkix-jdk18on-1.78.1.jar": []byte("x")}) // 入れ子の JAR の中（見えてはいけない）
	app := jar(t, map[string][]byte{
		"META-INF/MANIFEST.MF":                        []byte("Manifest-Version: 1.0\r\n"),
		"BOOT-INF/classes/application.properties":     []byte("server.ssl.key-store-password=s3cret-jar\n"),
		"BOOT-INF/lib/bcprov-jdk18on-1.78.1.jar":      inner,
		"BOOT-INF/lib/tomcat-embed-core-10.1.55.jar":  []byte("x"),
		"BOOT-INF/lib/spring-core-6.2.1.jar":          []byte("x"),
		"BOOT-INF/classes/lab/bcprov-jdk18on-9.9.jar": []byte("x"), // 同梱ライブラリの置き場ではない
	})
	war := jar(t, map[string][]byte{"WEB-INF/lib/conscrypt-openjdk-uber-2.9.0.jar": []byte("x")})
	dir, inv := collect(t, map[string][]byte{"opt/app/app.jar": app, "srv/web/site.war": war, "usr/share/java/bcprov-jdk18on-1.80.jar": jar(t, map[string][]byte{"a": nil})}, 0)
	got := libs(inv)
	want := map[string][2]string{
		dir + "/opt/app/app.jar!/BOOT-INF/lib/bcprov-jdk18on-1.78.1.jar":        {"bouncycastle", "1.78.1"},
		dir + "/opt/app/app.jar!/BOOT-INF/lib/tomcat-embed-core-10.1.55.jar":    {"tomcat-embed", "10.1.55"},
		dir + "/srv/web/site.war!/WEB-INF/lib/conscrypt-openjdk-uber-2.9.0.jar": {"conscrypt", "2.9.0"},
		dir + "/usr/share/java/bcprov-jdk18on-1.80.jar":                         {"bouncycastle", "1.80"},
	}
	if len(got) != len(want) {
		t.Errorf("libraries = %d, want %d: %v", len(got), len(want), got)
	}
	for p, w := range want {
		c, ok := got[p]
		if !ok || c.Name != w[0] || c.Version == nil || c.Version.Value != w[1] || c.Version.Source != "file-name" {
			t.Errorf("%s: %+v", p, c)
		}
	}
	// 同梱されているものは、どの JAR の中かと、成果物の名前を注記する
	c := got[dir+"/opt/app/app.jar!/BOOT-INF/lib/bcprov-jdk18on-1.78.1.jar"]
	if n := strings.Join(c.Notes, " "); !strings.Contains(n, "bcprov-jdk18on") || !strings.Contains(n, "bundled") {
		t.Errorf("notes = %v", c.Notes)
	}
}

// 壊れた JAR は読み飛ばしたことを記録する。数の上限を超えた分も、読み飛ばしたことを記録する。
func TestSkips(t *testing.T) {
	good := jar(t, map[string][]byte{"BOOT-INF/lib/bcprov-jdk18on-1.78.1.jar": []byte("x")})
	_, inv := collect(t, map[string][]byte{"a/broken.jar": []byte("this is not a zip"), "a/good.jar": good}, 0)
	if len(libs(inv)) != 1 {
		t.Errorf("libraries = %v", libs(inv))
	}
	found := false
	for _, s := range inv.Skipped {
		if strings.HasSuffix(s.Path, "broken.jar") && s.Reason == "parse-error" {
			found = true
		}
	}
	if !found {
		t.Errorf("the broken archive must be recorded as skipped: %+v", inv.Skipped)
	}
	_, inv = collect(t, map[string][]byte{"a/1.jar": good, "a/2.jar": good, "a/3.jar": good}, 2)
	if n := len(libs(inv)); n != 2 {
		t.Errorf("libraries = %d, want 2 (limit)", n)
	}
	found = false
	for _, s := range inv.Skipped {
		if s.Reason == "limit" {
			found = true
		}
	}
	if !found {
		t.Errorf("archives over the limit must be recorded as skipped: %+v", inv.Skipped)
	}
}

// 対象にする名前: .jar / .war / .ear（大文字小文字を区別しない）。
func TestIsArchive(t *testing.T) {
	for name, want := range map[string]bool{"app.jar": true, "SITE.WAR": true, "x.ear": true, "x.zip": false, "jar": false, "x.jar.bak": false, ".jar": false} {
		if IsArchive(name) != want {
			t.Errorf("%s: %v", name, !want)
		}
	}
}

// 1 つの JAR の処理で panic が起きても、残りの JAR は調べる。
func TestCollectSurvivesPanic(t *testing.T) {
	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	b := inventory.NewBuilder(rs, logx.New(io.Discard, time.Now))
	// ファイルを開く経路を持たない Collector は、開こうとすると panic する（パーサの中での panic の代わり）
	(&Collector{Builder: b, Rules: rs}).Collect([]string{"/opt/a/one.jar", "/opt/a/two.jar"})
	inv := b.Inventory()
	if len(inv.Skipped) != 2 || inv.Skipped[0].Reason != "internal-error" || inv.Skipped[1].Path != "/opt/a/two.jar" {
		t.Errorf("skipped = %+v", inv.Skipped)
	}
}
