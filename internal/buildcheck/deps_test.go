// Package buildcheck は「通信コードを持たない」というビルド時保証（設計書 4.2 層1）を検査する。
package buildcheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// 配布バイナリの依存グラフに含まれてはならないパッケージ。
var forbidden = []string{
	"net",
	"net/http",
	"os/exec",
	"os/user",
	"plugin",
	"crypto/tls",
	"crypto/x509",
	// テンプレートエンジンは、名前からメソッドを呼ぶ（reflect の MethodByName）。これが入ると、リンカが未使用のメソッドを
	// 捨てられなくなり、標準ライブラリのファイル記述子の型に付いている通信用のメソッド（accept、sendto など）が実体に残る。
	"text/template",
	"html/template",
}

var targets = []struct{ goos, goarch string }{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"windows", "amd64"},
}

func TestBinaryHasNoForbiddenDependencies(t *testing.T) {
	for _, tg := range targets {
		t.Run(tg.goos+"/"+tg.goarch, func(t *testing.T) {
			cmd := exec.Command("go", "list", "-deps", "kagiya/cmd/kagiya")
			cmd.Env = append(os.Environ(), "GOOS="+tg.goos, "GOARCH="+tg.goarch, "CGO_ENABLED=0", "GOFLAGS=-mod=vendor")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("go list failed: %v\n%s", err, out)
			}
			deps := map[string]bool{}
			for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				deps[strings.TrimSpace(l)] = true
			}
			if !deps["kagiya/cmd/kagiya"] {
				t.Fatalf("unexpected go list output:\n%s", out)
			}
			for _, f := range forbidden {
				if deps[f] {
					t.Errorf("forbidden package %q is in the dependency graph", f)
				}
			}
		})
	}
}

// 配布する実体に、通信・プロセス起動のためのシンボルが含まれないこと（CI とリリースの確認と同じ条件）。
// 依存するパッケージの一覧だけでは、リンカが残したメソッドまでは分からないので、実際にビルドして確かめる。
func TestBinaryHasNoNetworkSymbols(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bad := regexp.MustCompile(` net\.| net/http|os/exec\.|syscall\.(socket|connect|bind|listen|accept|sendto)$`)
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run("linux/"+arch, func(t *testing.T) {
			bin := filepath.Join(t.TempDir(), "kagiya")
			build := exec.Command("go", "build", "-trimpath", "-o", bin, "kagiya/cmd/kagiya")
			build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0", "GOFLAGS=-mod=vendor")
			if out, err := build.CombinedOutput(); err != nil {
				t.Fatalf("go build failed: %v\n%s", err, out)
			}
			out, err := exec.Command("go", "tool", "nm", bin).Output()
			if err != nil {
				t.Fatalf("go tool nm failed: %v", err)
			}
			lines := strings.Split(string(out), "\n")
			if len(lines) < 1000 {
				t.Fatalf("unexpected nm output (%d lines)", len(lines))
			}
			for _, l := range lines {
				if bad.MatchString(l) {
					t.Errorf("forbidden symbol in the binary: %s", strings.TrimSpace(l))
				}
			}
		})
	}
}
