// Package buildcheck は「通信コードを持たない」というビルド時保証（設計書 4.2 層1）を検査する。
package buildcheck

import (
	"os"
	"os/exec"
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
