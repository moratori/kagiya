package buildcheck

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// 設計書 3.3 / 4.2: ファイルに触れられるパッケージと、任意のシステムコールを呼べるパッケージを限定する。
var restricted = map[string][]string{
	// import パス → 使用を許可するディレクトリ（リポジトリルートからの相対）
	"os":            {"cmd/kagiya", "internal/cli", "internal/safefs", "internal/platform", "internal/output"},
	"path/filepath": {"cmd/kagiya", "internal/cli", "internal/safefs", "internal/platform", "internal/output"},
	"io/ioutil":     {},
	"syscall":       {"internal/platform"},
	"unsafe":        {"internal/platform"},
	"os/signal":     {"internal/cli"},
}

func TestImportPolicy(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	checked := 0
	for _, top := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, filepath.Dir(path))
			rel = filepath.ToSlash(rel)
			f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly|parser.ParseComments)
			if err != nil {
				return err
			}
			checked++
			for _, cg := range f.Comments {
				if strings.Contains(cg.Text(), "go:linkname") && rel != "internal/platform" {
					t.Errorf("%s: go:linkname is only allowed in internal/platform", path)
				}
			}
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				// lab/ は検証専用。本体から参照しない。
				if p == "kagiya/lab" || strings.HasPrefix(p, "kagiya/lab/") {
					t.Errorf("%s: the tool must not import lab code (%s)", path, p)
				}
				allowed, isRestricted := restricted[p]
				if !isRestricted {
					continue
				}
				ok := false
				for _, a := range allowed {
					if rel == a {
						ok = true
					}
				}
				if !ok {
					t.Errorf("%s: import %q is not allowed in %s (allowed: %v)", path, p, rel, allowed)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if checked == 0 {
		t.Fatal("no source files were checked")
	}
}
