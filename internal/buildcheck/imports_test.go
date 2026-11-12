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

// 任意のシステムコールを呼べる手段。vendor を含め、internal/platform 以外では使わせない。
var lowLevel = map[string]bool{"syscall": true, "unsafe": true}

func TestImportPolicy(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	checked := 0
	for _, top := range []string{"cmd", "internal", "rules", "vendor"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(root, filepath.Dir(path))
			rel = filepath.ToSlash(rel)
			// アセンブリやオブジェクトファイルは、Go の検査をすり抜けて任意の命令を実行できる。
			if ext := filepath.Ext(path); (ext == ".s" || ext == ".S" || ext == ".syso") && rel != "internal/platform" {
				t.Errorf("%s: assembly and object files are only allowed in internal/platform", path)
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			// ファイル全体を解析する（import より後ろにあるコメントの指示も見るため）。
			f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return err
			}
			checked++
			for _, cg := range f.Comments {
				for _, c := range cg.List {
					if strings.HasPrefix(c.Text, "//go:linkname") && rel != "internal/platform" {
						t.Errorf("%s: go:linkname is only allowed in internal/platform", fset.Position(c.Pos()))
					}
				}
			}
			vendored := strings.HasPrefix(rel, "vendor/") || rel == "vendor"
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				// lab/ は検証専用。本体から参照しない。
				if p == "kagiya/lab" || strings.HasPrefix(p, "kagiya/lab/") {
					t.Errorf("%s: the tool must not import lab code (%s)", path, p)
				}
				if p == "C" {
					t.Errorf("%s: cgo is not allowed", path)
				}
				if vendored {
					// 外部の依存は、任意のシステムコールを呼べる手段を使っていないこと（ファイルを扱う規則は本体のコードが対象）。
					if lowLevel[p] {
						t.Errorf("%s: vendored code must not import %q", path, p)
					}
					continue
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
