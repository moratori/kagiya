package buildcheck

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// 独立したレビュー（2026-11-14）の指摘 A-8。「出力先以外に書き込まない」を、import の単位だけでなく、関数の単位でも確かめる:
// ファイルシステムを変更する呼び出し（作成、削除、改名、権限や時刻の変更、書き込み用に開くこと）は、internal/output だけに置く。
var writeCalls = map[string]bool{
	"Create": true, "CreateTemp": true, "WriteFile": true, "Mkdir": true, "MkdirAll": true, "MkdirTemp": true,
	"Remove": true, "RemoveAll": true, "Rename": true, "Chmod": true, "Chown": true, "Lchown": true, "Chtimes": true,
	"Truncate": true, "Link": true, "Symlink": true,
}

var writeFlags = map[string]bool{"O_WRONLY": true, "O_RDWR": true, "O_CREATE": true, "O_APPEND": true, "O_TRUNC": true, "O_EXCL": true}

func TestWritesOnlyInOutputPackage(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	checked := 0
	for _, top := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			rel, _ := filepath.Rel(root, filepath.Dir(path))
			if rel = filepath.ToSlash(rel); rel == "internal/output" {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			checked++
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				recv, _ := sel.X.(*ast.Ident)
				// output パッケージの関数（output.Create など）を呼ぶのは構わない
				if recv != nil && recv.Name == "output" {
					return true
				}
				if writeCalls[sel.Sel.Name] {
					t.Errorf("%s: %s changes the filesystem; only internal/output may do that", fset.Position(call.Pos()), sel.Sel.Name)
				}
				// 書き込み用のフラグを付けて開く呼び出し（os.OpenFile、os.Root の OpenFile）
				if sel.Sel.Name == "OpenFile" {
					for _, arg := range call.Args {
						ast.Inspect(arg, func(m ast.Node) bool {
							if id, ok := m.(*ast.SelectorExpr); ok && writeFlags[id.Sel.Name] {
								t.Errorf("%s: OpenFile with %s; only internal/output may open files for writing", fset.Position(call.Pos()), id.Sel.Name)
							}
							return true
						})
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if checked < 50 {
		t.Fatalf("only %d files were checked", checked)
	}
}
