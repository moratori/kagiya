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

// docs/confidence.md の 4 章の原則 3: 確度を決める処理は、プログラムの 1 か所（internal/confidence。呼び出すのは internal/inventory）だけに置く。
// 実効値を計算する処理（internal/collect の下）は、確度を自分で決めない。確度の欄に値を入れることも、確度の値（高・中・低）を扱うことも、
// 確度を決める関数を呼ぶこともしない。渡してよいのは、確度の材料（confidence.Rule、confidence.Exact / Filled、confidence.ConfigurationOnly）だけ。
func TestCollectorsDoNotDecideConfidence(t *testing.T) {
	root := filepath.Join("..", "..", "internal", "collect")
	fset := token.NewFileSet()
	checked := 0
	forbidden := map[string]bool{"High": true, "Medium": true, "Low": true, "Of": true, "Lowest": true}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		checked++
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.KeyValueExpr:
				if id, ok := x.Key.(*ast.Ident); ok && id.Name == "Confidence" {
					t.Errorf("%s: a collector sets Confidence in a literal", fset.Position(x.Pos()))
				}
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "Confidence" {
						t.Errorf("%s: a collector assigns Confidence", fset.Position(lhs.Pos()))
					}
				}
			case *ast.SelectorExpr:
				pkg, ok := x.X.(*ast.Ident)
				if !ok {
					break
				}
				if pkg.Name == "confidence" && forbidden[x.Sel.Name] {
					t.Errorf("%s: a collector uses confidence.%s", fset.Position(x.Pos()), x.Sel.Name)
				}
				if pkg.Name == "model" && strings.HasPrefix(x.Sel.Name, "Confidence") {
					t.Errorf("%s: a collector uses model.%s", fset.Position(x.Pos()), x.Sel.Name)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 20 {
		t.Errorf("only %d files were checked", checked)
	}
}
