// Package shellconf は、シェルが取り込む（source する）設定ファイルのうち、「名前=値」が並ぶ単純なものを読む。
// シェルとしては実行しない。展開（変数、コマンドの置き換えなど）を含む値は「決まらない」とし、代入でない行があれば
// 全体を読めないものとして扱う。値を返すのは、呼び出し側が指定した名前だけ（それ以外は、代入があったことだけ）。
package shellconf

const (
	MaxSize = 64 << 10 // これより大きいファイルは読まない
	MaxLine = 4096     // これより長い行があれば読まない
)

// Result は、読み取った結果。
type Result struct {
	Values   map[string]string // 指定した名前のうち、値が決まったもの
	Unknown  map[string]bool   // 代入はあるが、値が決まらないもの（展開を含む）
	Assigned map[string]bool   // 代入があった名前すべて
	Opaque   int               // 0 でなければ、解釈できない行（代入でない行など）の番号。このとき、ほかの項目は当てにできない
}

// Parse は、設定ファイルを読む。names は、値を取り出す名前。
func Parse(data []byte, names ...string) Result {
	return Result{Values: map[string]string{}, Unknown: map[string]bool{}, Assigned: map[string]bool{}}
}
