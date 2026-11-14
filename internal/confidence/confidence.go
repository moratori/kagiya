// Package confidence は、実効値の確度を決める。
package confidence

// 確度の値。
const (
	High   = "high"
	Medium = "medium"
	Low    = "low"
)

// Match は、ルールを見つけた方法。
type Match int

const (
	Exact  Match = iota // 完全一致
	Filled              // 補った
)

// Rule は、実効値の計算に使ったルール 1 つについての、確度を決める材料。
type Rule struct {
	Match               Match
	VerifiedByHandshake bool
}

// Of は、使ったルールから、確度を決める。
func Of(rules ...Rule) string { return "" }

// Lowest は、最も低い確度を返す。
func Lowest(levels ...string) string { return "" }
