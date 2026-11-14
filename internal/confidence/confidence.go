// Package confidence は、実効値の確度を決める。確度を決める処理は、ここだけに置く（docs/confidence.md の 4 章の原則 3）。
//
// 確度は、kagiya が実効値の計算に使ったルールが、そのホストにどれだけ合っているかを表す。材料は、ルール 1 つにつき 2 つだけ:
//
//   - kagiya が、そのルールを、完全一致で見つけたか、補ったか
//   - 開発者が、そのルールを、その版そのものの数え上げで裏付けたか（ルールの verified-by-handshake）
//
// 証明書の種類を判定できなかったこと、JDK を 1 つに決められなかったこと、実効値が空であることは、確度を下げる理由にしない。
package confidence

// 確度の値（スキャン結果に書く値）。
const (
	High   = "high"
	Medium = "medium"
	Low    = "low"
)

// Match は、kagiya が、ホストの版に対応するルールを見つけた方法。
type Match int

const (
	// Exact は、完全一致（ホストに導入されている版と、版の文字列がすべて同じルール）。
	Exact Match = iota
	// Filled は、補った（同じ系列で作り直しの番号だけ違うルール、または、JDK で、開発元の版が同じで配っている組織が違うルール）。
	Filled
)

// Rule は、実効値の計算に使ったルール 1 つについての、確度を決める材料。
type Rule struct {
	Match               Match
	VerifiedByHandshake bool
}

// of は、ルール 1 つについての確度（docs/confidence.md の 6.3 節の表）。
func of(r Rule) string {
	switch {
	case r.Match == Exact && r.VerifiedByHandshake:
		return High
	case r.Match == Exact || r.VerifiedByHandshake:
		return Medium
	}
	return Low
}

// Of は、実効値の計算に使ったルールから、その実効値の確度を決める。
// 複数のルールを使った場合は、ルールごとの確度のうち、最も低いものにする（6.4 節）。
// ルールを 1 つも渡さない呼び出しは、呼び出し側の誤りなので、最も低い確度を返す（高い確度を誤って付けないため）。
func Of(rules ...Rule) string {
	levels := make([]string, 0, len(rules))
	for _, r := range rules {
		levels = append(levels, of(r))
	}
	return Lowest(levels...)
}

var rank = map[string]int{High: 3, Medium: 2, Low: 1}

// Lowest は、確度の並び（高 > 中 > 低）で、最も低いものを返す。決まった 3 つ以外の値と、空の並びは、低として扱う。
func Lowest(levels ...string) string {
	if len(levels) == 0 {
		return Low
	}
	lowest := High
	for _, l := range levels {
		if rank[l] < rank[lowest] {
			lowest = l
		}
		if rank[l] == 0 {
			return Low
		}
	}
	return lowest
}

// ConfigurationOnly は、ルールを 1 つも使わずに求めた実効値（設定ファイルに、名前の一覧がそのまま書かれている場合）に渡す。
var ConfigurationOnly = Rule{Match: Exact, VerifiedByHandshake: true}
