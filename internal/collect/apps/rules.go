package apps

import (
	"strings"

	"kagiya/internal/confidence"
	"kagiya/internal/ruleset"
)

// このファイルは、実効値の計算に使ったルールを、確度の材料として申告するための部品。
// 確度そのものは、ここでは決めない（internal/confidence だけが決める。docs/confidence.md の 4 章の原則 3）。

// ruleOf は、使ったルール 1 つについての、確度の材料を作る。
// src はそのルールの出典、item は使った項目の名前（出典全体の記載を使うなら空）、exact は、ホストの版そのもののルールか（補ったなら false）。
func ruleOf(src ruleset.Source, item string, exact bool) confidence.Rule {
	m := confidence.Exact
	if !exact {
		m = confidence.Filled
	}
	return confidence.Rule{Match: m, VerifiedByHandshake: src.EvidenceFor(item).Verified()}
}

// defaultsRule は、アプリの既定値表の項目 1 つを使ったときの、確度の材料を返す関数。
type defaultsRule func(item string) confidence.Rule

// groupOnlyItem は、アプリの既定値表の項目のうち、鍵交換のグループの求め方にだけ使うもの（暗号スイートの求め方には関係しない）かを返す。
func groupOnlyItem(item string) bool {
	return item == "tls.groups" || strings.HasPrefix(item, "tls.eecdh-") || strings.HasPrefix(item, "tls.ffdhe-")
}
