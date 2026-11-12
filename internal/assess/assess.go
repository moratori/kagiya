// Package assess は、見つかった暗号を評価ポリシー（ルールの policies/）で判定する。
//
// 判定の基準はすべてポリシーのデータにあり、ここには「何をどの規則に当てるか」の対応だけを置く。
// 1つの対象に複数の規則が当たった場合は、軸ごとに最も厳しい判定を採る。どの規則も当たらない軸は「unknown」になる。
package assess

import (
	"errors"
	"path"
	"sort"
	"strconv"
	"strings"

	"kagiya/internal/model"
	"kagiya/internal/ruleset"
)

type Evaluator struct {
	rs     *ruleset.RuleSet
	policy *ruleset.Policy
}

// New は、指定した評価ポリシーで判定する Evaluator を返す。
func New(rs *ruleset.RuleSet, policyID string) (*Evaluator, error) {
	p, ok := rs.Policy(policyID)
	if !ok {
		return nil, errors.New("unknown assessment policy: " + policyID)
	}
	return &Evaluator{rs: rs, policy: p}, nil
}

func (e *Evaluator) Policy() *ruleset.Policy { return e.policy }

// merge は、判定に規則1つ分を足す（軸ごとに厳しいほうを残す）。
func merge(v *model.Verdict, quantum, classical string) {
	if ruleset.QuantumRank[quantum] > ruleset.QuantumRank[v.Quantum] {
		v.Quantum = quantum
	}
	if ruleset.ClassicalRank[classical] > ruleset.ClassicalRank[v.Classical] {
		v.Classical = classical
	}
}

// combine は、部品ごとの判定をまとめる。
func combine(parts ...model.Verdict) model.Verdict {
	var out model.Verdict
	seen := map[string]bool{}
	for _, p := range parts {
		merge(&out, p.Quantum, p.Classical)
		for _, r := range p.Rules {
			if !seen[r] {
				seen[r] = true
				out.Rules = append(out.Rules, r)
			}
		}
	}
	return finish(out)
}

func finish(v model.Verdict) model.Verdict {
	if v.Quantum == "" {
		v.Quantum = "unknown"
	}
	if v.Classical == "" {
		v.Classical = "unknown"
	}
	return v
}

var unknown = model.Verdict{Quantum: "unknown", Classical: "unknown"}

func matchNames(patterns []string, name string) bool {
	for _, p := range patterns {
		if p == name {
			return true
		}
		if strings.Contains(p, "*") {
			if ok, err := path.Match(p, name); err == nil && ok {
				return true
			}
		}
	}
	return false
}

func in(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Name は、名前（TLS の鍵交換、SSH の方式名など）を判定する。どの規則も当たらなければ ok = false。
func (e *Evaluator) Name(scheme, name string) (model.Verdict, bool) {
	var v model.Verdict
	for _, r := range e.policy.Rules {
		if r.Scheme != scheme || !matchNames(r.Match.Names, name) {
			continue
		}
		merge(&v, r.Quantum, r.Classical)
		v.Rules = append(v.Rules, r.ID)
	}
	if len(v.Rules) == 0 {
		return unknown, false
	}
	return finish(v), true
}

// Algorithm は、暗号カタログのアルゴリズム（資産）を判定する。
func (e *Evaluator) Algorithm(assetID string, a *model.Algorithm) model.Verdict {
	if a == nil || !a.Known {
		return unknown
	}
	// カタログの ID。資産の ID は「alg:<カタログの ID>」で、鍵長が付くことがある（alg:rsa-2048）
	id := strings.TrimPrefix(assetID, "alg:")
	base := id
	if a.KeyBits > 0 {
		base = strings.TrimSuffix(id, "-"+strconv.Itoa(a.KeyBits))
	}
	var v model.Verdict
	for _, r := range e.policy.Rules {
		if r.Scheme != "catalog" {
			continue
		}
		m := r.Match
		if len(m.Names) > 0 && !matchNames(m.Names, id) && !matchNames(m.Names, base) {
			continue
		}
		if len(m.Family) > 0 && !in(m.Family, a.Family) {
			continue
		}
		if len(m.Primitive) > 0 && !in(m.Primitive, a.Primitive) {
			continue
		}
		if m.MinBits > 0 || m.MaxBits > 0 {
			// 鍵長の条件は、鍵長が分かっているものにだけ当たる
			if a.KeyBits <= 0 || a.KeyBits < m.MinBits || (m.MaxBits > 0 && a.KeyBits > m.MaxBits) {
				continue
			}
		}
		merge(&v, r.Quantum, r.Classical)
		v.Rules = append(v.Rules, r.ID)
	}
	return finish(v)
}

// Suite は、TLS の暗号スイートを判定する。鍵交換・認証・暗号化・MAC のそれぞれを判定してまとめる。
// 対応表にない名前は ok = false。
func (e *Evaluator) Suite(name string) (model.Verdict, bool) {
	s, ok := e.rs.SuiteAttributes(name)
	if !ok {
		return unknown, false
	}
	var parts []model.Verdict
	for _, c := range [][2]string{{"tls-kx", s.Kx}, {"tls-au", s.Au}, {"tls-enc", s.Enc}, {"tls-mac", s.Mac}} {
		// 部品ごとの判定では、規則が触れていない軸を空のままにする（その軸は他の部品が決める）。
		// 規則が1つも当たらない部品があれば、どちらの軸も判定できない。
		v := e.partial(c[0], c[1])
		if len(v.Rules) == 0 {
			v = unknown
		}
		parts = append(parts, v)
	}
	return combine(parts...), true
}

// partial は Name と同じ判定をするが、規則が触れていない軸を空のまま返す。
func (e *Evaluator) partial(scheme, name string) model.Verdict {
	var v model.Verdict
	for _, r := range e.policy.Rules {
		if r.Scheme == scheme && matchNames(r.Match.Names, name) {
			merge(&v, r.Quantum, r.Classical)
			v.Rules = append(v.Rules, r.ID)
		}
	}
	return v
}

// 実効値の項目 → 名前の種類。ここにない項目（数値など）は評価しない。
var parameterScheme = map[string]string{
	"tls.ciphers":                       "tls-suite",
	"tls.ciphersuites-tls13":            "tls-suite",
	"ssh.kex-algorithms":                "ssh-kex",
	"ssh.host-key-algorithms":           "ssh-key",
	"ssh.pubkey-accepted-algorithms":    "ssh-key",
	"ssh.hostbased-accepted-algorithms": "ssh-key",
	"ssh.ca-signature-algorithms":       "ssh-key",
	"ssh.ciphers":                       "ssh-cipher",
	"ssh.macs":                          "ssh-mac",
}

// Assess は、結果全体を判定する。
func (e *Evaluator) Assess(inv *model.Inventory) *model.Assessment {
	a := &model.Assessment{Policy: e.policy.ID, PolicyVersion: e.policy.Version,
		Assets: map[string]model.Verdict{}, Values: map[string]model.Verdict{}}

	for _, as := range inv.Assets {
		if as.Type == "algorithm" {
			a.Assets[as.ID] = e.Algorithm(as.ID, as.Algorithm)
		}
	}
	ref := func(id string) model.Verdict {
		if v, ok := a.Assets[id]; ok && id != "" {
			return v
		}
		return unknown
	}
	for _, as := range inv.Assets {
		switch {
		case as.Type == "certificate" && as.Certificate != nil:
			// 証明書は、公開鍵と署名のうち厳しいほう
			a.Assets[as.ID] = combine(ref(as.Certificate.PublicKey.Algorithm), ref(as.Certificate.SignatureAlgorithm))
		case (as.Type == "private-key" || as.Type == "public-key") && as.Key != nil:
			a.Assets[as.ID] = combine(ref(as.Key.Algorithm))
		}
	}

	for _, ev := range inv.EffectiveValues {
		scheme, ok := parameterScheme[ev.Parameter]
		if !ok || ev.Status != "resolved" {
			continue
		}
		for _, name := range ev.Values {
			key := scheme + ":" + name
			if _, done := a.Values[key]; done {
				continue
			}
			var v model.Verdict
			if scheme == "tls-suite" {
				v, _ = e.Suite(name)
			} else {
				v, _ = e.Name(scheme, name)
			}
			a.Values[key] = v // 規則のない名前も「判定できない」として残す
		}
	}
	// プロトコルの版は、設定に書かれた値を判定する（「all」「-SSLv3」のような、版の名前でない語は対象にしない）
	for _, s := range inv.Settings {
		if s.Parameter != "tls.protocols" {
			continue
		}
		for _, name := range s.Values {
			if v, ok := e.Name("tls-protocol", name); ok {
				a.Values["tls-protocol:"+name] = v
			}
		}
	}
	for _, m := range []map[string]model.Verdict{a.Assets, a.Values} {
		for k, v := range m {
			sort.Strings(v.Rules)
			m[k] = v
		}
	}
	return a
}
