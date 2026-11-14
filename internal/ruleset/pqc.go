// このファイルは、暗号ライブラリが耐量子のアルゴリズムに対応している版の事実（どの版から対応したか）。
// 事実は、検証ラボで各版の実物に尋ねた結果と、開発元の資料（リリースノート）から。出典は、ルールに書く。
// ここで言う「対応」は、ライブラリがその方式を持っていること。使われているかどうかは、別に実効値で見る。

package ruleset

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// VersionRange は、実物で確かめた版の範囲（両端を含む）。
type VersionRange struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
}

// PQCFeature は、耐量子の機能 1 つについての事実。
type PQCFeature struct {
	Name string `yaml:"name"` // ML-KEM、ML-DSA、SLH-DSA、TLS-MLKEM（TLS の ML-KEM 単独の鍵交換）、TLS-MLKEM-hybrid（TLS のハイブリッドの鍵交換）
	// 対象の成果物の名前（Java のライブラリ。末尾の * は前方一致）。空なら、ライブラリ全体
	Artifacts []string `yaml:"artifacts"`
	// この版から対応している。空なら「確かめた範囲では対応していない」
	Since   string       `yaml:"since"`
	Checked VersionRange `yaml:"checked"`
	// 確かめた範囲の中で、測れなかった版
	Unmeasured []string `yaml:"unmeasured"`
	// 根拠: measured（既定。実物に尋ねた）/ documented（開発元の資料だけ）
	Evidence string `yaml:"evidence"`
}

// PQCRule は、ライブラリ 1 つの、耐量子の機能の事実。
type PQCRule struct {
	Features []PQCFeature `yaml:"features"`
	Sources  []Source     `yaml:"sources"`
}

// PQCResult は、ある版についての結果。
type PQCResult struct {
	Supported, NotSupported, Unknown []string
	// measured: 実物で確かめた版の範囲 / documented: 開発元の資料から / extrapolated: 確かめた範囲の外の版で、前後から推定
	Basis string
}

const (
	PQCMeasured     = "measured"
	PQCDocumented   = "documented"
	PQCExtrapolated = "extrapolated"
)

var (
	pqcNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{1,31}$`)
	// 版: 数字を「.」でつないだもの。後ろに付いてよいのは、正式版を表す語（.Final、.RELEASE）、OpenSSL の英字（1.1.1k）、
	// 対象の OS とアーキテクチャ（-linux-x86_64 など）だけ。それ以外（alpha、RC、SNAPSHOT など）は、正式版でないので比べない
	versionPattern = regexp.MustCompile(`^(\d{1,9}(?:\.\d{1,9}){0,7})(?:[a-z]{1,2}|\.Final|\.RELEASE)?(?:-(?:linux|osx|windows)-[a-z0-9_]{1,16})?$`)
)

func checkPQC(r *PQCRule) error {
	if err := checkSources(r.Sources); err != nil {
		return err
	}
	if len(r.Features) == 0 || len(r.Features) > 32 {
		return errors.New("invalid number of PQC features")
	}
	for _, f := range r.Features {
		if !pqcNamePattern.MatchString(f.Name) {
			return fmt.Errorf("invalid PQC feature name %q", f.Name)
		}
		for _, a := range f.Artifacts {
			if len(a) > 64 || !javaArtifactPattern.MatchString(a) {
				return fmt.Errorf("PQC feature %s: invalid artifact %q", f.Name, a)
			}
		}
		if c, ok := CompareVersions(f.Checked.From, f.Checked.To); !ok || c > 0 {
			return fmt.Errorf("PQC feature %s: the checked range is missing or invalid", f.Name)
		}
		if f.Since != "" {
			if _, ok := CompareVersions(f.Since, f.Since); !ok {
				return fmt.Errorf("PQC feature %s: invalid version %q", f.Name, f.Since)
			}
		}
		for _, v := range f.Unmeasured {
			if _, ok := CompareVersions(v, v); !ok {
				return fmt.Errorf("PQC feature %s: invalid version %q", f.Name, v)
			}
		}
		if f.Evidence != "" && f.Evidence != PQCMeasured && f.Evidence != PQCDocumented {
			return fmt.Errorf("PQC feature %s: invalid evidence %q", f.Name, f.Evidence)
		}
	}
	return nil
}

// For は、成果物の名前（Java のライブラリ以外では空）と版から、耐量子の機能への対応を返す。
// 対象の機能が 1 つもなければ ok = false。
func (r *PQCRule) For(artifact, version string) (res PQCResult, ok bool) {
	if r == nil {
		return PQCResult{}, false
	}
	rank := map[string]int{PQCMeasured: 0, PQCDocumented: 1, PQCExtrapolated: 2}
	res.Basis = PQCMeasured
	weaken := func(basis string) {
		if rank[basis] > rank[res.Basis] {
			res.Basis = basis
		}
	}
	for _, f := range r.Features {
		if !f.applies(artifact) {
			continue
		}
		ok = true
		_, comparable := CompareVersions(version, version)
		for _, u := range f.Unmeasured {
			if c, both := CompareVersions(version, u); both && c == 0 {
				comparable = false
			}
		}
		if !comparable {
			res.Unknown = append(res.Unknown, f.Name)
			continue
		}
		below, _ := CompareVersions(version, f.Checked.From)
		above, _ := CompareVersions(version, f.Checked.To)
		if f.Since == "" {
			// 確かめた範囲では対応していない。それより新しい版のことは分からない
			if above > 0 {
				res.Unknown = append(res.Unknown, f.Name)
				continue
			}
			res.NotSupported = append(res.NotSupported, f.Name)
		} else if c, _ := CompareVersions(version, f.Since); c >= 0 {
			res.Supported = append(res.Supported, f.Name)
		} else {
			res.NotSupported = append(res.NotSupported, f.Name)
		}
		switch {
		case below < 0 || above > 0:
			weaken(PQCExtrapolated)
		case f.Evidence == PQCDocumented:
			weaken(PQCDocumented)
		}
	}
	return res, ok
}

func (f PQCFeature) applies(artifact string) bool {
	if len(f.Artifacts) == 0 {
		return true
	}
	for _, a := range f.Artifacts {
		if p, wild := strings.CutSuffix(a, "*"); (wild && strings.HasPrefix(artifact, p) && len(artifact) > len(p)) || (!wild && artifact == a) {
			return true
		}
	}
	return false
}

// CompareVersions は、2 つの版を、数字の並びとして比べる（a < b なら -1、同じなら 0、a > b なら 1）。
// どちらかが正式版の形でなければ ok = false（推測で前後を決めない）。
func CompareVersions(a, b string) (c int, ok bool) {
	x, okA := versionNumbers(a)
	y, okB := versionNumbers(b)
	if !okA || !okB {
		return 0, false
	}
	for i := 0; i < len(x) || i < len(y); i++ {
		var p, q int
		if i < len(x) {
			p = x[i]
		}
		if i < len(y) {
			q = y[i]
		}
		if p != q {
			if p < q {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

func versionNumbers(v string) ([]int, bool) {
	m := versionPattern.FindStringSubmatch(v)
	if m == nil {
		return nil, false
	}
	var out []int
	for _, s := range strings.Split(m[1], ".") {
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}
