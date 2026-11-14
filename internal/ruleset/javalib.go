// このファイルは、Java の暗号ライブラリの定義（JAR のファイル名から、ライブラリと版を特定する）。

package ruleset

import (
	"fmt"
	"regexp"
	"strings"
)

// JavaLibraryRule は、Java の暗号ライブラリ 1 つの定義。
type JavaLibraryRule struct {
	ID string `yaml:"id"`
	// 成果物（アーティファクト）の名前。JAR のファイル名は「<成果物の名前>-<版>.jar」。末尾に * を付けると前方一致
	Artifacts []string `yaml:"artifacts"`
	Sources   []Source `yaml:"sources"`
	// 耐量子のアルゴリズムに対応している版の事実（なければ nil）
	PQC *PQCRule `yaml:"pqc"`
}

var (
	javaArtifactPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*(-\*)?$`)
	javaVersionPattern  = regexp.MustCompile(`^[0-9][0-9A-Za-z.+_-]{0,63}$`)
)

func (rs *RuleSet) addJavaLibrary(l JavaLibraryRule, ids map[string]bool) error {
	if !idPattern.MatchString(l.ID) {
		return fmt.Errorf("invalid library id %q", l.ID)
	}
	if ids["lib\x00"+l.ID] {
		return fmt.Errorf("duplicate library id %q", l.ID)
	}
	ids["lib\x00"+l.ID] = true
	if err := checkSources(l.Sources); err != nil {
		return fmt.Errorf("library %s: %w", l.ID, err)
	}
	if len(l.Artifacts) == 0 || len(l.Artifacts) > 64 {
		return fmt.Errorf("library %s: invalid number of artifacts", l.ID)
	}
	for _, a := range l.Artifacts {
		if len(a) > 64 || !javaArtifactPattern.MatchString(a) {
			return fmt.Errorf("library %s: invalid artifact %q", l.ID, a)
		}
	}
	if l.PQC != nil {
		if err := checkPQC(l.PQC); err != nil {
			return fmt.Errorf("library %s: %w", l.ID, err)
		}
	}
	rs.JavaLibraries = append(rs.JavaLibraries, l)
	return nil
}

// JavaLibraryForFile は、JAR のファイル名（ディレクトリを除いた名前）から、暗号ライブラリの定義と、成果物の名前、版を返す。
// 名前は「<成果物の名前>-<版>.jar」か、版のない「<成果物の名前>.jar」。版は、数字で始まる部分。
func (rs *RuleSet) JavaLibraryForFile(file string) (rule JavaLibraryRule, artifact, version string, ok bool) {
	base, found := strings.CutSuffix(file, ".jar")
	if !found || base == "" || len(base) > 200 {
		return JavaLibraryRule{}, "", "", false
	}
	// 成果物の名前と版の境目の候補: 「-」の直後が数字のところ（成果物の名前にも数字で始まる部分がありうるので、すべて試す）
	try := func(artifact, version string) (JavaLibraryRule, bool) {
		if version != "" && !javaVersionPattern.MatchString(version) {
			return JavaLibraryRule{}, false
		}
		for _, l := range rs.JavaLibraries {
			for _, a := range l.Artifacts {
				if p, wild := strings.CutSuffix(a, "*"); (wild && strings.HasPrefix(artifact, p) && len(artifact) > len(p)) || (!wild && artifact == a) {
					return l, true
				}
			}
		}
		return JavaLibraryRule{}, false
	}
	for i := 0; i+1 < len(base); i++ {
		if base[i] == '-' && base[i+1] >= '0' && base[i+1] <= '9' {
			if l, ok := try(base[:i], base[i+1:]); ok {
				return l, base[:i], base[i+1:], true
			}
		}
	}
	if l, ok := try(base, ""); ok {
		return l, base, "", true
	}
	return JavaLibraryRule{}, "", "", false
}
