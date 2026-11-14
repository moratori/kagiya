// このファイルは、暗号ライブラリが耐量子のアルゴリズムに対応している版の事実（どの版から対応したか）。

package ruleset

// VersionRange は、実物で確かめた版の範囲（両端を含む）。
type VersionRange struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
}

// PQCFeature は、耐量子の機能 1 つについての事実。
type PQCFeature struct {
	Name       string       `yaml:"name"`
	Artifacts  []string     `yaml:"artifacts"`
	Since      string       `yaml:"since"`
	Checked    VersionRange `yaml:"checked"`
	Unmeasured []string     `yaml:"unmeasured"`
	Evidence   string       `yaml:"evidence"`
}

// PQCRule は、ライブラリ 1 つの、耐量子の機能の事実。
type PQCRule struct {
	Features []PQCFeature `yaml:"features"`
	Sources  []Source     `yaml:"sources"`
}

// PQCResult は、ある版についての結果。
type PQCResult struct {
	Supported, NotSupported, Unknown []string
	Basis                            string
}

func checkPQC(r *PQCRule) error { return nil }

// For は、成果物の名前と版から、耐量子の機能への対応を返す。
func (r *PQCRule) For(artifact, version string) (PQCResult, bool) { return PQCResult{}, false }

// CompareVersions は、2 つの版を比べる。
func CompareVersions(a, b string) (int, bool) { return 0, false }
