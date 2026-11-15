package cli

import (
	"regexp"

	"kagiya/internal/model"
	"kagiya/internal/parse/unitfile"
	"kagiya/internal/ruleset"
)

// ディストリの名前と版として結果に出してよい文字（設定ファイルの値なので、そのままは信用しない）。
var osReleaseValue = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._()/+:,-]{0,127}$`)

// parseOSRelease は /etc/os-release の内容から、ディストリの名前と版を取り出す。読めるものがなければ nil。
func parseOSRelease(data []byte) *model.Distribution {
	v := map[string]string{}
	for _, e := range unitfile.ParseEnv(data) {
		if osReleaseValue.MatchString(e.Value) {
			v[e.Key] = e.Value
		}
	}
	d := &model.Distribution{ID: v["ID"], VersionID: v["VERSION_ID"], Name: v["PRETTY_NAME"]}
	if d.Name == "" && v["NAME"] != "" {
		d.Name = v["NAME"]
		if v["VERSION"] != "" {
			d.Name += " " + v["VERSION"]
		}
	}
	if d.ID == "" && d.VersionID == "" && d.Name == "" {
		return nil
	}
	return d
}

// ruleHost は、ルールの補間に渡すホストの OS を返す（os-release の ID と VERSION_ID）。読めなければ空。
// 測っていない版を補うとき、Ubuntu は、ルールを測った OS のリリースが、ホストの OS のリリースと同じ場合に限る（ruleset.WithHost）。
func ruleHost(d *model.Distribution) ruleset.Host {
	if d == nil {
		return ruleset.Host{}
	}
	return ruleset.Host{ID: d.ID, VersionID: d.VersionID}
}
