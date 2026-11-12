// このファイルは、導入されているパッケージ版に対応する、アプリの既定値表の引き当て。どのアプリにも共通。

package apps

import (
	"kagiya/internal/model"
	"kagiya/internal/ruleset"
)

// appDefaults は、導入されているパッケージ版に対応するアプリの既定値と、その出典を返す。
//
// 実測した版そのものの表がなければ、パッケージ名・上流の版・ディストリの系列が同じ実測版の表で補間する。
// その場合は note に、実測した版と導入されている版が入る（呼び出し側は結果に残し、確度を下げる）。
// どちらもなければ defs は nil で、reason に理由が入る。
func (c *Collector) appDefaults(app ruleset.AppRule) (defs map[string][]string, prov *model.Provenance, note, reason string) {
	for _, pat := range app.Packages {
		for _, p := range c.Builder.Packages() {
			if !ruleset.MatchName([]string{pat}, p.Name) {
				continue
			}
			version := p.FullVersion()
			d, measured, src, exact, ok := c.Rules.AppDefaultsFor(app.ID, p.Name, version)
			if !ok {
				return nil, nil, "", "no default values are recorded for " + p.Name + " " + version
			}
			if !exact {
				note = "the default values measured on " + p.Name + " " + measured + " are used for the installed " + p.Name + " " + version + " (same upstream version and distribution, different release)"
			}
			return d, &model.Provenance{Image: src.Image, OS: src.OS, Package: p.Name, Version: measured}, note, ""
		}
	}
	return nil, nil, "", "no package information for this application; the default values are unknown"
}
