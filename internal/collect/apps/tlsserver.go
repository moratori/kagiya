package apps

import (
	"strings"

	"kagiya/internal/model"
	"kagiya/internal/parse/keymat"
	"kagiya/internal/ruleset"
	"kagiya/internal/tlsciphers"
	"kagiya/internal/tlseffective"
)

// このファイルは、OpenSSL を使う TLS サーバー（nginx、Apache httpd）に共通の「暗号スイートの実効値」の解決。
// アプリごとに違うのは「設定のどの記載が、どの範囲に効くか」だけで、それは各アプリのファイルが tlsScope にまとめて渡す。
// 版によって違う値（既定の暗号文字列、DH パラメータを持つか、OpenSSL の語の対応）は、すべてルール（rules/）から引く。

// tlsScope は、TLS を待ち受ける設定の範囲（nginx の server、Apache の VirtualHost）1つ分の、解決に必要な記載。
type tlsScope struct {
	name string // 結果に出す範囲の名前（設定値の記録と同じ表記）

	cipher     string // 効いている暗号文字列。記載がなければ空（アプリの既定を使う）
	cipherFile string // その記載の場所（接頭辞なし）
	cipherLine int

	tls13     string // アプリの設定が指定した TLS 1.3 のスイート（「:」区切り）。なければ空
	tls13File string
	tls13Line int

	certs   []string // 証明書のパス（接頭辞なしの絶対パス）
	certsOK bool     // 証明書の記載をすべて解釈できた（変数などを含まない）
	dhParam bool     // DH パラメータの指定がある

	blocker      string // 空でなければ、この範囲の実効値は求めない（理由）
	tls13Blocker string // 空でなければ、TLS 1.3 のスイートだけ求めない（理由）
}

const (
	paramCiphers = "tls.ciphers"
	paramTLS13   = "tls.ciphersuites-tls13"
	paramDHE     = "tls.dhe-without-params"
	paramCertSel = "tls.certificate-selection"

	// 既定の表での特別な値: アプリが暗号文字列を設定せず、OpenSSL のシステム既定のままになる
	cipherSystemDefault = "@system"
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
			version := packageVersion(p)
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

func packageVersion(p model.Package) string {
	if p.Release != "" {
		return p.Version + "-" + p.Release
	}
	return p.Version
}

// cipherTable は、導入されている暗号ライブラリのパッケージ版に対応する暗号スイートの対応表を返す。
// 見つからない、または複数の版が導入されていてどれを使うか決められない場合は、t は nil で、reason に理由が入る。
func (c *Collector) cipherTable(library string) (t *ruleset.CipherTable, prov *model.Provenance, note, reason string) {
	var patterns []string
	for _, l := range c.Rules.Libraries {
		if l.ID == library {
			patterns = l.Packages
		}
	}
	first := ""
	installed := ""
	for _, p := range c.Builder.Packages() {
		if !ruleset.MatchName(patterns, p.Name) {
			continue
		}
		version := packageVersion(p)
		if first == "" {
			first = p.Name + " " + version
		}
		tb, build, exact, ok := c.Rules.CipherTableFor(library, p.Name, version)
		if !ok {
			continue
		}
		if t != nil && (tb != t || installed != p.Name+" "+version) {
			return nil, nil, "", "more than one version of the " + library + " library is installed; which one this server uses is not determined"
		}
		t, installed = tb, p.Name+" "+version
		prov = &model.Provenance{Image: build.Source.Image, OS: build.Source.OS, Package: build.Package, Version: build.Version}
		note = ""
		if !exact {
			note = "the cipher table measured on " + build.Package + " " + build.Version + " is used for the installed " + installed + " (same upstream version and distribution, different release)"
		}
	}
	switch {
	case t != nil:
		return t, prov, note, ""
	case first == "":
		return nil, nil, "", "no package information for the " + library + " library; the cipher table to use is unknown"
	}
	return nil, nil, "", "no cipher table is recorded for " + first
}

// profileString は、「PROFILE=SYSTEM」が指す暗号文字列を、ライブラリが読むファイルから取り出す。
// ファイルは、暗号文字列そのもの（RHEL 8）か、openssl.cnf の断片（CipherString = ... の行。RHEL 9 以降）。
func (c *Collector) profileString(path string) *string {
	if path == "" {
		return nil
	}
	data, err := c.read(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	for _, l := range lines {
		k, v, ok := strings.Cut(l, "=")
		if ok && strings.TrimSpace(k) == "CipherString" {
			v = strings.TrimSpace(v)
			if cipherString.MatchString(v) {
				return &v
			}
			return nil
		}
	}
	v := strings.TrimSpace(lines[0])
	if v == "" || !cipherString.MatchString(v) {
		return nil
	}
	return &v
}

// certKinds は、証明書ファイルを読んで、鍵と署名の種類を返す。1つでも読めなければ ok = false。
func (c *Collector) certKinds(paths []string) (kinds []tlseffective.Cert, ok bool) {
	if len(paths) == 0 {
		return nil, false
	}
	for _, p := range paths {
		data, err := c.read(p)
		if err != nil {
			return nil, false
		}
		items, _ := keymat.Parse(p, data)
		found := false
		for _, it := range items {
			if it.Kind == "certificate" && it.Cert != nil {
				// ファイルの先頭の証明書がサーバー自身のもの（後ろは中間 CA）
				kinds = append(kinds, tlseffective.Cert{Key: keyKind(it.Cert.PublicKeyAlgorithmOID), Signature: signatureKind(it.Cert.SignatureAlgorithmOID)})
				found = true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return kinds, true
}

func keyKind(oid string) string {
	switch oid {
	case "1.2.840.113549.1.1.1", "1.2.840.113549.1.1.10":
		return "RSA"
	case "1.2.840.10045.2.1":
		return "EC"
	case "1.2.840.10040.4.1":
		return "DSA"
	}
	return "other"
}

func signatureKind(oid string) string {
	switch {
	case strings.HasPrefix(oid, "1.2.840.113549.1.1."):
		return "RSA"
	case strings.HasPrefix(oid, "1.2.840.10045.4."):
		return "ECDSA"
	case oid == "1.2.840.10040.4.3" || strings.HasPrefix(oid, "2.16.840.1.101.3.4.3.1") || strings.HasPrefix(oid, "2.16.840.1.101.3.4.3.2"):
		return "DSA"
	}
	return "other"
}

// settingAt は、指定した場所に書かれていた設定値（記録済みのもの）の ID を返す。
func (c *Collector) settingAt(svc model.Service, param, file string, line int) string {
	for _, s := range c.Builder.Settings() {
		if s.Service == svc.ID && s.Parameter == param && s.Location.Path == c.Prefix+file && s.Location.Line == line {
			return s.ID
		}
	}
	return ""
}

// opensslServerEffective は、各範囲について、実際に使える暗号スイートを求めて記録する。
//
// 求めるのは「許可されているスイート」まで。どのプロトコル（TLS 1.2、1.3 など）が有効かは、ここでは解決しない。
func (c *Collector) opensslServerEffective(app ruleset.AppRule, svc model.Service, scopes []tlsScope) {
	if len(scopes) == 0 {
		return
	}
	table, libProv, libNote, noTable := c.cipherTable("openssl")
	defs, appProv, appNote, noDefaults := c.appDefaults(app)

	// システムの openssl.cnf の既定（RHEL 系では暗号ポリシーが生成した内容）
	sysCipher, sysTLS13 := "", ""
	for _, s := range c.Builder.OSSettings() {
		switch s.ID {
		case "openssl.system_default.CipherString":
			sysCipher = s.Value
		case "openssl.system_default.Ciphersuites":
			sysTLS13 = s.Value
		}
	}
	var profile *string
	sysLevel := -1
	if table != nil {
		profile = c.profileString(table.ProfileSystem)
		if sysCipher != "" {
			// システムの暗号文字列に含まれるレベルの指定は、アプリが別の暗号文字列を設定しても残る
			if x, err := tlsciphers.Expand(table, sysCipher, profile); err == nil {
				sysLevel = x.Level
			}
		}
	}

	for _, sc := range scopes {
		e := model.EffectiveValue{Service: svc.ID, Parameter: paramCiphers, Direction: app.Direction, Scope: sc.name, Status: "resolved", Confidence: "high"}
		e13 := e
		e13.Parameter = paramTLS13
		fail := func(reason string) {
			e.Status, e.Confidence, e.Reason = "unresolved", "", reason
			c.Builder.AddEffective(e)
			if table == nil || len(table.TLS13) > 0 {
				e13.Status, e13.Confidence, e13.Reason = "unresolved", "", reason
				c.Builder.AddEffective(e13)
			}
		}
		if table == nil {
			fail(noTable)
			continue
		}
		if sc.blocker != "" {
			fail(sc.blocker)
			continue
		}
		in := tlseffective.Input{Table: table, Profile: profile, SystemLevel: sysLevel}
		if sysTLS13 != "" {
			in.SystemTLS13 = strings.Split(sysTLS13, ":")
		}

		usedAppDefault := false // アプリの既定値表の値を使ったか（補間した表なら、確度を下げる）

		// 1. 暗号文字列: 設定の記載、なければアプリの既定
		first := model.ResolutionStep{Layer: "app-config", Op: "override", Setting: c.settingAt(svc, paramCiphers, sc.cipherFile, sc.cipherLine)}
		in.CipherString = sc.cipher
		if sc.cipher == "" {
			def := defs[paramCiphers]
			if def == nil {
				reason := noDefaults
				if defs != nil {
					reason = "the default cipher string of this application version is not recorded"
				}
				fail(reason)
				continue
			}
			in.CipherString = strings.Join(def, ",")
			first = model.ResolutionStep{Layer: "app-default", Op: "default", Source: appProv}
			usedAppDefault = true
		}
		e.Steps = []model.ResolutionStep{first}
		levelFrom := first // 暗号文字列にセキュリティレベルの指定が含まれるとき、それがどの層のものか
		if in.CipherString == cipherSystemDefault {
			// アプリは何も設定しない。システムの openssl.cnf の暗号文字列があればそれ、なければライブラリの既定（DEFAULT）
			if sysCipher != "" {
				in.CipherString = sysCipher
				levelFrom = model.ResolutionStep{Layer: "os-policy", Op: "override"}
			} else {
				in.CipherString = "DEFAULT"
				levelFrom = model.ResolutionStep{Layer: "library", Op: "default", Source: libProv}
			}
			e.Steps = append(e.Steps, levelFrom)
		}
		if table.ProfileSystem != "" && strings.HasPrefix(in.CipherString, "PROFILE=SYSTEM") {
			e.Steps = append(e.Steps, model.ResolutionStep{Layer: "os-policy", Op: "profile"})
		}

		// 2. サーバーの持ち物: 証明書の種類と、DH パラメータ
		var notes []string
		if sc.certsOK {
			certs := sc.certs
			if strings.Join(defs[paramCertSel], ",") == "first" && len(certs) > 1 {
				certs = certs[:1] // この版は、同じ名前の証明書を複数指定しても最初の1つしか使わない
				usedAppDefault = true
			}
			in.Certs, in.CertsKnown = c.certKinds(certs)
		}
		if sc.tls13 != "" {
			in.AppTLS13 = strings.Split(sc.tls13, ":")
		}
		dheLayer := "app-config"
		var dheSource *model.Provenance
		switch v := strings.Join(defs[paramDHE], ","); {
		case sc.dhParam:
			in.DHE, in.DHEKnown = true, true
		case v == "builtin":
			in.DHE, in.DHEKnown, dheLayer, dheSource = true, true, "app-default", appProv
			usedAppDefault = true
		case v == "disabled":
			in.DHE, in.DHEKnown, dheLayer, dheSource = false, true, "app-default", appProv
			usedAppDefault = true
		}

		out, err := tlseffective.Resolve(in)
		if err != nil {
			fail("the cipher string cannot be expanded: " + err.Error())
			continue
		}
		e.Steps = append(e.Steps, model.ResolutionStep{Layer: "library", Op: "expand", Source: libProv})
		levelStep := model.ResolutionStep{Op: "security-level"}
		switch out.LevelSource {
		case "cipher-string":
			levelStep.Layer, levelStep.Setting, levelStep.Source = levelFrom.Layer, levelFrom.Setting, levelFrom.Source
		case "system":
			levelStep.Layer = "os-policy"
		case "library-default":
			levelStep.Layer, levelStep.Source = "library", libProv
		}
		if levelStep.Layer != "" {
			e.Steps = append(e.Steps, levelStep)
		}
		if in.CertsKnown {
			e.Steps = append(e.Steps, model.ResolutionStep{Layer: "app-config", Op: "filter-certificates"})
		}
		if in.DHEKnown {
			e.Steps = append(e.Steps, model.ResolutionStep{Layer: dheLayer, Op: "filter-dh-parameters", Source: dheSource})
		}
		if libNote != "" {
			notes = append(notes, libNote)
		}
		if appNote != "" && usedAppDefault {
			notes = append(notes, appNote)
		}
		for _, u := range out.Unfiltered {
			switch u {
			case "certificates":
				notes = append(notes, "the server certificate could not be read, so suites are not narrowed down by the certificate type")
			case "dh-parameters":
				notes = append(notes, "whether this application version can use DHE without DH parameters is not recorded, so DHE suites are kept")
			}
		}
		if len(out.Suites) == 0 {
			notes = append(notes, "no suite is usable with this configuration")
		}
		e.Values, e.Notes = out.Suites, notes
		if len(notes) > 0 {
			e.Confidence = "medium"
		}
		c.Builder.AddEffective(e)

		// TLS 1.3 のスイート（暗号文字列とは別に決まる）
		if len(table.TLS13) == 0 {
			continue
		}
		if sc.tls13Blocker != "" {
			e13.Status, e13.Confidence, e13.Reason = "unresolved", "", sc.tls13Blocker
			c.Builder.AddEffective(e13)
			continue
		}
		switch out.TLS13Source {
		case "app":
			e13.Steps = []model.ResolutionStep{{Layer: "app-config", Op: "override", Setting: c.settingAt(svc, paramTLS13, sc.tls13File, sc.tls13Line)}}
		case "system":
			e13.Steps = []model.ResolutionStep{{Layer: "os-policy", Op: "override"}}
		default:
			e13.Steps = []model.ResolutionStep{{Layer: "library", Op: "default", Source: libProv}}
		}
		if levelStep.Layer != "" {
			e13.Steps = append(e13.Steps, levelStep)
		}
		e13.Values = out.TLS13
		e13.Notes = []string{"used only when TLS 1.3 is enabled"}
		if libNote != "" {
			e13.Notes = append(e13.Notes, libNote)
			e13.Confidence = "medium"
		}
		c.Builder.AddEffective(e13)
	}
}
