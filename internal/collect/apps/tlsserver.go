package apps

import (
	"kagiya/internal/confidence"
	"strings"

	"kagiya/internal/model"
	"kagiya/internal/parse/keymat"
	"kagiya/internal/ruleset"
	"kagiya/internal/tlsciphers"
	"kagiya/internal/tlseffective"
)

// tlsScope は、TLS を待ち受ける設定の範囲（nginx の server、Apache の VirtualHost）1つ分の、解決に必要な記載。
type tlsScope struct {
	name string // 結果に出す範囲の名前（設定値の記録と同じ表記）

	cipher     string // 効いている暗号文字列。記載がなければ空（アプリの既定を使う）
	cipherFile string // その記載の場所（接頭辞なし）
	cipherLine int

	// 鍵交換のグループの指定（アプリの設定に書かれたもの）。なければ空
	groups      string
	groupsFile  string
	groupsLine  int
	groupsParam string // その記載を記録した設定項目の名前（空なら tls.groups）
	// 空でなければ、鍵交換のグループは求めない（理由）
	groupsBlocker string

	tls13     string // アプリの設定が指定した TLS 1.3 のスイート（「:」区切り）。なければ空
	tls13File string
	tls13Line int

	certs   []string // 証明書のパス（接頭辞なしの絶対パス）
	certsOK bool     // 証明書の記載をすべて解釈できた（変数などを含まない）
	dhParam bool     // DH パラメータの指定がある

	blocker      string   // 空でなければ、この範囲の実効値は求めない（理由）
	cipherParam  string   // 暗号文字列の根拠として示す設定項目の名前（空なら tls.ciphers）
	info         []string // 結果に添える説明（実測で確かめた挙動の説明。確度は下げない）
	autoRSA      bool     // 設定に証明書の指定がなく、アプリが自分で用意した RSA の証明書を使う（実測で確かめた挙動）
	noCert       bool     // 証明書を持たないサービス（認証なしのスイートだけを使える。TLS 1.3 は使えない）
	tls13Blocker string   // 空でなければ、TLS 1.3 のスイートだけ求めない（理由）
	tls12Blocker string   // 空でなければ、TLS 1.2 以下のスイートだけ求めない（理由）
	// 証明書のファイルを読まなくても分かっている、証明書の鍵の種類（RSA / EC / DSA）。あれば、certs の代わりに使う
	certKinds []string
	// 設定で、TLS 1.2 以下（または TLS 1.3）が有効にされていない。そのスイートは空として記録する
	tls12Off, tls13Off bool
	// この範囲を組み立てるのに、アプリごとの処理が使った、アプリの既定値表の項目（確度の材料として申告する）
	usedDefaults []string
}

const (
	paramCiphers  = model.ParamTLSCiphers
	paramTLS13    = model.ParamTLSCiphersuites
	paramDHE      = model.ParamTLSDHEWithout
	paramAppLevel = "tls.security-level" // 既定の表: アプリが OpenSSL に設定するセキュリティレベル
	paramCertSel  = model.ParamTLSCertSelection
	// 既定の表: 後の版で加わった設定項目のうち、その版で、効き方を測ってあるもの（PostgreSQL の ssl_groups など）
	paramMeasuredSettings = "tls.measured-settings"

	// 既定の表での特別な値: アプリが暗号文字列を設定せず、OpenSSL のシステム既定のままになる
	cipherSystemDefault = "@system"
)

// libraryTable は、導入されている暗号ライブラリのパッケージ版に対応する、実測の表を探す。
// find は、パッケージ名と版から表を引く（暗号スイートの対応表か、鍵交換のグループの対応表か）。what は、理由の文に入れる表の呼び名。
// 見つからない、または複数の版が導入されていてどれを使うか決められない場合は、ok = false で、reason に理由が入る。
func (c *Collector) libraryTable(library, what string, find func(pkg, version string) (key any, build ruleset.CipherBuild, exact, ok bool)) (key any, prov *model.Provenance, note, reason string, rule confidence.Rule) {
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
		version := p.FullVersion()
		if first == "" {
			first = p.Name + " " + version
		}
		k, build, exact, ok := find(p.Name, version)
		kind := strings.ReplaceAll(what, " ", "-") // cipher-table / group-table
		if !ok {
			c.Builder.NoteUnmeasured(model.Unmeasured{Kind: kind, Name: p.Name, Version: version, Status: "missing"})
			continue
		}
		if !exact {
			c.Builder.NoteUnmeasured(model.Unmeasured{Kind: kind, Name: p.Name, Version: version, Status: "interpolated", Measured: build.Version})
		}
		if key != nil && (k != key || installed != p.Name+" "+version) {
			return nil, nil, "", "more than one version of the " + library + " library is installed; which one this server uses is not determined", rule
		}
		key, installed = k, p.Name+" "+version
		prov = &model.Provenance{Image: build.Source.Image, OS: build.Source.OS, Package: build.Package, Version: build.Version}
		rule = ruleOf(build.Source, "", exact)
		note = ""
		if !exact {
			note = "the " + what + " measured on " + build.Package + " " + build.Version + " is used for the installed " + installed + " (same upstream version and distribution, different release)"
		}
	}
	switch {
	case key != nil:
		return key, prov, note, "", rule
	case first == "":
		return nil, nil, "", "no package information for the " + library + " library; the " + what + " to use is unknown", rule
	}
	return nil, nil, "", "no " + what + " is recorded for " + first, rule
}

// cipherTable は、導入されている暗号ライブラリのパッケージ版に対応する、暗号スイートの対応表を返す。
func (c *Collector) cipherTable(library string) (t *ruleset.CipherTable, prov *model.Provenance, note, reason string, rule confidence.Rule) {
	key, prov, note, reason, rule := c.libraryTable(library, "cipher table", func(pkg, version string) (any, ruleset.CipherBuild, bool, bool) {
		tb, build, exact, ok := c.Rules.CipherTableFor(library, pkg, version)
		return tb, build, exact, ok
	})
	if key == nil {
		return nil, nil, "", reason, rule
	}
	return key.(*ruleset.CipherTable), prov, note, "", rule
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

// cipherResolver は、1 つのサービスの範囲に共通の、暗号スイートの解決に必要な情報（鍵交換のグループの groupResolver と対になる）。
type cipherResolver struct {
	c   *Collector
	app ruleset.AppRule
	svc model.Service

	// 暗号スイートの対応表（導入されている OpenSSL の版のもの）
	table   *ruleset.CipherTable
	libProv *model.Provenance // 対応表を実測した版
	libNote string            // 補った場合の注記
	noTable string            // 対応表がない理由
	libRule confidence.Rule   // 対応表の、確度の材料
	profile *string           // 「PROFILE=SYSTEM」が指す暗号文字列（RHEL 系）

	// アプリの既定値表（導入されているアプリの版のもの）
	defs       map[string][]string
	appProv    *model.Provenance
	appNote    string
	noDefaults string
	defRule    defaultsRule

	// システムの openssl.cnf の既定（RHEL 系では暗号ポリシーが生成した内容）
	sysCipher, sysTLS13 string
	sysUnread           string // 書かれているが値を読めていない項目（暗号スイートに関わるもの）
	// 範囲によらず効くセキュリティレベル（なければ負）と、それがどこから来たかを表す段
	sysLevel int
	sysStep  model.ResolutionStep
	appLevel bool // アプリが自分でセキュリティレベルを決める（システムの設定によるレベルは効かない）
}

// newCipherResolver は、サービスに共通の情報（対応表、アプリの既定値表、システムの設定）を集める。
func (c *Collector) newCipherResolver(app ruleset.AppRule, svc model.Service) *cipherResolver {
	cr := &cipherResolver{c: c, app: app, svc: svc, sysLevel: -1}
	cr.table, cr.libProv, cr.libNote, cr.noTable, cr.libRule = c.cipherTable("openssl")
	cr.defs, cr.appProv, cr.appNote, cr.noDefaults, cr.defRule = c.appDefaults(app)
	for _, s := range c.Builder.OSSettings() {
		switch s.ID {
		case model.OSSettingOpenSSLUnread:
			if s.Value == "CipherString" || s.Value == "Ciphersuites" {
				cr.sysUnread = s.Value
			}
		case "openssl.system_default.CipherString":
			cr.sysCipher = s.Value
		case "openssl.system_default.Ciphersuites":
			cr.sysTLS13 = s.Value
		}
	}
	if cr.table != nil {
		cr.profile = c.profileString(cr.table.ProfileSystem)
		if cr.sysCipher != "" {
			// システムの暗号文字列に含まれるレベルの指定は、アプリが別の暗号文字列を設定しても残る
			if x, err := tlsciphers.Expand(cr.table, cr.sysCipher, cr.profile); err == nil {
				cr.sysLevel = x.Level
			}
		}
	}
	if cr.sysLevel >= 0 {
		cr.sysStep = model.ResolutionStep{Layer: "os-policy", Op: "security-level"}
	}
	if v := strings.Join(cr.defs[paramAppLevel], ","); len(v) == 1 && v[0] >= '0' && v[0] <= '5' && cr.table != nil && cr.table.SecurityLevels {
		cr.sysLevel, cr.appLevel = int(v[0]-'0'), true
		cr.sysStep = model.ResolutionStep{Layer: "app-default", Op: "security-level", Source: cr.appProv}
	}
	return cr
}

// opensslServerEffective は、各範囲について、実際に使える暗号スイートと、受け入れる鍵交換のグループを求めて記録する。
//
// 求めるのは「許可されているスイート」まで。どのプロトコル（TLS 1.2、1.3 など）が有効かは、ここでは解決しない。
func (c *Collector) opensslServerEffective(app ruleset.AppRule, svc model.Service, scopes []tlsScope) {
	if len(scopes) == 0 {
		return
	}
	ciphers := c.newCipherResolver(app, svc)
	groups := c.newGroupResolver(app, svc, ciphers.appProv, ciphers.appNote, ciphers.defs, ciphers.defRule)
	groups.levelUnknown = ciphers.sysUnread == "CipherString"
	for _, sc := range scopes {
		// 適用されたセキュリティレベルは、鍵交換のグループの絞り込みにも使う
		level, levelStep := ciphers.resolve(sc)
		groups.resolve(sc, level, levelStep)
	}
}

// serverCertificates は、範囲のサーバーが持つ証明書の種類を返す。use は、アプリの既定値表の項目を使ったことの申告。
// 種類を判定できない場合は、RSA の証明書の場合と EC の証明書の場合を合わせた一覧を求めるための 2 種類を返し、anyKind を true にする
// （確度は下げない。DSA の分は入れない）。
func (cr *cipherResolver) serverCertificates(sc tlsScope, use func(item string)) (certs []tlseffective.Cert, anyKind bool) {
	known := false
	switch {
	case sc.autoRSA: // 設定に証明書の指定がなく、アプリが自分で用意した RSA の証明書を使う
		return []tlseffective.Cert{{Key: "RSA", Signature: "RSA"}}, false
	case sc.noCert: // 証明書を持たないサービス
		return nil, false
	case len(sc.certKinds) > 0: // 証明書のファイルを読まなくても、種類が分かっている
		for _, k := range sc.certKinds {
			sig := k
			if k == "EC" {
				sig = "ECDSA"
			}
			certs = append(certs, tlseffective.Cert{Key: k, Signature: sig})
		}
		return certs, false
	case sc.certsOK:
		paths := sc.certs
		if strings.Join(cr.defs[paramCertSel], ",") == "first" && len(paths) > 1 {
			paths = paths[:1] // この版は、同じ名前の証明書を複数指定しても最初の1つしか使わない
			use(paramCertSel)
		}
		certs, known = cr.c.certKinds(paths)
	}
	if known {
		return certs, false
	}
	return []tlseffective.Cert{{Key: "RSA", Signature: "RSA"}, {Key: "EC", Signature: "ECDSA"}}, true
}

// resolveTLS13 は、範囲 1 つの TLS 1.3 のスイートを記録する（暗号文字列とは別に決まる）。
// e13 は、範囲などを入れた土台。out は、暗号スイートの計算の結果。tls13Default は、TLS 1.3 のスイートを、アプリの既定が決めていること。
func (cr *cipherResolver) resolveTLS13(sc tlsScope, e13 model.EffectiveValue, out tlseffective.Output, levelStep model.ResolutionStep, tls13Default bool) {
	if len(cr.table.TLS13) == 0 {
		return
	}
	if sc.tls13Blocker != "" {
		e13.Status, e13.Reason = model.StatusUnresolved, sc.tls13Blocker
		cr.c.Builder.AddEffective(e13)
		return
	}
	switch out.TLS13Source {
	case "app":
		e13.Steps = []model.ResolutionStep{{Layer: "app-config", Op: "override", Setting: cr.c.settingAt(cr.svc, paramTLS13, sc.tls13File, sc.tls13Line)}}
		if tls13Default {
			e13.Steps = []model.ResolutionStep{{Layer: "app-default", Op: "default", Source: cr.appProv}}
		}
	case "system":
		e13.Steps = []model.ResolutionStep{{Layer: "os-policy", Op: "override"}}
	default:
		e13.Steps = []model.ResolutionStep{{Layer: "library", Op: "default", Source: cr.libProv}}
	}
	if levelStep.Layer != "" {
		e13.Steps = append(e13.Steps, levelStep)
	}
	e13.Values = out.TLS13
	e13.Notes = []string{"used only when TLS 1.3 is enabled"}
	if sc.tls13Off {
		e13.Values, e13.Notes = nil, []string{"TLS 1.3 is not enabled in the configuration"}
	}
	if sc.noCert {
		e13.Values, e13.Notes = nil, []string{"TLS 1.3 needs a certificate, and this service has none"}
	}
	// TLS 1.3 のスイートの計算に使ったルール: 暗号スイートの対応表と、アプリの既定が決めている場合は、その項目
	rules13 := []confidence.Rule{cr.libRule}
	for _, item := range sc.usedDefaults {
		if cr.defRule != nil && !groupOnlyItem(item) {
			rules13 = append(rules13, cr.defRule(item))
		}
	}
	if tls13Default && cr.defRule != nil {
		rules13 = append(rules13, cr.defRule(paramTLS13))
	}
	if cr.libNote != "" {
		e13.Notes = append(e13.Notes, cr.libNote)
	}
	if cr.appNote != "" && tls13Default {
		e13.Notes = append(e13.Notes, cr.appNote)
	}
	cr.c.Builder.AddEffective(e13, rules13...)
}

// resolve は、範囲 1 つについて、暗号スイート（TLS 1.2 以下と TLS 1.3）を求めて記録し、適用されたセキュリティレベルと、その段を返す。
func (cr *cipherResolver) resolve(sc tlsScope) (int, model.ResolutionStep) {
	e := model.EffectiveValue{Service: cr.svc.ID, Parameter: paramCiphers, Direction: cr.app.Direction, Scope: sc.name, Status: model.StatusResolved}
	e13 := e
	e13.Parameter = paramTLS13
	fail := func(reason string) {
		e.Status, e.Reason = model.StatusUnresolved, reason
		cr.c.Builder.AddEffective(e)
		if cr.table == nil || len(cr.table.TLS13) > 0 {
			e13.Status, e13.Reason = model.StatusUnresolved, reason
			cr.c.Builder.AddEffective(e13)
		}
	}
	if cr.table == nil {
		fail(cr.noTable)
		return cr.sysLevel, cr.sysStep
	}
	if sc.blocker != "" {
		fail(sc.blocker)
		return cr.sysLevel, cr.sysStep
	}
	if cr.sysUnread != "" {
		fail("the " + cr.sysUnread + " setting in the system OpenSSL configuration could not be read, so the system default and the security level are not known")
		return cr.sysLevel, cr.sysStep
	}
	in := tlseffective.Input{Table: cr.table, Profile: cr.profile, SystemLevel: cr.sysLevel}
	if cr.sysTLS13 != "" {
		in.SystemTLS13 = strings.Split(cr.sysTLS13, ":")
	}

	usedAppDefault := false // アプリの既定値表の値を使ったか（補った表なら、その旨の注記を付ける）
	// 確度の材料: この実効値の計算に使ったルール。暗号スイートの対応表は、暗号文字列の展開に必ず使う
	rules := []confidence.Rule{cr.libRule}
	use := func(item string) { // アプリの既定値表の項目を使った
		usedAppDefault = true
		if cr.defRule != nil {
			rules = append(rules, cr.defRule(item))
		}
	}
	for _, item := range sc.usedDefaults {
		if !groupOnlyItem(item) {
			use(item)
		}
	}

	// 1. 暗号文字列: 設定の記載、なければアプリの既定
	cipherParam := paramCiphers
	if sc.cipherParam != "" {
		cipherParam = sc.cipherParam
	}
	first := model.ResolutionStep{Layer: "app-config", Op: "override", Setting: cr.c.settingAt(cr.svc, cipherParam, sc.cipherFile, sc.cipherLine)}
	in.CipherString = sc.cipher
	if sc.cipher == "" {
		def := cr.defs[paramCiphers]
		if def == nil {
			reason := cr.noDefaults
			if cr.defs != nil {
				reason = "the default cipher string of this application version is not recorded"
			}
			fail(reason)
			return cr.sysLevel, cr.sysStep
		}
		in.CipherString = strings.Join(def, ",")
		first = model.ResolutionStep{Layer: "app-default", Op: "default", Source: cr.appProv}
		use(paramCiphers)
	}
	e.Steps = []model.ResolutionStep{first}
	levelFrom := first // 暗号文字列にセキュリティレベルの指定が含まれるとき、それがどの層のものか
	if in.CipherString == cipherSystemDefault {
		// アプリは何も設定しない。システムの openssl.cnf の暗号文字列があればそれ、なければライブラリの既定（DEFAULT）
		if cr.sysCipher != "" {
			in.CipherString = cr.sysCipher
			levelFrom = model.ResolutionStep{Layer: "os-policy", Op: "override"}
		} else {
			in.CipherString = "DEFAULT"
			levelFrom = model.ResolutionStep{Layer: "library", Op: "default", Source: cr.libProv}
		}
		e.Steps = append(e.Steps, levelFrom)
	}
	if cr.table.ProfileSystem != "" && strings.HasPrefix(in.CipherString, "PROFILE=SYSTEM") {
		e.Steps = append(e.Steps, model.ResolutionStep{Layer: "os-policy", Op: "profile"})
	}

	// 2. サーバーの持ち物: 証明書の種類と、DH パラメータ
	var notes []string
	var anyKind bool
	in.Certs, anyKind = cr.serverCertificates(sc, use)
	in.CertsKnown = true
	tls13Default := false // TLS 1.3 のスイートを、アプリの既定が決めている
	if sc.tls13 != "" {
		in.AppTLS13 = strings.Split(sc.tls13, ":")
	} else if def := cr.defs[paramTLS13]; len(def) > 0 {
		// アプリ自身が TLS 1.3 のスイートの既定を持つ（システムの openssl.cnf の指定より優先される）
		in.AppTLS13, tls13Default = strings.Split(strings.Join(def, ","), ":"), true
	}
	dheLayer := "app-config"
	var dheSource *model.Provenance
	switch v := strings.Join(cr.defs[paramDHE], ","); {
	case sc.dhParam:
		in.DHE, in.DHEKnown = true, true
	case v == "builtin":
		in.DHE, in.DHEKnown, dheLayer, dheSource = true, true, "app-default", cr.appProv
		use(paramDHE)
	case v == "disabled":
		in.DHE, in.DHEKnown, dheLayer, dheSource = false, true, "app-default", cr.appProv
		use(paramDHE)
	}

	out, err := tlseffective.Resolve(in)
	if err != nil {
		fail("the cipher string cannot be expanded: " + err.Error())
		return cr.sysLevel, cr.sysStep
	}
	e.Steps = append(e.Steps, model.ResolutionStep{Layer: "library", Op: "expand", Source: cr.libProv})
	levelStep := model.ResolutionStep{Op: "security-level"}
	switch out.LevelSource {
	case "cipher-string":
		levelStep.Layer, levelStep.Setting, levelStep.Source = levelFrom.Layer, levelFrom.Setting, levelFrom.Source
	case "system":
		levelStep.Layer = "os-policy"
		if cr.appLevel {
			levelStep.Layer, levelStep.Source = "app-default", cr.appProv
			use(paramAppLevel)
		}
	case "library-default":
		levelStep.Layer, levelStep.Source = "library", cr.libProv
	}
	if levelStep.Layer != "" {
		e.Steps = append(e.Steps, levelStep)
	}
	if in.CertsKnown && !anyKind {
		e.Steps = append(e.Steps, model.ResolutionStep{Layer: "app-config", Op: "filter-certificates"})
	}
	if in.DHEKnown {
		e.Steps = append(e.Steps, model.ResolutionStep{Layer: dheLayer, Op: "filter-dh-parameters", Source: dheSource})
	}
	if cr.libNote != "" {
		notes = append(notes, cr.libNote)
	}
	if cr.appNote != "" && usedAppDefault {
		notes = append(notes, cr.appNote)
	}
	dheUnknown := false
	for _, u := range out.Unfiltered {
		if u == "dh-parameters" {
			dheUnknown = true
		}
	}
	if anyKind {
		e.Qualifiers = append(e.Qualifiers, model.QualifierAnyCertificateKind)
		notes = append(notes, "the kind of the server certificate is not known (the certificate could not be read), so the suites usable with an RSA certificate and those usable with an EC certificate are listed together")
	}
	if len(out.Suites) == 0 {
		notes = append(notes, "no suite is usable with this configuration")
		e.Qualifiers = append(e.Qualifiers, model.QualifierNothingAccepted)
	}
	if sc.tls12Off {
		out.Suites, notes, e.Qualifiers = nil, []string{"TLS 1.2 and older are not enabled in the configuration"}, nil
	}
	e.Values, e.Notes = out.Suites, notes
	e.Notes = append(e.Notes, sc.info...)
	blocker := sc.tls12Blocker
	if blocker == "" && dheUnknown && !sc.tls12Off {
		// DH パラメータの指定がないときに DHE を使えるかは、起動して確かめないと分からない。その版のルールにこの項目がなければ、求めない
		blocker = "whether this application version can use DHE suites without DH parameters is not recorded (it is not measured for this version), and no DH parameters are configured"
	}
	if blocker != "" {
		e = model.EffectiveValue{Service: e.Service, Parameter: e.Parameter, Direction: e.Direction, Scope: e.Scope, Status: model.StatusUnresolved, Reason: blocker}
	}
	cr.c.Builder.AddEffective(e, rules...)

	cr.resolveTLS13(sc, e13, out, levelStep, tls13Default)
	return out.Level, levelStep
}
