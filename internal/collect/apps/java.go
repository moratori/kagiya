package apps

import (
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"kagiya/internal/jsse"
	"kagiya/internal/model"
	"kagiya/internal/parse/javasecurity"
	"kagiya/internal/ruleset"
)

// このファイルは、導入されている JDK（OpenJDK）の TLS の既定の読み取り。
//
// Java の TLS（JSSE）の決まり方（検証ラボで、8 つのディストリの OpenJDK 8 / 11 / 17 / 21 / 25 で確かめたもの）:
//
//   - OpenSSL は使わない。JDK が対応しているプロトコル、スイート、グループから、セキュリティの設定
//     （java.security の jdk.tls.disabledAlgorithms）で無効にされたものを除いたものが、既定で受け入れるものになる。
//   - RHEL 系では、暗号ポリシーのファイル（/etc/crypto-policies/back-ends/java.config）の値が、java.security の値を置き換える。
//     つなぎ方は 2 通り: security.useSystemPropertiesFile=true（8 / 11 / 17 / 21）と、java.security の include（25）。
//   - java.security は、JDK ごとのディレクトリ（/usr/lib/jvm/<名前>/）の conf/security（Java 8 は jre/lib/security）にある。
//
// ここで求めるのは「アプリが何も指定しない場合」の値。アプリの設定（Tomcat の server.xml など）や起動時の指定
// （-D で始まるオプション、-Djava.security.properties で足される設定ファイル）は読まない。

const (
	jdkRuntime       = "openjdk"
	jdkPolicyPath    = "/etc/crypto-policies/back-ends/java.config"
	jdkFIPSPath      = "/proc/sys/crypto/fips_enabled"
	paramJDKDisabled = "tls.disabled-algorithms"
	jdkPropDisabled  = "jdk.tls.disabledAlgorithms"
	jdkPropSwitch    = "security.useSystemPropertiesFile"
	jdkMaxValue      = 16384
)

// 解釈の対象にする値の形（名前、条件の記号、区切り）。
var jdkValue = regexp.MustCompile(`^[A-Za-z0-9_.,*<>=!&:/ \t-]*$`)

func (c *Collector) jdk(app ruleset.AppRule, svc model.Service) {
	for _, sec := range c.jdkSecurityFiles(app) {
		home := strings.TrimSuffix(strings.TrimSuffix(sec, "/conf/security/java.security"), "/jre/lib/security/java.security")
		c.jdkHome(app, svc, home, sec)
	}
}

// jdkSecurityFiles は、導入されている JDK の java.security を返す（同じ JDK を指す別名のディレクトリは重ねて数えない）。
func (c *Collector) jdkSecurityFiles(app ruleset.AppRule) []string {
	var out []string
	seen := map[string]bool{}
	for _, pattern := range app.ConfigFiles {
		for _, sec := range c.globDeep(pattern) {
			key := sec
			if real, err := c.Opener.Resolve(c.Prefix + sec); err == nil {
				key = real
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, sec)
		}
	}
	return out
}

// jdkHomes は、導入されている JDK のディレクトリを返す。
func (c *Collector) jdkHomes() []string {
	var out []string
	for _, a := range c.Rules.Apps {
		if a.Grammar != "jdk" {
			continue
		}
		for _, sec := range c.jdkSecurityFiles(a) {
			out = append(out, strings.TrimSuffix(strings.TrimSuffix(sec, "/conf/security/java.security"), "/jre/lib/security/java.security"))
		}
	}
	sort.Strings(out)
	return out
}

// jdkPackage は、JDK のディレクトリに対応するパッケージを探す。
// ディレクトリ名は、RHEL 系ではパッケージ名から -headless を除いたもの（版とアーキテクチャが続くことがある）、
// Debian 系では java-<版>-openjdk-<アーキテクチャ>（パッケージは openjdk-<版>-jre-headless）。
func (c *Collector) jdkPackage(app ruleset.AppRule, home string) (pkg model.Package, reason string) {
	base := path.Base(home)
	var found, exact []model.Package
	for _, p := range c.Builder.Packages() {
		if !ruleset.MatchName(app.Packages, p.Name) {
			continue
		}
		prefix := strings.TrimSuffix(p.Name, "-headless")
		if n, ok := strings.CutPrefix(strings.TrimSuffix(p.Name, "-jre-headless"), "openjdk-"); ok && strings.HasSuffix(p.Name, "-jre-headless") {
			prefix = "java-" + n + "-openjdk"
		}
		if base != prefix && !strings.HasPrefix(base, prefix+"-") {
			continue
		}
		found = append(found, p)
		if strings.Contains(base, p.FullVersion()) {
			exact = append(exact, p)
		}
	}
	switch {
	case len(exact) == 1:
		return exact[0], ""
	case len(found) == 1:
		return found[0], ""
	case len(found) == 0:
		return model.Package{}, "no package information for the JDK in " + home + "; the JDK table to use is unknown"
	}
	return model.Package{}, "more than one package matches the JDK in " + home + "; which one it belongs to is not determined"
}

// jdkReleaseVersion は、JDK のディレクトリにある release ファイルから、開発元の版（JAVA_VERSION）を読む。
// 取り出すのはこの 1 項目だけで、版の形をしていない値は使わない。
func (c *Collector) jdkReleaseVersion(home string) string {
	data, err := c.read(home + "/release")
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "JAVA_VERSION="); ok {
			v = strings.Trim(strings.TrimSpace(v), "\"")
			if ruleset.ValidJavaVersion(v) {
				return v
			}
			return ""
		}
	}
	return ""
}

// JDK に含まれるセキュリティプロバイダの名前（java.security の security.provider.N に書かれる形）。
// 検証ラボで導入した 35 の JDK（OpenJDK 8 / 11 / 17 / 21 / 25。ディストリのパッケージ、Temurin、Corretto）の java.security に現れたもの。
var jdkOwnProviders = map[string]bool{
	"SUN": true, "SunRsaSign": true, "SunEC": true, "SunJSSE": true, "SunJCE": true, "SunJGSS": true, "SunSASL": true, "XMLDSig": true,
	"SunPCSC": true, "JdkLDAP": true, "JdkSASL": true, "SunPKCS11": true,
	// Java 8 はクラス名で書く
	"sun.security.provider.Sun": true, "sun.security.rsa.SunRsaSign": true, "sun.security.ec.SunEC": true, "com.sun.net.ssl.internal.ssl.Provider": true,
	"com.sun.crypto.provider.SunJCE": true, "sun.security.jgss.SunProvider": true, "com.sun.security.sasl.Provider": true,
	"org.jcp.xml.dsig.internal.dom.XMLDSigRI": true, "sun.security.smartcardio.SunPCSC": true,
}

var (
	jdkProviderKey  = regexp.MustCompile(`^security\.provider\.[0-9]{1,3}$`)
	jdkProviderName = regexp.MustCompile(`^[A-Za-z0-9_.$-]{1,128}$`)
)

// jdkForeignProvider は、java.security に、JDK に含まれないセキュリティプロバイダや、TLS の実装を差し替える設定がないかを調べる。
// あれば、その理由を返す（JDK の表は、JDK 自身の実装が TLS を担当する場合のもの）。
// FIPS モード用の一覧（fips.provider.N）は、FIPS モードのときだけ使われ、その場合は別に理由を付けるので、ここでは見ない。
func jdkForeignProvider(f *javasecurity.File) string {
	for _, name := range f.Names() {
		e, _ := f.Get(name)
		v := strings.TrimSpace(e.Value)
		switch {
		case jdkProviderKey.MatchString(name):
			fields := strings.Fields(v)
			if len(fields) == 0 {
				continue
			}
			if len(fields) > 1 || !jdkProviderName.MatchString(fields[0]) {
				if len(fields) > 1 && fields[0] == "SunPKCS11" {
					return "java.security registers SunPKCS11 with a configuration (" + name + "); cryptography may be delegated to another library, which has not been measured"
				}
				return "the value of " + name + " in java.security is not interpreted"
			}
			if !jdkOwnProviders[fields[0]] {
				return "java.security registers a security provider that is not part of the JDK (" + fields[0] + "); which implementation handles TLS has not been measured"
			}
		case name == "ssl.SocketFactory.provider" || name == "ssl.ServerSocketFactory.provider":
			if v != "" {
				return name + " is set in java.security; the TLS implementation is replaced, which has not been measured"
			}
		case name == "ssl.KeyManagerFactory.algorithm":
			if v != "" && v != "SunX509" && v != "NewSunX509" && v != "PKIX" {
				return name + " is set to a value that has not been measured"
			}
		}
	}
	return ""
}

// jdkContext は、ある JDK について、対応表と、無効にする方式の設定を読んだ結果。
type jdkContext struct {
	table      *ruleset.JDKTable
	input      jsse.Input // 無効にする方式の値と、include で取り込まれる値
	prov       *model.Provenance
	layer      string // 無効にする方式の記載がある層（app-config か os-policy）
	settingID  string // その記載を記録した設定値の ID
	confidence string
	notes      []string // 補間したことの注記
}

// jdkRead は、JDK のディレクトリ（home）と java.security（sec）から、対応表と設定を読む。根拠になる記載は、svc の設定値として記録する。
// 求められない場合は、reason に理由が入る。
func (c *Collector) jdkRead(app ruleset.AppRule, svc model.Service, home, sec string) (ctx jdkContext, reason string) {
	// 設定値。暗号ポリシーとのつなぎ方は表（その版で確かめたこと）に従うので、先に表を引く
	pkg, reason := c.jdkPackage(app, home)
	var tb *ruleset.JDKTable
	var build ruleset.CipherBuild
	exact := false
	if reason == "" {
		var ok bool
		if tb, build, exact, ok = c.Rules.JDKTableFor(jdkRuntime, pkg.Name, pkg.FullVersion()); !ok {
			reason = "no JDK table is recorded for " + pkg.Name + " " + pkg.FullVersion()
		}
	}
	// 表が見つからない場合（配布元の違う JDK、測っていないパッケージ）は、JDK のディレクトリにある release ファイルの
	// 開発元の版で引く。Java だけの扱いで、暗号ポリシーとのつなぎ方は引き継がれない（ruleset.JDKTableForJavaVersion）
	other := ""
	if reason != "" {
		if v := c.jdkReleaseVersion(home); v != "" {
			if t2, b2, ok := c.Rules.JDKTableForJavaVersion(jdkRuntime, v); ok {
				tb, build, exact, reason, other = t2, b2, false, "", v
			} else {
				reason += "; no JDK table is recorded for Java " + v + " either"
			}
		}
	}
	f := javasecurity.Load(sec, confFS{c}, map[string]string{"java.home": home, "__redhat_fips__": "false"})
	get := f.Get
	if reason == "" && len(f.Problems) > 0 {
		reason = "java.security is not fully read: " + f.Problems[0]
	}
	if reason == "" && f.Included && !tb.SecurityInclude {
		reason = "java.security uses include, which has not been measured on this JDK build"
	}
	if e, ok := f.Get(jdkPropSwitch); reason == "" && ok && strings.TrimSpace(e.Value) == "true" {
		if !tb.SystemPropertiesFile {
			reason = jdkPropSwitch + " is set, but its effect has not been measured on this JDK build"
		} else {
			// 暗号ポリシーのファイルの値が、java.security の値を置き換える
			policy := javasecurity.Load(jdkPolicyPath, confFS{c}, nil)
			if len(policy.Problems) > 0 || policy.Included {
				reason = "the crypto policy file for Java (java.config) cannot be read"
			}
			get = func(name string) (javasecurity.Entry, bool) {
				if e, ok := policy.Get(name); ok {
					return e, true
				}
				return f.Get(name)
			}
		}
	}

	// JDK に含まれないプロバイダが登録されていると、TLS をどの実装が担当するかが変わりうる
	if reason == "" {
		reason = jdkForeignProvider(f)
	}

	// 根拠になる記載を記録する（表がなくても、読めたものは残す）
	disabled, has := get(jdkPropDisabled)
	valid := has && len(disabled.Value) <= jdkMaxValue && jdkValue.MatchString(disabled.Value)
	layer, settingID := "app-config", ""
	if disabled.File == jdkPolicyPath {
		layer = "os-policy"
	}
	if valid {
		var items []string
		for _, it := range strings.Split(disabled.Value, ",") {
			if it = strings.Join(strings.Fields(it), " "); it != "" {
				items = append(items, it)
			}
		}
		c.Builder.AddSetting(model.Setting{Service: svc.ID, Parameter: paramJDKDisabled, Direction: app.Direction, Scope: home,
			Basis: "configured", Layer: layer, Source: "config-file", Effective: true, Values: items,
			Location: model.SettingLocation{Path: c.Prefix + disabled.File, Line: disabled.Line}})
		settingID = c.settingAt(svc, paramJDKDisabled, disabled.File, disabled.Line)
	}
	switch {
	case reason != "":
	case !has:
		reason = jdkPropDisabled + " is not set; the behaviour without it has not been measured"
	case !valid:
		reason = "the value of " + jdkPropDisabled + " is not interpreted"
	}
	// FIPS モードでは、JDK は別の暗号の実装に切り替わる（RHEL 系）。その状態は測っていない
	if data, err := c.read(jdkFIPSPath); reason == "" && err == nil && strings.TrimSpace(string(data)) == "1" {
		reason = "the host is in FIPS mode; the behaviour of the JDK in FIPS mode has not been measured"
	}
	// 「include 名前」で取り込まれる、ほかの設定値
	props := map[string]string{}
	if reason == "" {
		pending := []string{disabled.Value}
		for depth := 0; depth < 4 && len(pending) > 0; depth++ {
			var next []string
			for _, v := range pending {
				for _, it := range strings.Split(v, ",") {
					w := strings.Fields(it)
					if len(w) != 2 || w[0] != "include" {
						continue
					}
					if _, done := props[w[1]]; done {
						continue
					}
					e, ok := get(w[1])
					if !ok {
						continue // 解釈の側が、取り込み先がないことを理由にする
					}
					if len(e.Value) > jdkMaxValue || !jdkValue.MatchString(e.Value) {
						reason = "the value of " + w[1] + " is not interpreted"
						continue
					}
					props[w[1]] = e.Value
					next = append(next, e.Value)
				}
			}
			pending = next
		}
	}
	if reason != "" {
		return jdkContext{}, reason
	}
	ctx = jdkContext{table: tb, input: jsse.Input{Disabled: disabled.Value, Properties: props}, layer: layer, settingID: settingID, confidence: model.ConfidenceHigh,
		prov: &model.Provenance{Image: build.Source.Image, OS: build.Source.OS, Package: build.Package, Version: build.Version}}
	switch {
	case other != "":
		ctx.confidence = model.ConfidenceMedium
		ctx.notes = append(ctx.notes, "the JDK table measured on "+build.Package+" "+build.Version+" is used for this JDK because its release file reports the same upstream Java version ("+
			other+"); the table comes from another distributor's build of that version")
	case !exact:
		ctx.confidence = model.ConfidenceMedium
		ctx.notes = append(ctx.notes, interpolatedNote("JDK", build, pkg))
	}
	return ctx, ""
}

func (c *Collector) jdkHome(app ruleset.AppRule, svc model.Service, home, sec string) {
	params := []string{model.ParamTLSProtocols, paramCiphers, paramTLS13, model.ParamTLSGroups}
	ctx, reason := c.jdkRead(app, svc, home, sec)
	if reason != "" {
		c.unresolved(svc, app.Direction, home, reason, params...)
		return
	}
	tb := ctx.table
	r := jsse.Resolve(tb, ctx.input)
	steps := []model.ResolutionStep{{Layer: "library", Op: "default", Source: ctx.prov}, {Layer: ctx.layer, Op: "remove", Setting: ctx.settingID}}
	confidence := ctx.confidence
	notes := append([]string{"these are the defaults of this JDK, used unless the application chooses its own protocols, cipher suites or groups; " +
		"options given when Java is started (-D options, an extra security properties file) are not read"}, ctx.notes...)
	emit := func(param string, values, extra []string) {
		c.Builder.AddEffective(model.EffectiveValue{Service: svc.ID, Parameter: param, Direction: app.Direction, Scope: home,
			Status: model.StatusResolved, Values: values, Confidence: confidence, Steps: steps,
			Notes: append(append([]string{}, notes...), extra...)})
	}
	emit(model.ParamTLSProtocols, r.Protocols, nil)
	var tls12, tls13, dheNote []string
	for _, s := range r.Suites {
		switch {
		case s == "TLS_EMPTY_RENEGOTIATION_INFO_SCSV": // 再ネゴシエーションの印で、暗号スイートではない
		case strings.Contains(s, "_WITH_"):
			tls12 = append(tls12, s)
			if strings.Contains(s, "_DHE_") && tb.DHEDefaultBits < 2048 && dheNote == nil {
				dheNote = []string{"the DHE suites use " + strconv.Itoa(tb.DHEDefaultBits) + "-bit parameters when the client does not offer finite-field groups (measured on this JDK build)"}
			}
		default:
			tls13 = append(tls13, s)
		}
	}
	emit(paramCiphers, tls12, dheNote)
	emit(paramTLS13, tls13, nil)
	if r.GroupsBlocker != "" {
		c.unresolved(svc, app.Direction, home, r.GroupsBlocker, model.ParamTLSGroups)
		return
	}
	emit(model.ParamTLSGroups, jsseGroups(r), nil)
}

// unresolved は、指定した項目を「求められない」として、理由とともに記録する。
func (c *Collector) unresolved(svc model.Service, direction, scope, reason string, params ...string) {
	for _, p := range params {
		c.Builder.AddEffective(model.EffectiveValue{Service: svc.ID, Parameter: p, Direction: direction, Scope: scope,
			Status: model.StatusUnresolved, Reason: reason})
	}
}

// jsseGroups は、受け入れる鍵交換のグループを 1 つの一覧にする（TLS 1.3 のもの、続いて TLS 1.2 以下だけのもの）。
func jsseGroups(r jsse.Result) []string {
	groups := append([]string{}, r.Groups13...)
	in := map[string]bool{}
	for _, g := range groups {
		in[g] = true
	}
	for _, g := range r.Groups12 {
		if !in[g] {
			groups = append(groups, g)
		}
	}
	return groups
}

// interpolatedNote は、リリースだけが違うパッケージ版の表で補ったことの注記。
func interpolatedNote(what string, build ruleset.CipherBuild, pkg model.Package) string {
	return "the " + what + " table measured on " + build.Package + " " + build.Version + " is used for the installed " + pkg.Name + " " +
		pkg.FullVersion() + " (same upstream version and distribution, different release)"
}
