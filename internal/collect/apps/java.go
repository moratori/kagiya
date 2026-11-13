package apps

import (
	"path"
	"regexp"
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
	seen := map[string]bool{}
	for _, pattern := range app.ConfigFiles {
		for _, sec := range c.globDeep(pattern) {
			// 同じ JDK を指す別名のディレクトリ（/usr/lib/jvm/jre-21 など）を重ねて数えない
			key := sec
			if real, err := c.Opener.Resolve(c.Prefix + sec); err == nil {
				key = real
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			home := strings.TrimSuffix(strings.TrimSuffix(sec, "/conf/security/java.security"), "/jre/lib/security/java.security")
			c.jdkHome(app, svc, home, sec)
		}
	}
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

func (c *Collector) jdkHome(app ruleset.AppRule, svc model.Service, home, sec string) {
	params := []string{model.ParamTLSProtocols, paramCiphers, paramTLS13, model.ParamTLSGroups}
	fail := func(reason string) {
		for _, p := range params {
			c.Builder.AddEffective(model.EffectiveValue{Service: svc.ID, Parameter: p, Direction: app.Direction, Scope: home,
				Status: model.StatusUnresolved, Reason: reason})
		}
	}

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
		fail(reason)
		return
	}

	r := jsse.Resolve(tb, jsse.Input{Disabled: disabled.Value, Properties: props})
	prov := &model.Provenance{Image: build.Source.Image, OS: build.Source.OS, Package: build.Package, Version: build.Version}
	steps := []model.ResolutionStep{{Layer: "library", Op: "default", Source: prov}, {Layer: layer, Op: "remove", Setting: settingID}}
	confidence := model.ConfidenceHigh
	notes := []string{"these are the defaults of this JDK, used unless the application chooses its own protocols, cipher suites or groups; " +
		"options given when Java is started (-D options, an extra security properties file) are not read"}
	switch {
	case other != "":
		confidence = model.ConfidenceMedium
		notes = append(notes, "the JDK table measured on "+build.Package+" "+build.Version+" is used for this JDK because its release file reports the same upstream Java version ("+
			other+"); the table comes from another distributor's build of that version")
	case !exact:
		confidence = model.ConfidenceMedium
		notes = append(notes, "the JDK table measured on "+build.Package+" "+build.Version+" is used for the installed "+pkg.Name+" "+
			pkg.FullVersion()+" (same upstream version and distribution, different release)")
	}
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
		c.Builder.AddEffective(model.EffectiveValue{Service: svc.ID, Parameter: model.ParamTLSGroups, Direction: app.Direction, Scope: home,
			Status: model.StatusUnresolved, Reason: r.GroupsBlocker})
		return
	}
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
	emit(model.ParamTLSGroups, groups, nil)
}
