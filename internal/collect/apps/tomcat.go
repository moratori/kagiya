package apps

import (
	"path"
	"regexp"
	"strconv"
	"strings"

	"kagiya/internal/jsse"
	"kagiya/internal/model"
	"kagiya/internal/parse/serverxml"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
	"kagiya/internal/tomcatciphers"
)

// このファイルは、Tomcat の設定（server.xml）の読み取りと、受け入れるプロトコル・暗号スイートの解決。
//
// Tomcat の TLS の決まり方（検証ラボで、8 つの環境の Tomcat 9 / 10.1 / 11 を実際に起動して確かめたもの）:
//
//   - TLS の実装は 2 通り。JDK の実装（JSSE）と、OpenSSL の実装（Tomcat Native というライブラリを通す）。
//     実装を明示（sslImplementationName）していなければ、AprLifecycleListener があり、かつ Tomcat Native を読み込めたときに
//     OpenSSL の実装になる。Tomcat Native は、Tomcat の版が求める版より古いと読み込まれない。
//   - JDK の実装では、server.xml の ciphers（OpenSSL の書き方）を Tomcat が自分の表で解釈し、そのうち JDK が対応していて、
//     JDK の設定（jdk.tls.disabledAlgorithms）で無効にされていないものを受け入れる。protocols も同じ。
//   - TLS 1.3 のスイートを別の属性で持つ版では、ciphers に何を書いても TLS 1.3 のスイートは変わらない。
//
// ここで求めるのは、JDK の実装で動く場合。OpenSSL の実装で動く場合は、まだ求めない（理由を残す）。
//
// 読まないもの: setenv.sh（スクリプト）、systemd のドロップインで足された環境変数、パッケージ以外の方法で置かれた Tomcat Native。
// setenv.sh がある場合や、環境ファイルに Java の暗号の設定を変えるオプションがある場合は、値を求めない。

const (
	tomcatServer       = "tomcat"
	tomcatAPRListener  = "org.apache.catalina.core.AprLifecycleListener"
	tomcatFFMListener  = "org.apache.catalina.core.OpenSSLLifecycleListener"
	tomcatJSSEImpl     = "org.apache.tomcat.util.net.jsse.JSSEImplementation"
	tomcatOpenSSLImpl  = "org.apache.tomcat.util.net.openssl.OpenSSLImplementation"
	tomcatAPRProtocol  = "org.apache.coyote.http11.Http11AprProtocol"
	tomcatMaxCiphers   = 8192
	tomcatDebJavaHome  = "/usr/lib/jvm/default-java"
	tomcatRPMConf      = "/etc/tomcat/tomcat.conf"
	tomcatRPMSysconfig = "/etc/sysconfig/tomcat"
)

var (
	tomcatCiphersValue   = regexp.MustCompile(`^[A-Za-z0-9_.:!+@=, -]+$`)
	tomcatProtocolsValue = regexp.MustCompile(`^[A-Za-z0-9.+, -]+$`)
	tomcatPort           = regexp.MustCompile(`^[0-9]{1,5}$`)
	tomcatHostName       = regexp.MustCompile(`^[A-Za-z0-9*._-]{1,253}$`)
	tomcatNativeVersion  = regexp.MustCompile(`^(?:[0-9]+:)?([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})(?:[^0-9].*)?$`)
	tomcatEnvLine        = regexp.MustCompile(`^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)
	// Java の起動時の指定のうち、TLS の実装や設定を変えうるもの
	tomcatRiskyOptions = []string{"-Djava.security", "-Djdk.tls", "-Djdk.security", "-Djavax.net", "-Dhttps.", "-Djava.library.path", "-Djava.ext.dirs",
		"-Xbootclasspath", "-javaagent", "-agentpath", "-agentlib", "--patch-module", "--module-path", "-Dorg.apache.tomcat.util.net", "-Dcom.sun.net.ssl"}
	tomcatNativePackages = []string{"libtcnative-1", "libtcnative-2", "tomcat-native"}
	tomcatOptionVars     = map[string]bool{"JAVA_OPTS": true, "CATALINA_OPTS": true, "JDK_JAVA_OPTIONS": true, "JAVA_TOOL_OPTIONS": true, "LD_LIBRARY_PATH": true}
)

// tomcatHost は、TLS の設定 1 組（SSLHostConfig。古い書き方では Connector 自身）。
type tomcatHost struct {
	scope string
	attr  func(name string) (serverxml.Attr, bool)
	certs []serverxml.Certificate
	// 古い書き方での、キーストアの記載（Connector の属性）
	legacy bool
}

func (c *Collector) tomcat(app ruleset.AppRule, svc model.Service, config string) {
	if config == "" {
		return
	}
	data, err := c.read(config)
	if err != nil {
		return
	}
	f, err := serverxml.Parse(data)
	if err != nil {
		c.Builder.Skip(safefs.Skip{Path: c.Prefix + config, Reason: "invalid-value", Detail: "server.xml"})
		return
	}
	// 環境全体に関わること（どれかが分からなければ、どの Connector の値も求めない）
	common := ""
	if len(f.Problems) > 0 {
		common = "server.xml is not fully read: " + f.Problems[0]
	}
	var pkg model.Package
	n := 0
	for _, p := range c.Builder.Packages() {
		if ruleset.MatchName(app.Packages, p.Name) {
			pkg = p
			n++
		}
	}
	var tb *ruleset.TomcatTable
	var build ruleset.CipherBuild
	exact := false
	switch {
	case common != "":
	case n == 0:
		common = "no package information for Tomcat; the Tomcat table to use is unknown"
	case n > 1:
		common = "more than one Tomcat package is installed; which one this server.xml belongs to is not determined"
	default:
		var ok bool
		if tb, build, exact, ok = c.Rules.TomcatTableFor(tomcatServer, pkg.Name, pkg.FullVersion()); !ok {
			common = "no Tomcat table is recorded for " + pkg.Name + " " + pkg.FullVersion()
		}
	}
	// 配置。Debian 系は /etc/<名前>/server.xml で、CATALINA_BASE は /var/lib/<名前>。RHEL 系はどちらも /usr/share/tomcat
	name := path.Base(path.Dir(config))
	home, base := "/usr/share/"+name, "/var/lib/"+name
	envFiles := []string{"/etc/default/" + name}
	javaHome := tomcatDebJavaHome
	if pkg.Manager == "rpm" {
		base = home
		envFiles = []string{tomcatRPMConf, tomcatRPMSysconfig}
		javaHome = ""
	}
	if common == "" {
		javaHome, common = c.tomcatEnvironment(envFiles, []string{base + "/bin/setenv.sh", home + "/bin/setenv.sh"}, javaHome)
	}
	// どの JDK で動くか
	var ctx jdkContext
	jdkDir := ""
	if common == "" {
		ctx, jdkDir, common = c.tomcatJDK(svc, javaHome)
	}
	native := tomcatNativeState{}
	if common == "" {
		native = c.tomcatNative(tb)
	}
	apr, sslOff := false, false
	for _, l := range f.Listeners {
		switch l.ClassName {
		case tomcatAPRListener:
			apr = true
			if v, ok := l.Attr["SSLEngine"]; ok && strings.EqualFold(strings.TrimSpace(v.Value), "off") {
				sslOff = true
			}
		case tomcatFFMListener:
			if common == "" {
				common = "server.xml has an OpenSSLLifecycleListener (OpenSSL through the Java foreign function interface), which has not been measured"
			}
		}
	}

	for _, conn := range f.Connectors {
		if v, ok := conn.Attr["SSLEnabled"]; !ok || !strings.EqualFold(strings.TrimSpace(v.Value), "true") {
			continue
		}
		scope := "connector at line " + strconv.Itoa(conn.Line)
		if p, ok := conn.Attr["port"]; ok && tomcatPort.MatchString(p.Value) {
			scope = "connector " + p.Value
		}
		conn := conn
		hosts := []tomcatHost{}
		if len(conn.Hosts) == 0 {
			// 古い書き方: TLS の設定を Connector に直接書く
			hosts = append(hosts, tomcatHost{scope: scope, legacy: true, attr: func(name string) (serverxml.Attr, bool) {
				switch name {
				case "protocols":
					name = "sslEnabledProtocols"
				case "certificateKeystoreFile":
					name = "keystoreFile"
				case "ciphers":
				default:
					return serverxml.Attr{}, false
				}
				a, ok := conn.Attr[name]
				return a, ok
			}})
		}
		for i := range conn.Hosts {
			h := conn.Hosts[i]
			s := scope
			if len(conn.Hosts) > 1 {
				hn := "_default_"
				if v, ok := h.Attr["hostName"]; ok && tomcatHostName.MatchString(v.Value) {
					hn = v.Value
				}
				s += " host " + hn
			}
			hosts = append(hosts, tomcatHost{scope: s, certs: h.Certificates, attr: func(name string) (serverxml.Attr, bool) { a, ok := h.Attr[name]; return a, ok }})
		}
		// どの実装で動くか
		reason, why := common, ""
		if reason == "" {
			why, reason = tomcatImplementation(conn, apr, sslOff, native)
		}
		for _, h := range hosts {
			c.tomcatHost(app, svc, config, base, h, tb, build, exact, pkg, ctx, jdkDir, why, reason)
		}
	}
}

// tomcatImplementation は、その Connector が JDK の実装で動くと言えるかを決める。言えるなら why に根拠、言えないなら reason に理由が入る。
func tomcatImplementation(conn serverxml.Connector, apr, sslOff bool, native tomcatNativeState) (why, reason string) {
	switch p := strings.TrimSpace(conn.Attr["protocol"].Value); p {
	case "", "HTTP/1.1", "org.apache.coyote.http11.Http11NioProtocol", "org.apache.coyote.http11.Http11Nio2Protocol":
	case tomcatAPRProtocol:
		return "", "the Connector uses the APR protocol handler (OpenSSL through Tomcat Native); the values for that implementation are not resolved yet"
	default:
		return "", "the protocol attribute of the Connector names a handler that has not been measured"
	}
	switch impl := strings.TrimSpace(conn.Attr["sslImplementationName"].Value); impl {
	case tomcatJSSEImpl:
		return "sslImplementationName selects the JDK's TLS implementation (JSSE)", ""
	case tomcatOpenSSLImpl:
		return "", "sslImplementationName selects the OpenSSL implementation (Tomcat Native); the values for that implementation are not resolved yet"
	case "":
	default:
		return "", "sslImplementationName names an implementation that has not been measured"
	}
	switch {
	case !apr:
		return "server.xml has no AprLifecycleListener, so the JDK's TLS implementation (JSSE) is used", ""
	case native.reason != "":
		return "", native.reason
	case !native.installed:
		return "no Tomcat Native package is installed, so the JDK's TLS implementation (JSSE) is used", ""
	case !native.loadable:
		return "the installed Tomcat Native (" + native.pkg + ") is older than this Tomcat version requires and is not loaded, so the JDK's TLS implementation (JSSE) is used", ""
	case sslOff:
		return "", "the AprLifecycleListener has SSLEngine=\"off\" while Tomcat Native (" + native.pkg + ") can be loaded; the behaviour differs between Tomcat versions and has not been resolved"
	}
	return "", "Tomcat runs with the OpenSSL implementation here (Tomcat Native " + native.pkg + " is loaded through the AprLifecycleListener); the values for that implementation are not resolved yet"
}

type tomcatNativeState struct {
	installed bool
	loadable  bool   // Tomcat の求める版以上で、読み込まれる
	pkg       string // 「名前 版」
	reason    string // 空でなければ、判断できない理由
}

// tomcatNative は、導入されている Tomcat Native が、この Tomcat に読み込まれるかを調べる（パッケージの版と、表の求める版を比べる）。
func (c *Collector) tomcatNative(tb *ruleset.TomcatTable) tomcatNativeState {
	var st tomcatNativeState
	for _, p := range c.Builder.Packages() {
		if !ruleset.MatchName(tomcatNativePackages, p.Name) {
			continue
		}
		if st.installed {
			return tomcatNativeState{reason: "more than one Tomcat Native package is installed; which one is loaded is not determined"}
		}
		st.installed, st.pkg = true, p.Name+" "+p.FullVersion()
		m := tomcatNativeVersion.FindStringSubmatch(p.Version)
		if m == nil {
			return tomcatNativeState{reason: "the version of the installed Tomcat Native (" + st.pkg + ") cannot be read"}
		}
		have := [3]int{}
		for i := range have {
			have[i], _ = strconv.Atoi(m[i+1])
		}
		found := false
		for _, r := range tb.NativeRequired {
			need := [3]int{}
			parts := strings.Split(r, ".")
			for i := range need {
				need[i], _ = strconv.Atoi(parts[i])
			}
			if need[0] != have[0] {
				continue
			}
			found = true
			st.loadable = have[1] > need[1] || (have[1] == need[1] && have[2] >= need[2])
		}
		if !found {
			return tomcatNativeState{reason: "the installed Tomcat Native (" + st.pkg + ") belongs to a series that has not been measured with this Tomcat version"}
		}
	}
	return st
}

// tomcatEnvironment は、起動時に読まれる環境ファイルから、JAVA_HOME と、Java の起動時の指定を調べる。
// 読むのは「名前=値」の行だけ。値を確定できない場合や、TLS の設定を変えうる指定がある場合は、reason に理由が入る。
func (c *Collector) tomcatEnvironment(files, scripts []string, javaHome string) (home, reason string) {
	for _, s := range scripts {
		if _, err := c.read(s); err == nil {
			return "", s + " exists (setenv.sh is a script and is not interpreted); it can change the JDK and the options Java is started with"
		}
	}
	for _, file := range files {
		data, err := c.read(file)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(data), "\n") {
			l = strings.TrimSpace(l)
			m := tomcatEnvLine.FindStringSubmatch(l)
			if m == nil {
				continue // コメント、空行、ほかの形の行
			}
			key, value := m[1], strings.TrimSpace(m[2])
			if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
				value = value[1 : len(value)-1]
			}
			switch {
			case key == "JAVA_HOME" || key == "JRE_HOME":
				if strings.ContainsAny(value, "$`\\\"' \t") || !strings.HasPrefix(value, "/") || len(value) > 1024 {
					return "", key + " in " + file + " is not a plain path; the JDK that runs Tomcat is not determined"
				}
				javaHome = value
			case tomcatOptionVars[key]:
				for _, o := range tomcatRiskyOptions {
					if strings.Contains(value, o) {
						return "", key + " in " + file + " has an option (" + o + "...) that can change the TLS settings of Java; its effect is not interpreted"
					}
				}
				if key == "LD_LIBRARY_PATH" {
					return "", key + " in " + file + " changes where libraries (Tomcat Native) are loaded from"
				}
			}
		}
	}
	if javaHome == "" {
		return "", "JAVA_HOME is not set in " + strings.Join(files, " or ") + "; the JDK that runs Tomcat is not determined"
	}
	return javaHome, ""
}

// tomcatJDK は、JAVA_HOME の指す JDK を探し、その対応表と設定を読む。
func (c *Collector) tomcatJDK(svc model.Service, javaHome string) (ctx jdkContext, dir, reason string) {
	var jdkApp ruleset.AppRule
	found := false
	for _, a := range c.Rules.Apps {
		if a.Grammar == "jdk" {
			jdkApp, found = a, true
		}
	}
	if !found {
		return ctx, "", "no rule for the JDK is loaded"
	}
	real, err := c.Opener.Resolve(c.Prefix + javaHome)
	if err != nil {
		return ctx, "", "JAVA_HOME (" + javaHome + ") cannot be followed to a JDK; the JDK that runs Tomcat is not determined"
	}
	real = strings.TrimPrefix(real, c.Prefix)
	// Java 9 以降は conf/security。Java 8 は jre/lib/security（JAVA_HOME が jre を指していれば lib/security）
	for _, cand := range [][2]string{{real, "/conf/security/java.security"}, {real, "/jre/lib/security/java.security"}, {path.Dir(real), "/jre/lib/security/java.security"}} {
		if cand[0] != real && path.Base(real) != "jre" {
			continue
		}
		if _, err := c.read(cand[0] + cand[1]); err != nil {
			continue
		}
		jdkApp.Direction = "inbound"
		ctx, reason = c.jdkRead(jdkApp, svc, cand[0], cand[0]+cand[1])
		if reason != "" {
			reason = "the JDK that runs Tomcat (" + cand[0] + "): " + reason
		}
		return ctx, cand[0], reason
	}
	return ctx, "", "no java.security is found under JAVA_HOME (" + javaHome + "); the JDK that runs Tomcat is not determined"
}

// tomcatProtocols は、protocols の値を Tomcat と同じ読み方で解釈する（「+」「-」「,」で区切り、「-」は外す。all は表の一覧）。
func tomcatProtocols(tb *ruleset.TomcatTable, value string) []string {
	var out []string
	apply := func(op byte, name string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		names := []string{name}
		if strings.EqualFold(name, "all") {
			names = tb.ProtocolsAll
		}
		for _, n := range names {
			i := -1
			for j, x := range out {
				if x == n {
					i = j
				}
			}
			switch {
			case op == '-' && i >= 0:
				out = append(out[:i:i], out[i+1:]...)
			case op != '-' && i < 0:
				out = append(out, n)
			}
		}
	}
	op, start := byte('+'), 0
	for i := 0; i <= len(value); i++ {
		if i == len(value) || value[i] == '+' || value[i] == '-' || value[i] == ',' {
			apply(op, value[start:i])
			if i < len(value) {
				op, start = value[i], i+1
			}
		}
	}
	return out
}

// tomcatSuiteAuth は、TLS 1.2 以下のスイートの名前から、サーバーの証明書に求める鍵の種類を返す（決められなければ空）。
func tomcatSuiteAuth(suite string) string {
	kx, _, ok := strings.Cut(suite, "_WITH_")
	if !ok {
		return ""
	}
	kx = strings.TrimPrefix(strings.TrimPrefix(kx, "TLS_"), "SSL_")
	switch {
	case strings.HasSuffix(kx, "ECDSA"):
		return "EC"
	case strings.HasSuffix(kx, "DSS") || strings.HasPrefix(kx, "DHE_DSS") || strings.HasPrefix(kx, "DH_DSS"):
		return "DSA"
	case strings.HasPrefix(kx, "RSA") || strings.HasSuffix(kx, "_RSA") || strings.Contains(kx, "_RSA_"):
		return "RSA"
	}
	return ""
}

func (c *Collector) tomcatHost(app ruleset.AppRule, svc model.Service, config, base string, h tomcatHost, tb *ruleset.TomcatTable, build ruleset.CipherBuild,
	exact bool, pkg model.Package, ctx jdkContext, jdkDir, why, reason string) {
	// 設定の記載を記録する
	rec := func(directive, value string, line int) {
		if rule, ok := app.Directive(directive); ok {
			c.record(app, svc, rule, value, config, line, h.scope, base)
		}
	}
	ciphers, hasCiphers := h.attr("ciphers")
	protocols, hasProtocols := h.attr("protocols")
	if hasCiphers && len(ciphers.Value) <= tomcatMaxCiphers && tomcatCiphersValue.MatchString(ciphers.Value) {
		rec("ciphers", strings.Join(strings.FieldsFunc(ciphers.Value, func(r rune) bool { return r == ':' || r == ',' || r == ' ' }), ":"), ciphers.Line)
	} else if hasCiphers && reason == "" {
		reason = "the value of ciphers is not interpreted"
	}
	var wantProtocols []string
	if tb != nil {
		wantProtocols = tb.ProtocolsAll
	}
	if hasProtocols && len(protocols.Value) <= 1024 && tomcatProtocolsValue.MatchString(protocols.Value) {
		if tb != nil {
			wantProtocols = tomcatProtocols(tb, protocols.Value)
			if len(wantProtocols) > 0 {
				rec("protocols", strings.Join(wantProtocols, " "), protocols.Line)
			}
		}
	} else if hasProtocols && reason == "" {
		reason = "the value of protocols is not interpreted"
	}
	if ks, ok := h.attr("certificateKeystoreFile"); ok && h.legacy {
		rec("certificateKeystoreFile", ks.Value, ks.Line)
	}
	kinds, kindsKnown := map[string]bool{}, len(h.certs) > 0
	for _, cert := range h.certs {
		for _, d := range []string{"certificateFile", "certificateKeyFile", "certificateChainFile", "certificateKeystoreFile"} {
			if a, ok := cert.Attr[d]; ok {
				rec(d, a.Value, a.Line)
			}
		}
		kind := ""
		switch t := strings.ToUpper(strings.TrimSpace(cert.Attr["type"].Value)); t {
		case "RSA", "EC", "DSA":
			kind = t
		case "", "UNDEFINED":
			// 種類の指定がなければ、証明書のファイルから読む（キーストアの中身は読まない）
			if a, ok := cert.Attr["certificateFile"]; ok && !strings.ContainsAny(a.Value, "$%") {
				p := a.Value
				if !strings.HasPrefix(p, "/") {
					p = base + "/" + p
				}
				if ks, ok := c.certKinds([]string{p}); ok && len(ks) == 1 && ks[0].Key != "other" {
					kind = ks[0].Key
				}
			}
		}
		if kind == "" {
			kindsKnown = false
			continue
		}
		kinds[kind] = true
	}
	cipherSuites, hasCipherSuites := h.attr("cipherSuites")
	groups, hasGroups := h.attr("groups")
	if hasGroups {
		rec("groups", strings.ReplaceAll(strings.ReplaceAll(groups.Value, " ", ""), ",", ":"), groups.Line)
	}

	params := []string{model.ParamTLSProtocols, paramCiphers, paramTLS13, model.ParamTLSGroups}
	if reason != "" {
		for _, p := range params {
			c.Builder.AddEffective(model.EffectiveValue{Service: svc.ID, Parameter: p, Direction: app.Direction, Scope: h.scope,
				Status: model.StatusUnresolved, Reason: reason})
		}
		return
	}

	// Tomcat の解釈: 暗号指定 → スイートの名前。プロトコルは、SSLv2Hello（接続の始め方の形式で、プロトコルの版ではない）を除く
	spec := tb.DefaultCiphers
	tomcatProv := &model.Provenance{Image: build.Source.Image, OS: build.Source.OS, Package: build.Package, Version: build.Version}
	first := model.ResolutionStep{Layer: "app-default", Op: "default", Source: tomcatProv}
	if hasCiphers {
		spec = ciphers.Value
		first = model.ResolutionStep{Layer: "app-config", Op: "override", Setting: c.settingAt(svc, paramCiphers, config, ciphers.Line)}
	}
	names := tomcatciphers.Expand(tb, spec)
	tls13Reason := ""
	if tb.CipherSuitesAttribute {
		// TLS 1.3 のスイートは別の属性で決まり、ciphers の内容は関係しない（実測）
		only12 := names[:0:0]
		for _, n := range names {
			if strings.Contains(n, "_WITH_") {
				only12 = append(only12, n)
			}
		}
		names = append(only12, tb.DefaultCipherSuites...)
		if hasCipherSuites {
			_ = cipherSuites
			tls13Reason = "the cipherSuites attribute is set; its effect has not been measured yet"
		}
	}
	var protos []string
	for _, p := range wantProtocols {
		if p != "SSLv2Hello" {
			protos = append(protos, p)
		}
	}
	r := jsse.ResolveExplicit(ctx.table, ctx.input, protos, names)

	confidence := ctx.confidence
	notes := []string{"Tomcat runs on the JDK's TLS implementation (JSSE) with the JDK in " + jdkDir + ": " + why,
		"Tomcat's own cipher table decides what the ciphers value means; of those, the suites that this JDK supports and has not disabled are accepted",
		"not read: setenv.sh, environment added by systemd drop-ins, and a Tomcat Native library installed without a package"}
	notes = append(notes, ctx.notes...)
	if !exact {
		confidence = model.ConfidenceMedium
		notes = append(notes, "the Tomcat table measured on "+build.Package+" "+build.Version+" is used for the installed "+pkg.Name+" "+
			pkg.FullVersion()+" (same upstream version and distribution, different release)")
	}
	steps := []model.ResolutionStep{first, {Layer: "library", Op: "intersect", Source: ctx.prov}, {Layer: ctx.layer, Op: "remove", Setting: ctx.settingID}}
	emit := func(param string, values []string, conf string, st []model.ResolutionStep, extra ...string) {
		if values == nil {
			values = []string{}
		}
		c.Builder.AddEffective(model.EffectiveValue{Service: svc.ID, Parameter: param, Direction: app.Direction, Scope: h.scope,
			Status: model.StatusResolved, Values: values, Confidence: conf, Steps: st, Notes: append(append([]string{}, notes...), extra...)})
	}
	unresolved := func(param, reason string) {
		c.Builder.AddEffective(model.EffectiveValue{Service: svc.ID, Parameter: param, Direction: app.Direction, Scope: h.scope,
			Status: model.StatusUnresolved, Reason: reason})
	}
	protoFirst := model.ResolutionStep{Layer: "app-default", Op: "default", Source: tomcatProv}
	if hasProtocols {
		protoFirst = model.ResolutionStep{Layer: "app-config", Op: "override", Setting: c.settingAt(svc, model.ParamTLSProtocols, config, protocols.Line)}
	}
	emit(model.ParamTLSProtocols, r.Protocols, confidence, []model.ResolutionStep{protoFirst, steps[1], steps[2]})

	var tls12, tls13 []string
	for _, s := range r.Suites {
		if !strings.Contains(s, "_WITH_") {
			tls13 = append(tls13, s)
			continue
		}
		// サーバーの証明書の種類で成り立たないスイートは除く
		if a := tomcatSuiteAuth(s); kindsKnown && a != "" && !kinds[a] {
			continue
		}
		tls12 = append(tls12, s)
	}
	conf12, extra := confidence, []string(nil)
	if !kindsKnown {
		conf12 = model.ConfidenceMedium
		extra = append(extra, "the kind of the server certificate is not known (a keystore whose contents are not read, or no type attribute), so the suites are not narrowed by certificate kind; "+
			"suites that need a kind of certificate the server does not have are not usable")
	}
	if len(h.certs) > 1 {
		extra = append(extra, "with more than one certificate, Tomcat picks the certificate from the order of the suites the client offers; a client that offers suites for both kinds may be refused a suite that is listed here (measured)")
	}
	emit(paramCiphers, tls12, conf12, steps, extra...)
	if tls13Reason != "" {
		unresolved(paramTLS13, tls13Reason)
	} else {
		st := steps
		if tb.CipherSuitesAttribute {
			st = []model.ResolutionStep{{Layer: "app-default", Op: "default", Source: tomcatProv}, steps[1], steps[2]}
		}
		emit(paramTLS13, tls13, confidence, st)
	}
	switch {
	case hasGroups:
		unresolved(model.ParamTLSGroups, "the groups attribute is set; its effect depends on the Tomcat and Java versions and has not been resolved")
	case r.GroupsBlocker != "":
		unresolved(model.ParamTLSGroups, r.GroupsBlocker)
	default:
		g := append([]string{}, r.Groups13...)
		in := map[string]bool{}
		for _, x := range g {
			in[x] = true
		}
		for _, x := range r.Groups12 {
			if !in[x] {
				g = append(g, x)
			}
		}
		emit(model.ParamTLSGroups, g, confidence, []model.ResolutionStep{{Layer: "library", Op: "default", Source: ctx.prov}, steps[2]})
	}
}
