package apps

import (
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
	paramTomcatMultiCert = "tls.multiple-certificates" // 既定値表: OpenSSL の実装で、証明書を複数置いたときの扱い
	tomcatServer         = "tomcat"
	tomcatAPRListener    = "org.apache.catalina.core.AprLifecycleListener"
	tomcatFFMListener    = "org.apache.catalina.core.OpenSSLLifecycleListener"
	tomcatJSSEImpl       = "org.apache.tomcat.util.net.jsse.JSSEImplementation"
	tomcatOpenSSLImpl    = "org.apache.tomcat.util.net.openssl.OpenSSLImplementation"
	tomcatAPRProtocol    = "org.apache.coyote.http11.Http11AprProtocol"
	tomcatMaxCiphers     = 8192
	tomcatDebJavaHome    = "/usr/lib/jvm/default-java"
	tomcatRPMConf        = "/etc/tomcat/tomcat.conf"
	tomcatRPMSysconfig   = "/etc/sysconfig/tomcat"
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
	in, common := c.tomcatInstallation(app, svc, config, f)
	var openssl []tlsScope
	// OpenSSL の実装での、証明書を複数置いたときの扱い（その版で確かめた事実。既定値表にある）
	multiCert := ""
	if defs, _, _, _ := c.appDefaults(app); defs != nil {
		multiCert = strings.Join(defs[paramTomcatMultiCert], ",")
	}
	for _, conn := range f.Connectors {
		if v, ok := conn.Attr["SSLEnabled"]; !ok || !strings.EqualFold(strings.TrimSpace(v.Value), "true") {
			continue
		}
		// どの実装で動くか
		reason, why, impl := common, "", ""
		if reason == "" && len(conn.Hosts) == 0 && !in.table.ConnectorTLSAttributes {
			reason = "the Connector has no SSLHostConfig element; this Tomcat version does not take TLS settings written on the Connector itself (the server did not start with them when measured)"
		}
		if reason == "" {
			impl, why, reason = tomcatImplementation(conn, in.apr, in.sslOff, in.native)
		}
		for _, h := range tomcatHosts(conn) {
			if impl == "openssl" {
				openssl = append(openssl, c.tomcatOpenSSLScope(in, h, why, multiCert))
				continue
			}
			if reason == "" {
				reason = in.jdkReason
			}
			c.tomcatHost(in, h, why, reason)
		}
	}
	// OpenSSL の実装で動く範囲は、OpenSSL を使うほかのサーバーと同じ求め方をする
	c.opensslServerEffective(app, svc, openssl)
}

// tomcatHosts は、Connector の TLS の設定を、範囲（SSLHostConfig。古い書き方では Connector 自身）ごとに分ける。
func tomcatHosts(conn serverxml.Connector) []tomcatHost {
	scope := "connector at line " + strconv.Itoa(conn.Line)
	if p, ok := conn.Attr["port"]; ok && tomcatPort.MatchString(p.Value) {
		scope = "connector " + p.Value
	}
	if len(conn.Hosts) == 0 {
		// 古い書き方: TLS の設定を Connector に直接書く。属性の名前が違う
		names := map[string]string{"protocols": "sslEnabledProtocols", "certificateKeystoreFile": "keystoreFile", "ciphers": "ciphers"}
		return []tomcatHost{{scope: scope, legacy: true, attr: func(name string) (serverxml.Attr, bool) {
			old, ok := names[name]
			if !ok {
				return serverxml.Attr{}, false
			}
			a, ok := conn.Attr[old]
			return a, ok
		}}}
	}
	var hosts []tomcatHost
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
	return hosts
}

// tomcatImplementation は、その Connector がどの TLS の実装で動くかを決める。impl は "jsse"（JDK）か "openssl"（Tomcat Native 経由）で、
// why にその根拠が入る。決められない場合は、reason に理由が入る。
func tomcatImplementation(conn serverxml.Connector, apr, sslOff bool, native tomcatNativeState) (impl, why, reason string) {
	loaded := apr && !sslOff && native.reason == "" && native.installed && native.loadable // Tomcat Native が読み込まれ、OpenSSL を使える
	switch p := strings.TrimSpace(conn.Attr["protocol"].Value); p {
	case "", "HTTP/1.1", "org.apache.coyote.http11.Http11NioProtocol", "org.apache.coyote.http11.Http11Nio2Protocol":
	case tomcatAPRProtocol:
		if loaded {
			return "openssl", "the Connector uses the APR protocol handler, which runs on OpenSSL through Tomcat Native (" + native.pkg + ")", ""
		}
		return "", "", "the Connector uses the APR protocol handler, but whether Tomcat Native can be loaded here is not determined"
	default:
		return "", "", "the protocol attribute of the Connector names a handler that has not been measured"
	}
	switch impl := strings.TrimSpace(conn.Attr["sslImplementationName"].Value); impl {
	case tomcatJSSEImpl:
		return "jsse", "sslImplementationName selects the JDK's TLS implementation (JSSE)", ""
	case tomcatOpenSSLImpl:
		if loaded {
			return "openssl", "sslImplementationName selects the OpenSSL implementation, and Tomcat Native (" + native.pkg + ") is loaded", ""
		}
		return "", "", "sslImplementationName selects the OpenSSL implementation, but whether Tomcat Native can be loaded here is not determined (without it the server does not start)"
	case "":
	default:
		return "", "", "sslImplementationName names an implementation that has not been measured"
	}
	switch {
	case !apr:
		return "jsse", "server.xml has no AprLifecycleListener, so the JDK's TLS implementation (JSSE) is used", ""
	case native.reason != "":
		return "", "", native.reason
	case !native.installed:
		return "jsse", "no Tomcat Native package is installed, so the JDK's TLS implementation (JSSE) is used", ""
	case !native.loadable:
		return "jsse", "the installed Tomcat Native (" + native.pkg + ") is older than this Tomcat version requires and is not loaded, so the JDK's TLS implementation (JSSE) is used", ""
	case sslOff:
		return "", "", "the AprLifecycleListener has SSLEngine=\"off\" while Tomcat Native (" + native.pkg + ") can be loaded; the behaviour differs between Tomcat versions and has not been resolved"
	}
	return "openssl", "Tomcat Native (" + native.pkg + ") is loaded through the AprLifecycleListener, so the OpenSSL implementation is used", ""
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

// tomcatSettings は、範囲 1 つについて、server.xml に書かれていた値（解釈できたもの）。
type tomcatSettings struct {
	ciphers, protocols       serverxml.Attr
	hasCiphers, hasProtocols bool
	wantProtocols            []string // protocols を Tomcat の読み方で解釈したもの（記載がなければ、表の既定）
	hasCipherSuites          bool
	hasGroups                bool
	kinds                    map[string]bool // サーバーの証明書の鍵の種類
	kindsKnown               bool            // すべての証明書の種類が分かった
}

// tomcatRecord は、範囲 1 つの設定の記載を検証して記録し、解釈に使う値を返す。解釈できない値があれば、reason に理由が入る。
func (c *Collector) tomcatRecord(in *tomcatInstall, h tomcatHost) (set tomcatSettings, reason string) {
	rec := func(directive, value string, line int) {
		if rule, ok := in.app.Directive(directive); ok {
			c.record(in.app, in.svc, rule, value, in.config, line, h.scope, in.base)
		}
	}
	set.ciphers, set.hasCiphers = h.attr("ciphers")
	set.protocols, set.hasProtocols = h.attr("protocols")
	if set.hasCiphers && len(set.ciphers.Value) <= tomcatMaxCiphers && tomcatCiphersValue.MatchString(set.ciphers.Value) {
		rec("ciphers", strings.Join(strings.FieldsFunc(set.ciphers.Value, func(r rune) bool { return r == ':' || r == ',' || r == ' ' }), ":"), set.ciphers.Line)
	} else if set.hasCiphers {
		reason = "the value of ciphers is not interpreted"
	}
	if in.table != nil {
		set.wantProtocols = in.table.ProtocolsAll
	}
	if set.hasProtocols && len(set.protocols.Value) <= 1024 && tomcatProtocolsValue.MatchString(set.protocols.Value) {
		if in.table != nil {
			set.wantProtocols = tomcatProtocols(in.table, set.protocols.Value)
			if len(set.wantProtocols) > 0 {
				rec("protocols", strings.Join(set.wantProtocols, " "), set.protocols.Line)
			}
		}
	} else if set.hasProtocols && reason == "" {
		reason = "the value of protocols is not interpreted"
	}
	if ks, ok := h.attr("certificateKeystoreFile"); ok && h.legacy {
		rec("certificateKeystoreFile", ks.Value, ks.Line)
	}
	set.kinds, set.kindsKnown = map[string]bool{}, len(h.certs) > 0
	for _, cert := range h.certs {
		for _, d := range []string{"certificateFile", "certificateKeyFile", "certificateChainFile", "certificateKeystoreFile"} {
			if a, ok := cert.Attr[d]; ok {
				rec(d, a.Value, a.Line)
			}
		}
		if kind := c.tomcatCertKind(in, cert); kind != "" {
			set.kinds[kind] = true
		} else {
			set.kindsKnown = false
		}
	}
	_, set.hasCipherSuites = h.attr("cipherSuites")
	groups, hasGroups := h.attr("groups")
	if set.hasGroups = hasGroups; hasGroups {
		rec("groups", strings.ReplaceAll(strings.ReplaceAll(groups.Value, " ", ""), ",", ":"), groups.Line)
	}
	return set, reason
}

// tomcatCertKind は、証明書の鍵の種類（RSA / EC / DSA）を返す。分からなければ空。
// type 属性があればそれ、なければ証明書のファイルから読む（キーストアの中身は読まない）。
func (c *Collector) tomcatCertKind(in *tomcatInstall, cert serverxml.Certificate) string {
	switch t := strings.ToUpper(strings.TrimSpace(cert.Attr["type"].Value)); t {
	case "RSA", "EC", "DSA":
		return t
	case "", "UNDEFINED":
		a, ok := cert.Attr["certificateFile"]
		if !ok || strings.ContainsAny(a.Value, "$%") {
			return ""
		}
		p := a.Value
		if !strings.HasPrefix(p, "/") {
			p = in.base + "/" + p
		}
		if ks, ok := c.certKinds([]string{p}); ok && len(ks) == 1 && ks[0].Key != "other" {
			return ks[0].Key
		}
	}
	return ""
}

// tomcatHost は、範囲 1 つについて、設定の記載を記録し、JDK の実装で受け入れるプロトコル・暗号スイート・グループを求めて記録する。
// reason が空でなければ（JDK の実装で動くと言えない、環境が分からないなど）、値は求めず、その理由を残す。
func (c *Collector) tomcatHost(in *tomcatInstall, h tomcatHost, why, reason string) {
	app, svc, tb := in.app, in.svc, in.table
	set, bad := c.tomcatRecord(in, h)
	if reason == "" {
		reason = bad
	}
	unresolved := func(reason string, params ...string) {
		c.unresolved(svc, app.Direction, h.scope, reason, params...)
	}
	if reason != "" {
		unresolved(reason, model.ParamTLSProtocols, paramCiphers, paramTLS13, model.ParamTLSGroups)
		return
	}

	// Tomcat の解釈: 暗号指定 → スイートの名前
	spec := tb.DefaultCiphers
	tomcatProv := &model.Provenance{Image: in.build.Source.Image, OS: in.build.Source.OS, Package: in.build.Package, Version: in.build.Version}
	appDefault := model.ResolutionStep{Layer: "app-default", Op: "default", Source: tomcatProv}
	first := appDefault
	if set.hasCiphers {
		spec = set.ciphers.Value
		first = model.ResolutionStep{Layer: "app-config", Op: "override", Setting: c.settingAt(svc, paramCiphers, in.config, set.ciphers.Line)}
	}
	names := tomcatciphers.Expand(tb, spec)
	tls13Reason, tls13Note := "", ""
	if tb.CipherSuitesAttribute {
		// TLS 1.3 のスイートは別の属性で決まり、ciphers の内容は関係しない（実測）
		only12 := names[:0:0]
		for _, n := range names {
			if strings.Contains(n, "_WITH_") {
				only12 = append(only12, n)
			}
		}
		names = append(only12, tb.DefaultCipherSuites...)
		switch {
		case !set.hasCipherSuites:
		case tb.CipherSuitesIgnoredByJDK:
			tls13Note = "the cipherSuites attribute is set, but with the JDK's TLS implementation it did not change the accepted TLS 1.3 suites on this Tomcat version (measured), so the default is listed"
		default:
			tls13Reason = "the cipherSuites attribute is set; its effect with the JDK's TLS implementation has not been measured on this Tomcat version"
		}
	}
	// プロトコルは、SSLv2Hello（接続の始め方の形式で、プロトコルの版ではない）を除く
	var protos []string
	for _, p := range set.wantProtocols {
		if p != "SSLv2Hello" {
			protos = append(protos, p)
		}
	}
	r := jsse.ResolveExplicit(in.jdk.table, in.jdk.input, protos, names)

	confidence := in.jdk.confidence
	notes := []string{"Tomcat runs on the JDK's TLS implementation (JSSE) with the JDK in " + in.jdkDir + ": " + why,
		"Tomcat's own cipher table decides what the ciphers value means; of those, the suites that this JDK supports and has not disabled are accepted",
		"not read: setenv.sh, environment added by systemd drop-ins, and a Tomcat Native library installed without a package"}
	notes = append(notes, in.jdk.notes...)
	if !in.exact {
		confidence = model.ConfidenceMedium
		notes = append(notes, interpolatedNote("Tomcat", in.build, in.pkg))
	}
	byJDK := model.ResolutionStep{Layer: "library", Op: "intersect", Source: in.jdk.prov}
	disabled := model.ResolutionStep{Layer: in.jdk.layer, Op: "remove", Setting: in.jdk.settingID}
	emit := func(param string, values []string, conf string, first model.ResolutionStep, extra ...string) {
		if values == nil {
			values = []string{}
		}
		c.Builder.AddEffective(model.EffectiveValue{Service: svc.ID, Parameter: param, Direction: app.Direction, Scope: h.scope,
			Status: model.StatusResolved, Values: values, Confidence: conf, Steps: []model.ResolutionStep{first, byJDK, disabled},
			Notes: append(append([]string{}, notes...), extra...)})
	}

	// プロトコル
	protoFirst := appDefault
	if set.hasProtocols {
		protoFirst = model.ResolutionStep{Layer: "app-config", Op: "override", Setting: c.settingAt(svc, model.ParamTLSProtocols, in.config, set.protocols.Line)}
	}
	emit(model.ParamTLSProtocols, r.Protocols, confidence, protoFirst)

	// 暗号スイート（TLS 1.2 以下と TLS 1.3）
	var tls12, tls13 []string
	for _, s := range r.Suites {
		if !strings.Contains(s, "_WITH_") {
			tls13 = append(tls13, s)
			continue
		}
		// サーバーの証明書の種類で成り立たないスイートは除く
		if a := tomcatSuiteAuth(s); set.kindsKnown && a != "" && !set.kinds[a] {
			continue
		}
		tls12 = append(tls12, s)
	}
	conf12, extra := confidence, []string(nil)
	if !set.kindsKnown {
		conf12 = model.ConfidenceMedium
		extra = append(extra, "the kind of the server certificate is not known (a keystore whose contents are not read, or no type attribute), so the suites are not narrowed by certificate kind; "+
			"suites that need a kind of certificate the server does not have are not usable")
	}
	if len(h.certs) > 1 {
		extra = append(extra, "with more than one certificate, Tomcat picks the certificate from the order of the suites the client offers; a client that offers suites for both kinds may be refused a suite that is listed here (measured)")
	}
	if set.hasGroups && (!set.kindsKnown || set.kinds["EC"]) {
		// EC の証明書の曲線が groups に含まれないと、ECDSA で認証するスイートは成り立たない（実測）。曲線は読んでいない
		unresolved("the groups attribute is set and the server has (or may have) an EC certificate; whether the ECDSA suites work depends on the curve of that certificate, which is not read", paramCiphers)
	} else {
		emit(paramCiphers, tls12, conf12, first, extra...)
	}
	switch {
	case tls13Reason != "":
		unresolved(tls13Reason, paramTLS13)
	case tb.CipherSuitesAttribute && tls13Note != "":
		emit(paramTLS13, tls13, confidence, appDefault, tls13Note)
	case tb.CipherSuitesAttribute:
		emit(paramTLS13, tls13, confidence, appDefault)
	default:
		emit(paramTLS13, tls13, confidence, first)
	}

	// 鍵交換のグループ
	switch {
	case set.hasGroups:
		unresolved("the groups attribute is set; its effect depends on the Tomcat and Java versions and has not been resolved", model.ParamTLSGroups)
	case r.GroupsBlocker != "":
		unresolved(r.GroupsBlocker, model.ParamTLSGroups)
	default:
		// グループは、それを使うスイートが残っているときだけ受け入れる（実測）
		used := jsse.Result{}
		if len(tls13) > 0 {
			used.Groups13 = r.Groups13
		}
		for _, x := range r.Suites {
			if strings.Contains(x, "_ECDHE_") {
				used.Groups12 = r.Groups12
				break
			}
		}
		c.Builder.AddEffective(model.EffectiveValue{Service: svc.ID, Parameter: model.ParamTLSGroups, Direction: app.Direction, Scope: h.scope,
			Status: model.StatusResolved, Values: jsseGroups(used), Confidence: confidence, Notes: append([]string{}, notes...),
			Steps: []model.ResolutionStep{{Layer: "library", Op: "default", Source: in.jdk.prov}, disabled}})
	}
}

// tomcatOpenSSLScope は、OpenSSL の実装（Tomcat Native 経由）で動く範囲 1 つについて、設定の記載を記録し、
// OpenSSL を使うサーバーに共通の求め方（opensslServerEffective）に渡す形にする。
//
// この実装では、Tomcat は ciphers の値をそのまま OpenSSL に渡す（解釈するのは、導入されている OpenSSL）。
func (c *Collector) tomcatOpenSSLScope(in *tomcatInstall, h tomcatHost, why string, multiCert string) tlsScope {
	set, bad := c.tomcatRecord(in, h)
	sc := tlsScope{name: h.scope, blocker: bad, certsOK: len(h.certs) > 0,
		info: []string{"Tomcat runs on OpenSSL here: " + why, "not read: setenv.sh, environment added by systemd drop-ins, and a Tomcat Native library installed without a package"}}
	if set.hasCiphers {
		sc.cipher = strings.Join(strings.FieldsFunc(set.ciphers.Value, func(r rune) bool { return r == ':' || r == ',' || r == ' ' }), ":")
		sc.cipherFile, sc.cipherLine = in.config, set.ciphers.Line
	}
	// 証明書の種類。すべて分かっていればそれで絞り込み、分からないものがあれば絞り込まない
	if set.kindsKnown {
		for _, k := range []string{"RSA", "EC", "DSA"} {
			if set.kinds[k] {
				sc.certKinds = append(sc.certKinds, k)
			}
		}
	} else {
		sc.certsOK = false
	}
	// プロトコルの版。TLS 1.2 を外して、それより古いものだけを残した設定は、OpenSSL のセキュリティレベルしだいで変わる
	on := map[string]bool{}
	for _, p := range set.wantProtocols {
		on[p] = true
	}
	sc.tls13Off = !on["TLSv1.3"]
	switch {
	case on["TLSv1.2"]:
	case on["TLSv1.1"] || on["TLSv1"] || on["SSLv3"]:
		sc.tls12Blocker = "TLS 1.2 is not enabled and only older protocol versions are; whether OpenSSL accepts them depends on its security level, and nothing was accepted when measured"
	default:
		sc.tls12Off = true
	}
	if len(h.certs) > 1 && multiCert != "all" && sc.blocker == "" {
		// 証明書の並び順で結果が変わる版がある（実測）。どちらの証明書のスイートも受け入れることを確かめた版だけ求める
		sc.blocker = "the server has more than one certificate; with the OpenSSL implementation the result depended on the order of the certificates on some versions (measured), and this version has not been confirmed to accept the suites of every certificate"
	}
	if set.hasGroups {
		sc.info = append(sc.info, "the groups attribute is set, but with the OpenSSL implementation it did not change the accepted groups (measured)")
	}
	if set.hasCipherSuites {
		sc.tls13Blocker = "the cipherSuites attribute is set; its effect with the OpenSSL implementation has not been measured"
	}
	return sc
}
