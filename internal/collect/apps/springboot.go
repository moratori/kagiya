package apps

import (
	"path"
	"sort"
	"strconv"
	"strings"

	"kagiya/internal/jsse"
	"kagiya/internal/model"
	"kagiya/internal/parse/jarfile"
	"kagiya/internal/parse/springconf"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
	"kagiya/internal/tomcatciphers"
)

// このファイルは、Spring Boot のアプリ（組み込みの Tomcat で TLS を待ち受ける、実行できる JAR）の読み取りと、
// 受け入れるプロトコル・暗号スイートの解決。
//
// 決まり方（検証ラボで、Spring Boot 2.7.0〜4.1.2 の全パッチ版を実際に起動して確かめたもの）:
//
//   - TLS の設定は、JAR の中の application.properties / application.yml の server.ssl.*（と、SSL バンドル）にある。
//     キーストアや証明書の指定がなければ、TLS を待ち受けない。
//   - 暗号の指定（server.ssl.ciphers）は、同梱の Tomcat が自分の表で解釈する。書いていなければ Tomcat の既定。
//     そのうち、アプリを動かす JDK が対応していて、無効にしていないものを受け入れる。
//   - どの JDK で動くかは、JAR からは分からない。起動の定義（systemd のユニットの ExecStart）から読む。
//     定義が読めない JAR は、導入されているすべての JDK で結果を求め、同じになった項目だけ確定とする。
//
// 読むのは、JAR の中身の一覧、マニフェストの決まった項目、決まった名前の設定ファイルの許可した項目だけ。
// 入れ子の JAR、クラスファイル、パスワードの項目は読まない。実行中のプロセスも見ない。
// 設定は、JAR の外（環境変数、起動時の引数、JAR の隣の設定ファイル）から上書きできる。上書きが見つかった場合は値を求めず、
// 見つからなかった場合も「JAR の外からの上書きは確認していない」と注記する。

const (
	springApp          = "spring-boot"
	springEmbedded     = "tomcat-embed-core"
	springMaxManifest  = 64 << 10
	springMaxConfig    = 1 << 20
	springMaxUnits     = 4000
	springMaxApps      = 200
	springDefaultPort  = "8080"
	springClassesEntry = "BOOT-INF/classes/"
	springLibEntry     = "BOOT-INF/lib/"
)

var springLimits = jarfile.Limits{MaxArchiveSize: 2 << 30, MaxEntries: 200000, MaxNameLen: 1024, MaxEntrySize: springMaxConfig, MaxRatio: 200}

// CollectJavaApps は、Java のアプリ（いまは Spring Boot）を調べる。archives は、探索で見つかった JAR（接頭辞つきの絶対パス）。
// 起動の定義（systemd のユニット）から参照されている JAR も対象にする。
func (c *Collector) CollectJavaApps(archives []string) {
	var app ruleset.AppRule
	found := false
	for _, a := range c.Rules.Apps {
		if a.Grammar == "springboot" {
			app, found = a, true
		}
	}
	if !found {
		return
	}
	var launches map[string]*javaLaunch
	c.Builder.Guard("", "reading the launch definitions of Java applications", func() { launches = c.javaLaunches() })
	jars := map[string]bool{}
	var order []string
	add := func(p string) {
		if p = path.Clean(p); !jars[p] {
			jars[p] = true
			order = append(order, p)
		}
	}
	for p := range launches {
		add(p)
	}
	for _, p := range archives {
		add(strings.TrimPrefix(p, c.Prefix))
	}
	sort.Strings(order)
	n := 0
	for _, jar := range order {
		if n >= springMaxApps {
			c.Builder.Skip(safefs.Skip{Path: c.Prefix + jar, Reason: "limit", Detail: "more Java applications than the limit; this and the following ones are not examined"})
			break
		}
		c.Builder.Guard(c.Prefix+jar, "reading a Java application", func() {
			if c.springBoot(app, jar, launches[jar]) {
				n++
			}
		})
	}
}

// springBoot は、JAR 1 つを調べる。Spring Boot のアプリであれば記録して true を返す。
func (c *Collector) springBoot(app ruleset.AppRule, jar string, launch *javaLaunch) bool {
	f, err := c.Opener.Open(c.Prefix + jar)
	if err != nil {
		return false
	}
	defer f.Close()
	a, err := jarfile.Open(f, f.Size(), springLimits)
	if err != nil {
		return false // 壊れた JAR は、JAR の棚卸し（jars）の側で記録する
	}
	// マニフェスト: Spring Boot の版と、クラスとライブラリの置き場だけを読む
	manifest, err := a.Read("META-INF/MANIFEST.MF")
	if err != nil || len(manifest) > springMaxManifest {
		return false
	}
	mf := manifestValues(manifest, "Spring-Boot-Version", "Spring-Boot-Classes", "Spring-Boot-Lib")
	boot := mf["Spring-Boot-Version"]
	if boot == "" || len(boot) > 32 {
		return false
	}
	// 先頭に起動スクリプトがある JAR（そのまま実行できる JAR）は、起動のしかたが .conf と環境変数で決まる
	launch, execReason := c.executableJar(f, jar, launch)
	classes, lib := mf["Spring-Boot-Classes"], mf["Spring-Boot-Lib"]
	if classes == "" {
		classes = springClassesEntry
	}
	if lib == "" {
		lib = springLibEntry
	}

	svc := model.Service{ID: "svc:" + app.ID + ":" + jar, App: app.ID, ConfigFiles: []string{c.Prefix + jar}}
	svc.Activity = model.Activity{Level: model.ActivityInstalled, Evidence: []model.Evidence{{Kind: "archive-present", Path: c.Prefix + jar}}}
	if launch != nil {
		svc.Activity = launch.activity
	}
	c.Builder.AddService(svc)

	// 同梱の Tomcat
	tomcatVersion, otherServer := "", ""
	for _, e := range a.Entries {
		name, ok := strings.CutPrefix(e.Name, lib)
		if !ok || strings.Contains(name, "/") {
			continue
		}
		if v, ok := strings.CutPrefix(strings.TrimSuffix(name, ".jar"), springEmbedded+"-"); ok && strings.HasSuffix(name, ".jar") {
			tomcatVersion = v
		}
		for _, other := range []string{"jetty-server-", "undertow-core-", "reactor-netty-http-"} {
			if strings.HasPrefix(name, other) {
				otherServer = strings.TrimSuffix(other, "-")
			}
		}
	}

	// 設定。プロファイルは、起動時の引数、環境変数、設定ファイルの中の順に優先される
	opt := springconf.Options{}
	if launch != nil {
		switch {
		case launch.cmd.ProfilesSet:
			opt.Profiles, opt.ProfilesSet = launch.cmd.Profiles, true
		case launch.envProfilesSet:
			opt.Profiles, opt.ProfilesSet = launch.envProfiles, true
		}
	}
	cfg := springconf.LoadWith(func(name string) ([]byte, bool) {
		data, err := a.Read(classes + name)
		return data, err == nil
	}, opt)
	scope := "port " + springDefaultPort
	if p, ok := cfg.Get("server.port"); ok && tomcatPort.MatchString(p.Value) {
		scope = "port " + p.Value
	}
	sb := &springBootApp{c: c, app: app, svc: svc, jar: jar, classes: classes, scope: scope, cfg: cfg, boot: boot, launch: launch}

	// TLS を待ち受ける設定か
	table, known := c.Rules.SpringBootFor(boot)
	tls := sb.settings(table)
	sb.management(tls)
	if !tls.enabled && tls.reason == "" {
		return true // TLS を待ち受けない（サービスとしてだけ記録する）
	}
	params := []string{model.ParamTLSProtocols, paramCiphers, paramTLS13, model.ParamTLSGroups}
	fail := func(reason string) bool {
		c.unresolved(svc, app.Direction, scope, reason, params...)
		return true
	}
	switch {
	case !known:
		return fail("no measurements are recorded for Spring Boot " + boot)
	case tls.reason != "":
		return fail(tls.reason)
	case tomcatVersion == "" && otherServer != "":
		return fail("the application bundles " + otherServer + " instead of an embedded Tomcat (tomcat-embed-core); other embedded servers have not been measured")
	case tomcatVersion == "":
		return fail("no embedded Tomcat (tomcat-embed-core) is bundled in the application; which server handles TLS is not determined")
	case len(cfg.Problems) > 0:
		return fail("the configuration in the JAR is not fully read: " + cfg.Problems[0])
	case execReason != "":
		return fail(execReason)
	}
	tb, src, ok := c.Rules.EmbeddedTomcatTableFor(springEmbedded, tomcatVersion)
	if !ok {
		return fail("no table is recorded for the embedded Tomcat " + tomcatVersion)
	}
	sb.tomcat, sb.tomcatVersion = tb, tomcatVersion
	sb.tomcatProv = &model.Provenance{Image: src.Image, OS: src.OS, Package: springEmbedded, Version: tomcatVersion}
	if r := sb.outside(a); r != "" {
		return fail(r)
	}
	sb.resolve(tls)
	return true
}

// manifestValues は、JAR のマニフェストから、指定した名前の項目だけを取り出す（続きの行は扱わない。値は 1 行に収まる短いもの）。
func manifestValues(data []byte, names ...string) map[string]string {
	out := map[string]string{}
	for _, l := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		k, v, ok := strings.Cut(l, ": ")
		if !ok {
			continue
		}
		for _, n := range names {
			if k == n && len(v) <= 256 && !strings.ContainsAny(v, "\x00\\") {
				out[n] = strings.TrimSpace(v)
			}
		}
	}
	return out
}

type springBootApp struct {
	c       *Collector
	app     ruleset.AppRule
	svc     model.Service
	jar     string // 接頭辞なし
	classes string // JAR の中の、クラスと設定ファイルの置き場
	scope   string
	cfg     *springconf.Config
	boot    string
	launch  *javaLaunch

	tomcat        *ruleset.TomcatTable
	tomcatVersion string
	tomcatProv    *model.Provenance
}

// springTLS は、設定から読んだ TLS の指定。
type springTLS struct {
	enabled bool
	reason  string // 空でなければ、値を求められない理由

	protocols, ciphers    []string
	hasProtocols          bool
	hasCiphers            bool
	protocolsAt, cipherAt springconf.Value
	certificate           string // PEM の証明書の場所（ファイルのパス。なければ空）
}

// location は、設定ファイルの中の位置を、「JAR!/置き場/ファイル」の形（接頭辞なし）で返す。
func (sb *springBootApp) location(v springconf.Value) string {
	return sb.jar + "!/" + sb.classes + v.File
}

func (sb *springBootApp) record(directive, value string, at springconf.Value) {
	if rule, ok := sb.app.Directive(directive); ok {
		sb.c.record(sb.app, sb.svc, rule, value, sb.location(at), at.Line, sb.scope, "")
	}
}

// recordPath は、ファイルの場所の設定を記録する。「file:」は外し、JAR の中を指すもの（classpath:）や相対パスは記録しない
// （相対パスは、起動したときの作業ディレクトリしだいで、ここでは決まらない）。
func (sb *springBootApp) recordPath(directive string, v springconf.Value) string {
	p := strings.TrimPrefix(v.Value, "file:")
	if !strings.HasPrefix(p, "/") || strings.Contains(p, ":") {
		return ""
	}
	sb.record(directive, p, v)
	return p
}

// settings は、JAR の中の設定から、TLS を待ち受けるかと、その指定を読む。あわせて、根拠になる記載を記録する。
func (sb *springBootApp) settings(table *ruleset.SpringBootTable) springTLS {
	cfg := sb.cfg
	var t springTLS
	if v, ok := cfg.Get("server.ssl.enabled"); ok && strings.EqualFold(v.Value, "false") {
		return t
	}
	state := func(s string, what string) (use bool) {
		switch {
		case table == nil:
			return true // 版の事実がない。後で「測っていない版」として理由を付ける
		case s == "yes":
			return true
		case s == "unknown":
			t.reason = "the " + what + " settings are used, but the application did not start with them on Spring Boot " + sb.boot + " when measured"
		}
		return false
	}
	base := "server.ssl."
	if b, ok := cfg.Get("server.ssl.bundle"); ok {
		// SSL バンドル。この設定のない版では、書いても TLS を待ち受けない（実測）
		bundles := ""
		if table != nil {
			bundles = table.SSLBundles
		}
		if !state(bundles, "SSL bundle") {
			return t
		}
		name := strings.ToLower(strings.NewReplacer("-", "", "_", "").Replace(b.Value))
		found := false
		for _, kind := range []string{"jks", "pem"} {
			prefix := "spring.ssl.bundle." + kind + "." + name + "."
			loc, okL := cfg.Get(prefix + "keystore.location")
			cert, okC := cfg.Get(prefix + "keystore.certificate")
			if !okL && !okC && !cfg.Unresolved[prefix+"keystore.location"] {
				continue
			}
			found = true
			base = prefix + "options."
			if okL {
				sb.recordPath("key-store", loc)
			}
			if okC {
				t.certificate = sb.recordPath("certificate", cert)
			}
			if k, ok := cfg.Get(prefix + "keystore.private-key"); ok {
				sb.recordPath("certificate-private-key", k)
			}
		}
		if !found {
			t.reason = "server.ssl.bundle names an SSL bundle whose definition is not found in the configuration in the JAR"
			return t
		}
	} else {
		ks, okK := cfg.Get("server.ssl.key-store")
		cert, okC := cfg.Get("server.ssl.certificate")
		switch {
		case okK:
			sb.recordPath("key-store", ks)
		case okC:
			pem := ""
			if table != nil {
				pem = table.PEMProperties
			}
			if !state(pem, "PEM certificate") {
				return t
			}
			t.certificate = sb.recordPath("certificate", cert)
			if k, ok := cfg.Get("server.ssl.certificate-private-key"); ok {
				sb.recordPath("certificate-private-key", k)
			}
		case cfg.Unresolved["server.ssl.key-store"] || cfg.Unresolved["server.ssl.certificate"]:
			// 場所は分からないが、TLS は待ち受ける
		default:
			return t // キーストアも証明書もない: TLS を待ち受けない
		}
	}
	t.enabled = true
	t.protocols, t.protocolsAt = cfg.List(base + "enabled-protocols")
	t.ciphers, t.cipherAt = cfg.List(base + "ciphers")
	t.hasProtocols, t.hasCiphers = t.protocols != nil, t.ciphers != nil
	// 値を確定できない記載（${...}）が、TLS の項目にある
	var unresolved []string
	for k := range cfg.Unresolved {
		if strings.HasPrefix(k, "server.ssl.") || strings.HasPrefix(k, "spring.ssl.") || k == "spring.profiles.active" {
			unresolved = append(unresolved, k)
		}
	}
	sort.Strings(unresolved)
	for _, k := range unresolved {
		if strings.HasSuffix(k, "ciphers") || strings.HasSuffix(k, "enabled-protocols") || strings.HasSuffix(k, ".bundle") || strings.HasSuffix(k, ".enabled") || k == "spring.profiles.active" {
			t.reason = "the value of " + k + " has a placeholder (${...}) and is not interpreted"
			return t
		}
	}
	if t.hasProtocols {
		ok := len(t.protocols) <= 16
		for _, p := range t.protocols {
			ok = ok && tomcatProtocolsValue.MatchString(p)
		}
		if !ok {
			t.reason = "the value of enabled-protocols is not interpreted"
			return t
		}
		sb.record("enabled-protocols", strings.Join(t.protocols, " "), t.protocolsAt)
	}
	if t.hasCiphers {
		joined := strings.Join(t.ciphers, ":")
		if len(joined) > tomcatMaxCiphers || !tomcatCiphersValue.MatchString(joined) || strings.ContainsAny(joined, ", ") {
			t.reason = "the value of ciphers is not interpreted"
			return t
		}
		sb.record("ciphers", joined, t.cipherAt)
	}
	return t
}

// management は、管理用の待ち受け（management.server.port で、本体と別のポートにしたもの）が TLS を使いうる場合に、
// 別の待ち受けとして「不明」で記録する。TLS の設定の決まり方（management.server.ssl.*、本体の設定の引き継ぎ）は測っていないので、
// 値は求めない。待ち受けがあること自体を見落とさないための記録。
func (sb *springBootApp) management(main springTLS) {
	cfg := sb.cfg
	port, ok := cfg.Get("management.server.port")
	if !ok || !tomcatPort.MatchString(port.Value) || port.Value == "0" || "port "+port.Value == sb.scope {
		return // 指定なし、本体と同じポート、無効（-1）
	}
	if v, ok := cfg.Get("management.server.ssl.enabled"); ok && strings.EqualFold(v.Value, "false") {
		return
	}
	own := false
	for _, k := range []string{"management.server.ssl.key-store", "management.server.ssl.certificate", "management.server.ssl.bundle"} {
		if _, ok := cfg.Get(k); ok || cfg.Unresolved[k] || cfg.Inline[k] {
			own = true
		}
	}
	if !own && !main.enabled && main.reason == "" {
		return // TLS の設定が、管理用にも本体にもない
	}
	sb.c.unresolved(sb.svc, sb.app.Direction, "port "+port.Value,
		"the management port of Spring Boot (management.server.port) is a separate listener; how its TLS settings are decided "+
			"(management.server.ssl.*, or the settings of the main port) has not been measured, so whether and how it accepts TLS is not determined",
		model.ParamTLSProtocols, paramCiphers, paramTLS13, model.ParamTLSGroups)
}

// outside は、JAR の外から設定が上書きされていることが分かる場合に、その理由を返す。
func (sb *springBootApp) outside(a *jarfile.Archive) string {
	c := sb.c
	for _, e := range a.Entries {
		if strings.HasPrefix(e.Name, sb.classes+"config/application") {
			return "the JAR has configuration files in a config/ directory on the class path, which are not interpreted"
		}
	}
	dirs := []string{path.Dir(sb.jar)}
	if l := sb.launch; l != nil {
		switch {
		case l.cmd.Risky != "":
			return "the application is started with an option (" + l.cmd.Risky + "...) that can change the TLS settings of Java; its effect is not interpreted"
		case l.envUnknown != "":
			return "the value of " + l.envUnknown + " in the environment of " + l.name + " is not determined (it is filled in when the application is started)"
		case l.envRisky != "":
			return l.envRisky + " in the environment of " + l.name + " adds Java options that are not interpreted"
		case l.cmd.Overrides:
			return "TLS settings or the location of configuration files are given on the command line in " + l.name + "; they override the configuration in the JAR and are not interpreted"
		case l.envOverride != "":
			return "TLS settings or the location of configuration files are given in the environment of " + l.name + " (" + l.envOverride + "); they override the configuration in the JAR and are not interpreted"
		}
		if l.workDir != "" && l.workDir != dirs[0] {
			dirs = append(dirs, l.workDir)
		}
	}
	// JAR の隣（と作業ディレクトリ）の設定ファイルは、JAR の中の設定より優先される
	for _, d := range dirs {
		for _, sub := range []string{"", "/config"} {
			for _, name := range []string{"application.properties", "application.yml", "application.yaml"} {
				if _, err := c.read(d + sub + "/" + name); err == nil {
					return "a configuration file outside the JAR (" + d + sub + "/" + name + ") overrides the configuration in the JAR and is not interpreted"
				}
			}
		}
	}
	return ""
}

// springResult は、ある JDK で動かした場合の結果。
type springResult struct {
	home   string
	jdk    jdkContext
	reason string
	r      jsse.Result
	tls12  []string
	tls13  []string
	groups []string
}

// jdkChoice は、アプリを動かす JDK を決める。起動の定義から Java が決まれば、その JDK（certain = true）。
// 決まらなければ、見つかったすべての JDK を候補として返す（結果が同じになった項目だけを確定とする。確度は下げる）。
func (sb *springBootApp) jdkChoice() (homes []string, why string, certain bool) {
	c := sb.c
	if l := sb.launch; l != nil && !l.javaUnknown {
		// 実行ファイルはリンクのことが多い（/usr/bin/java → /etc/alternatives/java → JDK の bin/java）。辿った先の JDK を使う
		java := l.cmd.Java
		if real, err := c.Opener.Resolve(c.Prefix + java); err == nil {
			java = strings.TrimPrefix(real, c.Prefix)
		}
		homes = []string{path.Dir(path.Dir(java))}
		why = "the JDK is the one named in " + l.name + " (" + l.cmd.Java + ", the JDK in " + homes[0] + ")"
		if l.javaFrom != "" {
			why = "the application is started by " + l.name + "; the JDK is the one that " + l.javaFrom + " names (the JDK in " + homes[0] + ")"
		}
	} else if l != nil {
		homes = c.jdkHomes()
		why = "the application is started by " + l.name + "; its launch script uses the Java that JAVA_HOME names, or else the java on PATH, and which JDK that is, is not determined. " +
			"The values are those that are the same with every JDK found on this host (" + strings.Join(homes, ", ") + "). A JDK in a place that is not searched is not considered"
	} else {
		homes = c.jdkHomes()
		why = "no launch definition was found for this JAR, so it is not known which JDK runs it; the values are those that are the same with every JDK found on this host (" +
			strings.Join(homes, ", ") + "). A JDK in a place that is not searched is not considered"
	}
	return homes, why, sb.launch != nil && !sb.launch.javaUnknown
}

// resolve は、受け入れるプロトコル・暗号スイート・グループを求めて記録する。
func (sb *springBootApp) resolve(t springTLS) {
	c, tb := sb.c, sb.tomcat
	// Tomcat に渡る指定。ciphers を書くと、TLS 1.3 のスイートもその指定に従う（実測）
	var names []string
	first := model.ResolutionStep{Layer: "app-default", Op: "default", Source: sb.tomcatProv}
	if t.hasCiphers {
		names = tomcatciphers.Expand(tb, strings.Join(t.ciphers, ":"))
		first = model.ResolutionStep{Layer: "app-config", Op: "override", Setting: c.settingAt(sb.svc, paramCiphers, sb.location(t.cipherAt), t.cipherAt.Line)}
	} else {
		names = tomcatciphers.Expand(tb, tb.DefaultCiphers)
		if tb.CipherSuitesAttribute {
			only12 := names[:0:0]
			for _, n := range names {
				if strings.Contains(n, "_WITH_") {
					only12 = append(only12, n)
				}
			}
			names = append(only12, tb.DefaultCipherSuites...)
		}
	}
	protoFirst := model.ResolutionStep{Layer: "app-default", Op: "default", Source: sb.tomcatProv}
	protos := tb.ProtocolsAll
	if t.hasProtocols {
		protos = t.protocols
		protoFirst = model.ResolutionStep{Layer: "app-config", Op: "override", Setting: c.settingAt(sb.svc, model.ParamTLSProtocols, sb.location(t.protocolsAt), t.protocolsAt.Line)}
	}
	var want []string
	for _, p := range protos {
		if p != "SSLv2Hello" {
			want = append(want, p)
		}
	}
	// 証明書の種類（PEM のファイルを読めた場合だけ分かる。キーストアの中は読まない）
	kind := ""
	if t.certificate != "" {
		if ks, ok := c.certKinds([]string{t.certificate}); ok && len(ks) == 1 && ks[0].Key != "other" {
			kind = ks[0].Key
		}
	}

	homes, why, certain := sb.jdkChoice()
	params := []string{model.ParamTLSProtocols, paramCiphers, paramTLS13, model.ParamTLSGroups}
	if len(homes) == 0 {
		c.unresolved(sb.svc, sb.app.Direction, sb.scope, "no launch definition names the Java for this JAR and no JDK is found on this host; which JDK runs the application is not determined", params...)
		return
	}
	var results []springResult
	for _, h := range homes {
		res := springResult{}
		res.jdk, res.home, res.reason = c.tomcatJDK(sb.svc, h)
		if res.home == "" {
			res.home = h
		}
		if res.reason == "" {
			res.r = jsse.ResolveExplicit(res.jdk.table, res.jdk.input, want, names)
			for _, s := range res.r.Suites {
				switch {
				case !strings.Contains(s, "_WITH_"):
					res.tls13 = append(res.tls13, s)
				case kind != "" && tomcatSuiteAuth(s) != "" && tomcatSuiteAuth(s) != kind:
				default:
					res.tls12 = append(res.tls12, s)
				}
			}
			used := jsse.Result{}
			if len(res.tls13) > 0 {
				used.Groups13 = res.r.Groups13
			}
			for _, s := range res.r.Suites {
				if strings.Contains(s, "_ECDHE_") {
					used.Groups12 = res.r.Groups12
					break
				}
			}
			res.groups = jsseGroups(used)
		}
		results = append(results, res)
	}

	confidence := model.ConfidenceHigh
	if !certain {
		confidence = model.ConfidenceMedium
	}
	notes := []string{
		"Spring Boot " + sb.boot + " with the embedded Tomcat " + sb.tomcatVersion + ", on the JDK's TLS implementation (JSSE): " + why,
		"the settings come from the configuration inside the JAR; settings given outside the JAR (environment variables, command-line arguments, configuration files in other places, a configuration server) are not confirmed",
	}
	// 項目ごとに、すべての JDK で同じ結果なら確定、違えば「不明」
	emit := func(param string, pick func(springResult) []string, firstStep model.ResolutionStep, conf string, blocker func(springResult) string, extra ...string) {
		var agreed []string
		for i, res := range results {
			reason := res.reason
			if reason == "" && blocker != nil {
				reason = blocker(res)
			}
			if reason != "" {
				if len(results) > 1 {
					reason = "with the JDK in " + res.home + ": " + reason
				}
				c.unresolved(sb.svc, sb.app.Direction, sb.scope, reason, param)
				return
			}
			v := pick(res)
			if i == 0 {
				agreed = v
			} else if sortedJoinStrings(agreed) != sortedJoinStrings(v) {
				var parts []string
				for _, x := range results {
					parts = append(parts, x.home+": "+strconv.Itoa(len(pick(x)))+" value(s)")
				}
				c.unresolved(sb.svc, sb.app.Direction, sb.scope, "the result differs between the JDKs found on this host, and it is not known which one runs this application ("+strings.Join(parts, "; ")+")", param)
				return
			}
		}
		if agreed == nil {
			agreed = []string{}
		}
		jdk := results[0].jdk
		n := append(append(append([]string{}, notes...), jdk.notes...), extra...)
		if jdk.confidence == model.ConfidenceMedium {
			conf = model.ConfidenceMedium
		}
		steps := []model.ResolutionStep{firstStep, {Layer: "library", Op: "intersect", Source: jdk.prov}, {Layer: jdk.layer, Op: "remove", Setting: jdk.settingID}}
		c.Builder.AddEffective(model.EffectiveValue{Service: sb.svc.ID, Parameter: param, Direction: sb.app.Direction, Scope: sb.scope,
			Status: model.StatusResolved, Values: agreed, Confidence: conf, Steps: steps, Notes: n})
	}
	emit(model.ParamTLSProtocols, func(r springResult) []string { return r.r.Protocols }, protoFirst, confidence, nil)
	conf12, extra := confidence, []string(nil)
	if kind == "" {
		conf12 = model.ConfidenceMedium
		extra = []string{"the kind of the server certificate is not known (a keystore whose contents are not read), so the suites are not narrowed by certificate kind; " +
			"suites that need a kind of certificate the server does not have are not usable"}
	}
	emit(paramCiphers, func(r springResult) []string { return r.tls12 }, first, conf12, nil, extra...)
	emit(paramTLS13, func(r springResult) []string { return r.tls13 }, first, confidence, nil)
	emit(model.ParamTLSGroups, func(r springResult) []string { return r.groups }, model.ResolutionStep{Layer: "library", Op: "default"}, confidence,
		func(r springResult) string { return r.r.GroupsBlocker })
}

func sortedJoinStrings(v []string) string {
	s := append([]string{}, v...)
	sort.Strings(s)
	return strings.Join(s, ",")
}
