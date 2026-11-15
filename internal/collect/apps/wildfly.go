package apps

import (
	"kagiya/internal/confidence"
	"regexp"
	"strconv"
	"strings"

	"kagiya/internal/elytronciphers"
	"kagiya/internal/jsse"
	"kagiya/internal/model"
	"kagiya/internal/parse/jarfile"
	"kagiya/internal/parse/standalonexml"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

// このファイルは、WildFly（開発元の配布物を展開して置いたもの）の読み取り。
//
// WildFly は、Undertow の https-listener で TLS を待ち受ける。設定は、https-listener が指す Elytron の server-ssl-context
// （WildFly 24 までは、古い形式の security-realm も）にある。TLS の実装は JDK のもの（JSSE）。
// 受け入れるプロトコルと暗号スイートは、次の順で求める:
//
//  1. 設定の記載（なければ既定）を、WildFly の対応表（rules/java/wildfly.yaml）で解釈する。
//     暗号の指定（cipher-suite-filter）は、Elytron 自身の表と規則で解釈する（internal/elytronciphers）。
//  2. そのうち、WildFly を動かす JDK が対応していて、無効にしていないものが残る（rules/java/openjdk.yaml と java.security）。
//
// 解釈の規則と既定は、検証ラボで 19.0.0.Final〜42.0.0.Final の 54 版を場面ごとに起動して確かめたもの。測っていない版と、
// 測っていない書き方は、値を求めず「不明」にする。
//
// 読まないもの: パスワードの記載、ドメインのモード（domain.xml / host.xml）、管理用の待ち受け、起動時に渡されるシステムプロパティ。

const (
	wildflyConfigDir    = "/standalone/configuration"
	wildflyConfigSuffix = wildflyConfigDir + "/standalone.xml"
	wildflyProductDir   = "/modules/system/layers/base/org/jboss/as/product/main"
	wildflyMaxHomes     = 16
	wildflyMaxManifest  = 64 << 10
	wildflyUnmeasured   = "wildfly" // 「測定が要る版」での種類と名前
)

var (
	wildflyVersionValue = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[A-Za-z0-9]{1,16}$`)
	wildflyConfigName   = regexp.MustCompile(`^standalone[A-Za-z0-9._-]{0,64}\.xml$`)
	// 古い形式の ssl の protocol で、測った値（TLS の実装の名前）
	wildflyContextProtocols = map[string]bool{"TLS": true, "TLSv1": true, "TLSv1.1": true, "TLSv1.2": true, "TLSv1.3": true}
	wildflyProtocol         = regexp.MustCompile(`^(SSLv2Hello|SSLv[23]|TLSv1(\.[123])?)$`)
	wildflyJSSEName         = regexp.MustCompile(`^(TLS|SSL)_[A-Z0-9_]{1,90}$`)
	wildflyName             = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	wildflyJavaAssign       = regexp.MustCompile(`^(?:export\s+)?(JAVA_HOME|JAVA)=(.*)$`)
	wildflyProductJar       = regexp.MustCompile(`^wildfly-feature-pack-product-conf-[A-Za-z0-9._-]{1,64}\.jar$`)
	// 製品の JAR は、マニフェストだけが入った小さなもの
	wildflyJarLimits = jarfile.Limits{MaxArchiveSize: 1 << 20, MaxEntries: 256, MaxNameLen: 256, MaxEntrySize: wildflyMaxManifest, MaxRatio: 200}
	// relative-to の名前と、WildFly の置き場所からの相対の場所（起動時にシステムプロパティで変えられていれば、実際と食い違う）
	wildflyRelativeTo = map[string]string{
		"jboss.home.dir":          "",
		"jboss.server.base.dir":   "/standalone",
		"jboss.server.config.dir": wildflyConfigDir,
		"jboss.server.data.dir":   "/standalone/data",
	}
)

// wildflyLaunch は、systemd のユニットから読んだ、WildFly の起動のしかた。
type wildflyLaunch struct {
	unit   unitInfo
	config string // 設定ファイルの名前（指定がなければ空）
	domain bool   // ドメインのモードで起動する
	reason string // 空でなければ、設定ファイルを決められない理由
}

// wildfly は、置かれている WildFly を探し、1 つずつ調べる。
func (c *Collector) wildfly(app ruleset.AppRule) {
	launches := c.wildflyLaunches(app)
	var homes []string
	seen := map[string]bool{}
	add := func(home string) {
		// 同じ場所を指す別の名前（/opt/wildfly → /opt/wildfly-42.0.0.Final のようなリンク）は、1 つにまとめる
		key := home
		if real, err := c.Opener.Resolve(c.Prefix + home); err == nil {
			key = real
		}
		if home == "" || seen[key] || len(homes) >= wildflyMaxHomes {
			return
		}
		seen[key] = true
		homes = append(homes, home)
	}
	var found []string
	for _, p := range app.ConfigFiles {
		for _, f := range c.globDeep(p) {
			if home := strings.TrimSuffix(f, wildflyConfigSuffix); home != f {
				found = append(found, home)
			}
		}
	}
	// ユニットが起動する場所を先に（リンクでまとめるとき、ユニットに書かれた名前を残す）
	for _, home := range found {
		if _, ok := launches[home]; ok {
			add(home)
		}
	}
	for _, home := range found {
		add(home)
	}
	for _, home := range homes {
		l, launched := launches[home]
		c.wildflyHome(app, home, l, launched)
	}
}

// wildflyLaunches は、WildFly を起動するユニットを、置き場所ごとに返す。
// 読めるのは、配布物に付いている形（<置き場所>/bin/launch.sh モード 設定ファイル 待ち受けアドレス）と、standalone.sh / domain.sh を直接起動する形。
func (c *Collector) wildflyLaunches(app ruleset.AppRule) map[string]wildflyLaunch {
	out := map[string]wildflyLaunch{}
	for _, u := range c.units(app) {
		args := c.unitArgs(u)
		if len(args) == 0 {
			continue
		}
		l := wildflyLaunch{unit: u}
		prog := args[0].text
		home := ""
		switch {
		case strings.HasSuffix(prog, "/bin/launch.sh"):
			home = strings.TrimSuffix(prog, "/bin/launch.sh")
			if len(args) > 1 && args[1].text == "domain" {
				l.domain = true
			}
			if len(args) > 2 {
				l.config = args[2].text
			}
		case strings.HasSuffix(prog, "/bin/standalone.sh"):
			home = strings.TrimSuffix(prog, "/bin/standalone.sh")
			for i := 1; i < len(args); i++ {
				a := args[i].text
				switch {
				case (a == "-c" || a == "--server-config") && i+1 < len(args):
					l.config = args[i+1].text
					i++
				case strings.HasPrefix(a, "-c="):
					l.config = strings.TrimPrefix(a, "-c=")
				case strings.HasPrefix(a, "--server-config="):
					l.config = strings.TrimPrefix(a, "--server-config=")
				}
			}
		case strings.HasSuffix(prog, "/bin/domain.sh"):
			home, l.domain = strings.TrimSuffix(prog, "/bin/domain.sh"), true
		default:
			continue
		}
		if !l.domain && l.config != "" && !wildflyConfigName.MatchString(l.config) {
			l.reason = "the configuration file named in " + u.path + " is not a plain file name in standalone/configuration; which file the server is started with is not determined"
		}
		if _, dup := out[home]; !dup && strings.HasPrefix(home, "/") {
			out[home] = l
		}
	}
	return out
}

// wildflyInstall は、1 つの WildFly について、待ち受けによらず決まること。
type wildflyInstall struct {
	app    ruleset.AppRule
	svc    model.Service
	home   string
	config string
	file   *standalonexml.File

	version string
	table   *ruleset.WildFlyTable
	legacy  bool // 古い形式（security-realm）のある版
	prov    *model.Provenance

	jdks    []string // WildFly を動かす JDK の候補
	why     string
	certain bool   // JDK が 1 つに決まっている
	reason  string // 空でなければ、値を求められない理由（どの待ち受けにも共通）
}

func (c *Collector) wildflyHome(app ruleset.AppRule, home string, l wildflyLaunch, launched bool) {
	svc := model.Service{ID: "svc:" + app.ID + ":" + home, App: app.ID, Activity: model.Activity{Level: "unknown"}}
	if launched {
		svc.Activity = c.activity(app, []unitInfo{l.unit}, false, model.Component{})
	}
	if launched && l.domain {
		c.Builder.AddService(svc)
		c.Builder.ServiceNote(svc.ID, "started in domain mode by "+l.unit.path+"; the configuration of domain mode (domain.xml, host.xml) is not read")
		return
	}
	config := home + wildflyConfigSuffix
	if launched && l.reason == "" && l.config != "" {
		config = home + wildflyConfigDir + "/" + l.config
	}
	svc.ConfigFiles = []string{c.Prefix + config}
	c.Builder.AddService(svc)
	data, err := c.read(config)
	if err != nil {
		c.Builder.ServiceNote(svc.ID, "the configuration file "+config+" cannot be read")
		return
	}
	f, err := standalonexml.Parse(data)
	if err != nil {
		c.Builder.Skip(safefs.Skip{Path: c.Prefix + config, Reason: "invalid-value", Detail: "standalone.xml"})
		return
	}
	in := &wildflyInstall{app: app, svc: svc, home: home, config: config, file: f}
	switch {
	case len(f.Problems) > 0:
		in.reason = "the configuration file is not fully read: " + f.Problems[0]
	case launched && l.reason != "":
		in.reason = l.reason
	}
	if in.reason == "" {
		in.version, in.reason = c.wildflyVersion(home)
	}
	if in.reason == "" {
		tb, v, ok := c.Rules.WildFlyFor(in.version)
		if !ok {
			c.Builder.NoteUnmeasured(model.Unmeasured{Kind: wildflyUnmeasured, Name: wildflyUnmeasured, Version: in.version, Status: "missing"})
			in.reason = "no WildFly table is recorded for WildFly " + in.version
		} else {
			in.table, in.legacy = tb, v.LegacyRealm
			in.prov = &model.Provenance{Image: tb.Source.Image, OS: tb.Source.OS, Package: wildflyUnmeasured, Version: in.version}
		}
	}
	if in.reason == "" {
		in.jdks, in.why, in.certain, in.reason = c.wildflyJDKs(home)
	}
	if !launched {
		in.why += ". No unit that starts this WildFly was read, so the configuration file is taken to be standalone.xml (the default)"
	}
	for _, lis := range f.Listeners {
		c.wildflyListener(in, lis)
	}
}

// wildflyVersion は、置かれている WildFly の版を読む。
// 30 までは、製品のマニフェスト（modules/.../org/jboss/as/product/main/dir/META-INF/MANIFEST.MF）、31 以降は、同じディレクトリにある
// 製品の JAR（wildfly-feature-pack-product-conf-<版>.jar）の中のマニフェストに、JBoss-Product-Release-Version として書かれている
// （検証ラボで、19.0.0.Final〜42.0.0.Final の 54 版の配布物で確かめた）。
func (c *Collector) wildflyVersion(home string) (version, reason string) {
	dir := home + wildflyProductDir
	manifest, err := c.read(dir + "/dir/META-INF/MANIFEST.MF")
	if err != nil {
		manifest = nil
		if real, err := c.Opener.Resolve(c.Prefix + dir); err == nil {
			ents, _ := c.Opener.ListNames(real)
			var jars []string
			for _, e := range ents {
				if !e.IsDir && wildflyProductJar.MatchString(e.Name) {
					jars = append(jars, e.Name)
				}
			}
			if len(jars) == 1 {
				manifest = c.wildflyJarManifest(real + "/" + jars[0])
			}
		}
	}
	if len(manifest) > wildflyMaxManifest {
		manifest = nil
	}
	mf := manifestValues(manifest, "JBoss-Product-Release-Name", "JBoss-Product-Release-Version")
	version = mf["JBoss-Product-Release-Version"]
	switch {
	case version == "":
		return "", "the version of this WildFly cannot be read (no product manifest under " + dir + ")"
	case !strings.HasPrefix(mf["JBoss-Product-Release-Name"], "WildFly"):
		return "", "this installation is not WildFly (its product manifest names another product); it is not handled"
	case !wildflyVersionValue.MatchString(version):
		return "", "the version of this WildFly cannot be read (the product manifest has a value in an unexpected form)"
	}
	return version, ""
}

func (c *Collector) wildflyJarManifest(path string) []byte {
	f, err := c.Opener.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	a, err := jarfile.Open(f, f.Size(), wildflyJarLimits)
	if err != nil {
		return nil
	}
	data, err := a.Read("META-INF/MANIFEST.MF")
	if err != nil {
		return nil
	}
	return data
}

// wildflyJDKs は、WildFly を動かす JDK の候補を返す。
//
// standalone.sh は、bin/standalone.conf を取り込んでから、JAVA_HOME の指す Java（なければ PATH の java）で起動する。
// standalone.conf はシェルのスクリプトなので、解釈はしない。行頭に書かれた「JAVA_HOME=絶対パス」が 1 つだけあれば、その JDK とする。
// それ以外（指定がない、条件の中にある、複数ある、JAVA を直接指定している）は、どの JDK かを決めず、見つかった JDK すべてを候補にする
// （呼び出し側は、すべての JDK で同じになる項目だけを確定とする）。
func (c *Collector) wildflyJDKs(home string) (homes []string, why string, certain bool, reason string) {
	conf := home + "/bin/standalone.conf"
	javaHome, unclear := "", false
	if data, err := c.read(conf); err == nil {
		for _, raw := range strings.Split(string(data), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || line[0] == '#' {
				continue
			}
			for _, o := range tomcatRiskyOptions {
				if strings.Contains(line, o) {
					return nil, "", false, conf + " has an option (" + o + "...) that can change the TLS settings of Java; its effect is not interpreted"
				}
			}
			m := wildflyJavaAssign.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			value := strings.TrimSpace(m[2])
			if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
				value = value[1 : len(value)-1]
			}
			plain := strings.HasPrefix(value, "/") && len(value) <= 1024 && !strings.ContainsAny(value, "$`\\\"' \t;&|()<>")
			if m[1] == "JAVA_HOME" && raw == strings.TrimRight(raw, " \t\r") && !strings.HasPrefix(raw, " ") && !strings.HasPrefix(raw, "\t") && plain && javaHome == "" {
				javaHome = value
			} else {
				unclear = true
			}
		}
	}
	if javaHome != "" && !unclear {
		return []string{javaHome}, "the JDK is the one that JAVA_HOME in " + conf + " names (" + javaHome + ")", true, ""
	}
	homes = c.jdkHomes()
	if len(homes) == 0 {
		return nil, "", false, "no JDK is found on this host; which JDK runs WildFly is not determined"
	}
	why = "standalone.sh uses the Java that JAVA_HOME names, or else the java on PATH, and which JDK that is, is not determined"
	if unclear {
		why = conf + " sets JAVA_HOME or JAVA in a way that is not interpreted, so which JDK runs WildFly is not determined"
	}
	why += ". The values are those that are the same with every JDK found on this host (" + strings.Join(homes, ", ") + "). A JDK in a place that is not searched is not considered"
	return homes, why, false, ""
}

// wildflyPlan は、待ち受け 1 つの設定の読み取り結果（JDK によらない部分）。
type wildflyPlan struct {
	elytron bool

	// Elytron の形式
	filter    standalonexml.Attr // cipher-suite-filter
	hasFilter bool
	names     standalonexml.Attr // cipher-suite-names（TLS 1.3 用）
	hasNames  bool

	// どちらの形式でも: プロトコルと、TLS 1.2 以下の暗号スイートが、設定に書かれているか（書かれていれば、その行）
	hasProtocols bool
	protocolsAt  int
	hasSuites    bool
	suitesAt     int

	// Elytron の形式: ssl-context の protocols
	protocols []string

	// 古い形式（security-realm。24 まで）。lab/out/tlsapp/wildfly-legacy の測定による
	contextProtocol   string   // ssl の protocol（TLS の実装の名前）。書かれていなければ空
	realmProtocols    []string // engine の enabled-protocols（書かれたままの名前）
	hasRealmProtocols bool
	realmSuites       []string // engine の enabled-cipher-suites（書かれたままの名前）
	hasRealmSuites    bool
	// 待ち受けの側の指定は、security-realm の側の指定を置き換える
	listenerProtocols    []string // https-listener の enabled-protocols（カンマで区切り、前後の空白を落としたもの）
	hasListenerProtocols bool
	listenerFilter       standalonexml.Attr // https-listener の enabled-cipher-suites（Elytron の式として解釈される）
	hasListenerFilter    bool
}

func wildflyExpression(values ...string) bool {
	for _, v := range values {
		if strings.Contains(v, "${") {
			return true
		}
	}
	return false
}

// wildflyProtocols は、空白区切りのプロトコルの並びを読む。
func wildflyProtocols(value string) ([]string, bool) {
	list := strings.Fields(value)
	if len(list) == 0 || len(list) > 8 {
		return nil, false
	}
	for _, p := range list {
		if !wildflyProtocol.MatchString(p) {
			return nil, false
		}
	}
	return list, true
}

func (c *Collector) wildflyListener(in *wildflyInstall, l standalonexml.Listener) {
	name := l.Attr["name"].Value
	scope := "https-listener at line " + strconv.Itoa(l.Line)
	if wildflyName.MatchString(l.Server) && wildflyName.MatchString(name) {
		scope = "https-listener " + l.Server + "/" + name
	}
	params := []string{model.ParamTLSProtocols, paramCiphers, paramTLS13, model.ParamTLSGroups}
	plan, reason := c.wildflyRead(in, l, scope)
	if in.reason != "" {
		reason = in.reason
	}
	if reason == "" {
		reason = wildflyCheck(in, plan)
	}
	if reason != "" {
		c.unresolved(in.svc, in.app.Direction, scope, reason, params...)
		return
	}
	c.wildflyResolve(in, plan, scope)
}

// wildflyRead は、待ち受け 1 つの設定の記載を記録し、解釈に使う値を返す。解釈できない書き方があれば、reason に理由が入る。
func (c *Collector) wildflyRead(in *wildflyInstall, l standalonexml.Listener, scope string) (plan wildflyPlan, reason string) {
	rec := func(directive, value string, line int, base string) {
		if rule, ok := in.app.Directive(directive); ok && value != "" && !wildflyExpression(value) {
			c.record(in.app, in.svc, rule, value, in.config, line, scope, base)
		}
	}
	recStore := func(path standalonexml.Attr, relativeTo string) {
		sub, known := wildflyRelativeTo[relativeTo]
		switch {
		case relativeTo == "" && strings.HasPrefix(path.Value, "/"):
			rec("key-store", path.Value, path.Line, "")
		case known && !strings.HasPrefix(path.Value, "/"):
			rec("key-store", path.Value, path.Line, in.home+sub)
		}
	}
	context, hasContext := l.Attr["ssl-context"]
	realmName, hasRealm := l.Attr["security-realm"]
	lp, hasLP := l.Attr["enabled-protocols"]
	lc, hasLC := l.Attr["enabled-cipher-suites"]
	note := func(r string) {
		if reason == "" {
			reason = r
		}
	}
	if wildflyExpression(context.Value, realmName.Value, lp.Value, lc.Value) {
		note("an attribute of the https-listener is written as an expression (${...}); its value is decided when the server starts")
	}
	switch {
	case hasContext && hasRealm:
		note("the https-listener names both an ssl-context and a security-realm")
	case !hasContext && !hasRealm:
		note("the https-listener names neither an ssl-context nor a security-realm")
	case hasContext:
		plan.elytron = true
		if hasLP {
			note("enabled-protocols on the https-listener cannot be combined with an ssl-context (the server refused this configuration when measured)")
		} else if hasLC {
			note("enabled-cipher-suites on the https-listener cannot be combined with an ssl-context (the server refused this configuration when measured)")
		}
		var ctx *standalonexml.Element
		for i := range in.file.SSLContexts {
			if in.file.SSLContexts[i].Attr["name"].Value == context.Value {
				ctx = &in.file.SSLContexts[i]
				break
			}
		}
		if ctx == nil {
			for _, sni := range in.file.SNIContexts {
				if sni == context.Value {
					note("the https-listener uses a server-ssl-sni-context (the context is chosen by the server name), which has not been measured")
				}
			}
			note("the ssl-context named by the https-listener is not found in the configuration file")
			return plan, reason
		}
		a := ctx.Attr
		plan.filter, plan.hasFilter = a["cipher-suite-filter"], a["cipher-suite-filter"].Value != ""
		plan.names, plan.hasNames = a["cipher-suite-names"], a["cipher-suite-names"].Value != ""
		protocols, hasProtocols := a["protocols"]
		if wildflyExpression(plan.filter.Value, plan.names.Value, protocols.Value, a["providers"].Value, a["provider-name"].Value, a["key-manager"].Value) {
			note("an attribute of the ssl-context is written as an expression (${...}); its value is decided when the server starts")
		}
		// 記載を記録する。暗号の指定の区切りは「:」に揃える（Elytron は「,」と「:」を同じに扱う）
		rec("cipher-suite-filter", strings.ReplaceAll(plan.filter.Value, ",", ":"), plan.filter.Line, "")
		rec("cipher-suite-names", plan.names.Value, plan.names.Line, "")
		if hasProtocols {
			plan.hasProtocols, plan.protocolsAt = true, protocols.Line
			var ok bool
			if plan.protocols, ok = wildflyProtocols(protocols.Value); ok {
				rec("protocols", strings.Join(plan.protocols, " "), protocols.Line, "")
			} else {
				note("the value of protocols on the ssl-context is not interpreted")
			}
		}
		if a["providers"].Value != "" || a["provider-name"].Value != "" {
			note("the ssl-context sets providers or provider-name (a TLS implementation other than the JDK's default), which has not been measured (with providers=openssl the server did not start)")
		}
		for _, km := range in.file.KeyManagers {
			if km.Attr["name"].Value != a["key-manager"].Value || a["key-manager"].Value == "" {
				continue
			}
			for _, ks := range in.file.KeyStores {
				if ks.Name == km.Attr["key-store"].Value && ks.Path.Value != "" {
					recStore(ks.Path, ks.RelativeTo)
				}
			}
		}
	default:
		var realm *standalonexml.Realm
		for i := range in.file.Realms {
			if in.file.Realms[i].Name == realmName.Value {
				realm = &in.file.Realms[i]
				break
			}
		}
		if realm == nil || !realm.HasSSL {
			note("the security-realm named by the https-listener has no ssl element in the configuration file")
			return plan, reason
		}
		ep, hasEP := realm.Engine["enabled-protocols"]
		ec, hasEC := realm.Engine["enabled-cipher-suites"]
		if wildflyExpression(realm.SSL["protocol"].Value, ep.Value, ec.Value) {
			note("an attribute of the security-realm is written as an expression (${...}); its value is decided when the server starts")
		}
		// ssl の protocol は、TLS の実装（SSLContext）の名前。測った 5 つの値では、受け入れるものを変えなかった。
		// JDK にない名前では、サーバーが起動しなかった（その JDK にあるかどうかは、wildflyWith で確かめる）
		if p, ok := realm.SSL["protocol"]; ok {
			if !wildflyContextProtocols[p.Value] {
				note("the ssl element of the security-realm sets protocol to a value that has not been measured (with a name the JDK does not have, the server did not start)")
			}
			plan.contextProtocol = p.Value
		}
		// security-realm の側（engine）。JDK の知らない名前は落ちる（wildflyWith）
		list := func(value string, max int) ([]string, bool) {
			l := strings.Fields(value)
			return l, len(l) > 0 && len(l) <= max
		}
		if hasEP {
			plan.hasProtocols, plan.protocolsAt, plan.hasRealmProtocols = true, ep.Line, true
			var ok bool
			if plan.realmProtocols, ok = list(ep.Value, 16); ok {
				rec("enabled-protocols", strings.Join(plan.realmProtocols, " "), ep.Line, "")
			} else {
				note("the value of enabled-protocols in the security-realm is not interpreted")
			}
		}
		if hasEC {
			plan.hasSuites, plan.suitesAt, plan.hasRealmSuites = true, ec.Line, true
			var ok bool
			if plan.realmSuites, ok = list(ec.Value, 256); ok {
				rec("enabled-cipher-suites", strings.Join(plan.realmSuites, " "), ec.Line, "")
			} else {
				note("the value of enabled-cipher-suites in the security-realm is not interpreted")
			}
		}
		// 待ち受けの側。書かれていれば、security-realm の側の指定を置き換える（実測。共通部分ではない）
		if hasLP {
			plan.hasProtocols, plan.protocolsAt, plan.hasListenerProtocols = true, lp.Line, true
			// カンマで区切り、前後の空白を落とす（空白は区切りではない）
			for _, v := range strings.Split(lp.Value, ",") {
				plan.listenerProtocols = append(plan.listenerProtocols, strings.TrimSpace(v))
			}
			if strings.TrimSpace(lp.Value) == "" || len(plan.listenerProtocols) > 16 {
				note("the value of enabled-protocols on the https-listener is not interpreted")
			} else {
				rec("enabled-protocols", strings.Join(plan.listenerProtocols, " "), lp.Line, "")
			}
		}
		if hasLC {
			plan.hasSuites, plan.suitesAt, plan.hasListenerFilter, plan.listenerFilter = true, lc.Line, true, lc
			if strings.TrimSpace(lc.Value) == "" {
				note("the value of enabled-cipher-suites on the https-listener is not interpreted")
			} else {
				rec("enabled-cipher-suites", lc.Value, lc.Line, "")
			}
		}
		if p, ok := realm.Keystore["path"]; ok {
			recStore(p, realm.Keystore["relative-to"].Value)
		}
	}
	return plan, reason
}

// wildflyCheck は、表を使って確かめること（その版にある形式か、Elytron が受け付ける指定か）。
func wildflyCheck(in *wildflyInstall, plan wildflyPlan) string {
	if !plan.elytron {
		if !in.legacy {
			return "the https-listener names a security-realm, but WildFly " + in.version + " does not take TLS settings from a security-realm (that form ended with WildFly 24)"
		}
		if plan.hasListenerFilter {
			if _, err := elytronciphers.Evaluate(in.table, plan.listenerFilter.Value, nil); err != nil {
				return "the enabled-cipher-suites value on the https-listener is not accepted by Elytron's rules (as measured, the server does not start with it), or is not interpreted here"
			}
		}
		return ""
	}
	if plan.hasFilter {
		if _, err := elytronciphers.Evaluate(in.table, plan.filter.Value, nil); err != nil {
			return "the cipher-suite-filter value is not accepted by Elytron's rules (the server does not start with it), or is not interpreted here"
		}
	}
	if plan.hasNames {
		if _, err := elytronciphers.EvaluateNames(in.table, plan.names.Value, nil); err != nil {
			return "the cipher-suite-names value is not accepted by Elytron's rules (the server does not start with it), or is not interpreted here"
		}
	}
	return ""
}

// wildflyResult は、JDK 1 つでの結果。
type wildflyResult struct {
	jdk    jdkContext
	home   string
	reason string

	protocols, tls12, tls13, groups []string
	groupsBlocker                   string
}

// wildflyWith は、その JDK で受け入れるものを求める。
func wildflyWith(in *wildflyInstall, plan wildflyPlan, jdk jdkContext) (res wildflyResult) {
	tb := in.table
	var want, protocols []string
	if plan.elytron {
		supported := make([]string, 0, len(jdk.table.Suites))
		for _, s := range jdk.table.Suites {
			supported = append(supported, s.Name)
		}
		filter := tb.DefaultCipherSuiteFilter
		if plan.hasFilter {
			filter = plan.filter.Value
		}
		// 式が受け付けられることは、先に確かめてある
		want, _ = elytronciphers.Evaluate(tb, filter, supported)
		protocols = append([]string{}, tb.DefaultProtocols...)
		if plan.hasNames {
			tls13, _ := elytronciphers.EvaluateNames(tb, plan.names.Value, supported)
			want = append(want, tls13...)
			// TLS 1.3 は、TLS 1.3 用の指定（cipher-suite-names）を書いたときだけ受け入れる（実測）
			if tb.TLS13RequiresCipherSuiteNames {
				protocols = append(protocols, "TLSv1.3")
			}
		}
		if plan.hasProtocols {
			protocols = plan.protocols
		}
	} else {
		if res.reason = wildflyLegacy(tb, plan, jdk, &protocols, &want); res.reason != "" {
			return res
		}
	}
	r := jsse.ResolveExplicit(jdk.table, jdk.input, protocols, want)
	// キーストアの中は読まないので、RSA の証明書の場合と EC の証明書の場合を合わせた一覧にする
	res.tls12, res.tls13 = jsse.SplitByCertificate(r.Suites, nil)
	// 使える暗号スイートのないプロトコルは、受け入れない（実測: プロトコルを TLS 1.3 だけにして TLS 1.3 用の指定を書かないと、何も受け入れない）
	for _, p := range r.Protocols {
		if (p == "TLSv1.3" && len(res.tls13) > 0) || (p != "TLSv1.3" && len(res.tls12) > 0) {
			res.protocols = append(res.protocols, p)
		}
	}
	// グループは、それを使うスイートが残っているときだけ受け入れる
	used := jsse.Result{}
	if len(res.tls13) > 0 {
		used.Groups13 = r.Groups13
	}
	for _, s := range res.tls12 {
		if strings.Contains(s, "_ECDHE_") {
			used.Groups12 = r.Groups12
			break
		}
	}
	res.groups, res.groupsBlocker = jsseGroups(used), r.GroupsBlocker
	return res
}

// wildflyLegacy は、古い形式（security-realm）で、有効にされるプロトコルと暗号スイートを求める（JDK が無効にしているものを除く前）。
// 値を求められない場合は、理由を返す。決まりは、19.0.0〜24.0.1 の 14 版の測定による（lab/out/tlsapp/wildfly-legacy）。
func wildflyLegacy(tb *ruleset.WildFlyTable, plan wildflyPlan, jdk jdkContext, protocols, want *[]string) (reason string) {
	hasProtocol, hasSuite := map[string]bool{}, map[string]bool{}
	supported := make([]string, 0, len(jdk.table.Suites))
	for _, p := range jdk.table.Protocols {
		hasProtocol[p.Name] = true
	}
	for _, s := range jdk.table.Suites {
		hasSuite[s.Name] = true
		supported = append(supported, s.Name)
	}
	keep := func(names []string, known map[string]bool) []string {
		out := []string{}
		for _, n := range names {
			if known[n] {
				out = append(out, n)
			}
		}
		return out
	}
	// ssl の protocol: その JDK にない名前では、サーバーが起動しない
	if cp := plan.contextProtocol; cp != "" && cp != "TLS" && !hasProtocol[cp] {
		return "the ssl element of the security-realm sets protocol to " + cp + ", which this JDK does not have (as measured, the server does not start with a name the JDK does not have)"
	}
	// security-realm の側。書かれた名前のうち、JDK が知っているものだけが残る。1 つも残らない場合は、キーストアによって結果が違う
	const none = ": as measured, the server does not start when the keystore exists, and applies no restriction at all when the certificate is generated on first use"
	*protocols = append([]string{}, tb.LegacyDefaultProtocols...)
	if plan.hasRealmProtocols {
		if *protocols = keep(plan.realmProtocols, hasProtocol); len(*protocols) == 0 {
			return "none of the enabled-protocols in the security-realm is a protocol of this JDK" + none
		}
	}
	// 名指しがなければ、JDK の既定の暗号スイート
	*want = nil
	for _, s := range jdk.table.Suites {
		if s.Default {
			*want = append(*want, s.Name)
		}
	}
	if plan.hasRealmSuites {
		if *want = keep(plan.realmSuites, hasSuite); len(*want) == 0 {
			return "none of the enabled-cipher-suites in the security-realm is a cipher suite of this JDK" + none
		}
	}
	// 待ち受けの側の指定は、security-realm の側の指定を置き換える。JDK の知らないプロトコルは落ち、1 つも残らなければ、何も受け入れない
	if plan.hasListenerProtocols {
		*protocols = keep(plan.listenerProtocols, hasProtocol)
	}
	// 暗号は、Elytron の式として、JDK が対応しているスイートの中から選ばれる（式が受け付けられることは、先に確かめてある）
	if plan.hasListenerFilter {
		*want, _ = elytronciphers.Evaluate(tb, plan.listenerFilter.Value, supported)
	}
	return ""
}

// wildflyResolve は、待ち受け 1 つについて、受け入れるプロトコル・暗号スイート・グループを求めて記録する。
// JDK が 1 つに決まっていなければ、見つかった JDK すべてで求め、同じになった項目だけを確定とする。
func (c *Collector) wildflyResolve(in *wildflyInstall, plan wildflyPlan, scope string) {
	var results []wildflyResult
	for _, h := range in.jdks {
		jdk, dir, reason := c.javaHomeJDK(in.svc, h, "WildFly")
		res := wildflyResult{reason: reason}
		if reason == "" {
			res = wildflyWith(in, plan, jdk)
		}
		res.jdk, res.home = jdk, dir
		if res.home == "" {
			res.home = h
		}
		results = append(results, res)
	}
	// JDK を 1 つに決められない場合は、見つけた JDK のどれでも同じ値になった項目だけを出す（そのことでは、確度を下げない）
	var anyJDK []string
	if !in.certain {
		anyJDK = []string{model.QualifierAnyJDKFound}
	}
	wildflyRule := ruleOf(in.table.Source, "", true) // WildFly の表は、その版そのもののものだけを使う
	notes := []string{
		"WildFly " + in.version + ", on the JDK's TLS implementation (JSSE): " + in.why,
		"not read: system properties given when the server is started (they can change values written as expressions, and the settings of Java) and the management interface",
	}
	emit := func(param string, pick func(wildflyResult) []string, steps func(jdkContext) []model.ResolutionStep, qualifiers []string, blocker func(wildflyResult) string, extra ...string) {
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
				c.unresolved(in.svc, in.app.Direction, scope, reason, param)
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
				c.unresolved(in.svc, in.app.Direction, scope, "the result differs between the JDKs found on this host, and it is not known which one runs WildFly ("+strings.Join(parts, "; ")+")", param)
				return
			}
		}
		if agreed == nil {
			agreed = []string{}
		}
		jdk := results[0].jdk
		// 確度の材料: WildFly の表と、候補の JDK それぞれの表（最も低いものになる）
		rules := []confidence.Rule{wildflyRule}
		for _, res := range results {
			rules = append(rules, res.jdk.suites)
			if param == model.ParamTLSGroups {
				rules = append(rules, res.jdk.groups)
			}
		}
		q := append(append([]string{}, anyJDK...), qualifiers...)
		if param == model.ParamTLSProtocols && len(agreed) == 0 {
			q = append(q, model.QualifierNothingAccepted) // どのプロトコルも受け入れない設定
		}
		c.Builder.AddEffective(model.EffectiveValue{Service: in.svc.ID, Parameter: param, Direction: in.app.Direction, Scope: scope,
			Status: model.StatusResolved, Values: agreed, Qualifiers: q, Steps: steps(jdk),
			Notes: append(append(append([]string{}, notes...), jdk.notes...), extra...)}, rules...)
	}
	appDefault := model.ResolutionStep{Layer: "app-default", Op: "default", Source: in.prov}
	configured := func(param string, line int) model.ResolutionStep {
		return model.ResolutionStep{Layer: "app-config", Op: "override", Setting: c.settingAt(in.svc, param, in.config, line)}
	}
	through := func(first model.ResolutionStep) func(jdkContext) []model.ResolutionStep {
		return func(jdk jdkContext) []model.ResolutionStep {
			return []model.ResolutionStep{first, {Layer: "library", Op: "intersect", Source: jdk.prov}, {Layer: jdk.layer, Op: "remove", Setting: jdk.settingID}}
		}
	}

	// プロトコル
	first := appDefault
	if plan.hasProtocols {
		first = configured(model.ParamTLSProtocols, plan.protocolsAt)
	}
	emit(model.ParamTLSProtocols, func(r wildflyResult) []string { return r.protocols }, through(first), nil, nil)

	// TLS 1.2 以下の暗号スイート。キーストアの中は読まないので、証明書の種類では絞り込まない
	first = appDefault
	switch {
	case plan.elytron && plan.hasFilter:
		first = configured(paramCiphers, plan.filter.Line)
	case plan.hasSuites:
		first = configured(paramCiphers, plan.suitesAt)
	}
	emit(paramCiphers, func(r wildflyResult) []string { return r.tls12 }, through(first), []string{model.QualifierAnyCertificateKind}, nil,
		"the kind of the server certificate is not known (the contents of a keystore are not read), so the suites usable with an RSA certificate and those usable with an EC certificate are listed together; "+
			"suites that need a kind of certificate the server does not have are not usable")

	// TLS 1.3 の暗号スイート
	first = appDefault
	var extra []string
	switch {
	case plan.elytron && plan.hasNames:
		first = configured(paramTLS13, plan.names.Line)
	case plan.elytron:
		extra = []string{"TLS 1.3 is accepted only when cipher-suite-names is set on the ssl-context (measured); it is not set"}
	}
	emit(paramTLS13, func(r wildflyResult) []string { return r.tls13 }, through(first), nil, nil, extra...)

	// 鍵交換のグループ（JDK の既定のまま）
	emit(model.ParamTLSGroups, func(r wildflyResult) []string { return r.groups }, func(jdk jdkContext) []model.ResolutionStep {
		return []model.ResolutionStep{{Layer: "library", Op: "default", Source: jdk.prov}, {Layer: jdk.layer, Op: "remove", Setting: jdk.settingID}}
	}, nil, func(r wildflyResult) string { return r.groupsBlocker })
}
