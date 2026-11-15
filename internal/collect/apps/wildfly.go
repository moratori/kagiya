package apps

import (
	"regexp"
	"strconv"
	"strings"

	"kagiya/internal/confidence"
	"kagiya/internal/elytronciphers"
	"kagiya/internal/jsse"
	"kagiya/internal/model"
	"kagiya/internal/parse/standalonexml"
	"kagiya/internal/ruleset"
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
//
// 置かれている WildFly を探し、版・設定ファイル・動かす JDK を決める部分は、wildfly_install.go にある。

var (
	// 古い形式の ssl の protocol で、測った値（TLS の実装の名前）
	wildflyContextProtocols = map[string]bool{"TLS": true, "TLSv1": true, "TLSv1.1": true, "TLSv1.2": true, "TLSv1.3": true}
	wildflyProtocol         = regexp.MustCompile(`^(SSLv2Hello|SSLv[23]|TLSv1(\.[123])?)$`)
	wildflyName             = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	// relative-to の名前と、WildFly の置き場所からの相対の場所（起動時にシステムプロパティで変えられていれば、実際と食い違う）
	wildflyRelativeTo = map[string]string{
		"jboss.home.dir":          "",
		"jboss.server.base.dir":   "/standalone",
		"jboss.server.config.dir": wildflyConfigDir,
		"jboss.server.data.dir":   "/standalone/data",
	}
)

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

// wildflyReader は、待ち受け 1 つの設定の記載を読む間の状態。
type wildflyReader struct {
	c      *Collector
	in     *wildflyInstall
	scope  string
	plan   wildflyPlan
	reason string // 解釈できない書き方があれば、最初に見つかった理由
}

func (r *wildflyReader) note(reason string) {
	if r.reason == "" {
		r.reason = reason
	}
}

// rec は、設定の記載を記録する（式で書かれた値は、起動時に決まるので記録しない）。
func (r *wildflyReader) rec(directive, value string, line int, base string) {
	if rule, ok := r.in.app.Directive(directive); ok && value != "" && !wildflyExpression(value) {
		r.c.record(r.in.app, r.in.svc, rule, value, r.in.config, line, r.scope, base)
	}
}

// recStore は、キーストアの場所を記録する（場所の基準が分かる場合だけ）。
func (r *wildflyReader) recStore(path standalonexml.Attr, relativeTo string) {
	sub, known := wildflyRelativeTo[relativeTo]
	switch {
	case relativeTo == "" && strings.HasPrefix(path.Value, "/"):
		r.rec("key-store", path.Value, path.Line, "")
	case known && !strings.HasPrefix(path.Value, "/"):
		r.rec("key-store", path.Value, path.Line, r.in.home+sub)
	}
}

// wildflyRead は、待ち受け 1 つの設定の記載を記録し、解釈に使う値を返す。解釈できない書き方があれば、reason に理由が入る。
func (c *Collector) wildflyRead(in *wildflyInstall, l standalonexml.Listener, scope string) (plan wildflyPlan, reason string) {
	r := &wildflyReader{c: c, in: in, scope: scope}
	context, hasContext := l.Attr["ssl-context"]
	realmName, hasRealm := l.Attr["security-realm"]
	if wildflyExpression(context.Value, realmName.Value, l.Attr["enabled-protocols"].Value, l.Attr["enabled-cipher-suites"].Value) {
		r.note("an attribute of the https-listener is written as an expression (${...}); its value is decided when the server starts")
	}
	switch {
	case hasContext && hasRealm:
		r.note("the https-listener names both an ssl-context and a security-realm")
	case !hasContext && !hasRealm:
		r.note("the https-listener names neither an ssl-context nor a security-realm")
	case hasContext:
		r.elytron(l, context)
	default:
		r.legacy(l, realmName)
	}
	return r.plan, r.reason
}

// elytron は、いまの形式（https-listener が、Elytron の server-ssl-context を指す）の記載を読む。
func (r *wildflyReader) elytron(l standalonexml.Listener, context standalonexml.Attr) {
	_, hasLP := l.Attr["enabled-protocols"]
	_, hasLC := l.Attr["enabled-cipher-suites"]
	r.plan.elytron = true
	if hasLP {
		r.note("enabled-protocols on the https-listener cannot be combined with an ssl-context (the server refused this configuration when measured)")
	} else if hasLC {
		r.note("enabled-cipher-suites on the https-listener cannot be combined with an ssl-context (the server refused this configuration when measured)")
	}
	var ctx *standalonexml.Element
	for i := range r.in.file.SSLContexts {
		if r.in.file.SSLContexts[i].Attr["name"].Value == context.Value {
			ctx = &r.in.file.SSLContexts[i]
			break
		}
	}
	if ctx == nil {
		for _, sni := range r.in.file.SNIContexts {
			if sni == context.Value {
				r.note("the https-listener uses a server-ssl-sni-context (the context is chosen by the server name), which has not been measured")
			}
		}
		r.note("the ssl-context named by the https-listener is not found in the configuration file")
		return
	}
	a := ctx.Attr
	r.plan.filter, r.plan.hasFilter = a["cipher-suite-filter"], a["cipher-suite-filter"].Value != ""
	r.plan.names, r.plan.hasNames = a["cipher-suite-names"], a["cipher-suite-names"].Value != ""
	protocols, hasProtocols := a["protocols"]
	if wildflyExpression(r.plan.filter.Value, r.plan.names.Value, protocols.Value, a["providers"].Value, a["provider-name"].Value, a["key-manager"].Value) {
		r.note("an attribute of the ssl-context is written as an expression (${...}); its value is decided when the server starts")
	}
	// 記載を記録する。暗号の指定の区切りは「:」に揃える（Elytron は「,」と「:」を同じに扱う）
	r.rec("cipher-suite-filter", strings.ReplaceAll(r.plan.filter.Value, ",", ":"), r.plan.filter.Line, "")
	r.rec("cipher-suite-names", r.plan.names.Value, r.plan.names.Line, "")
	if hasProtocols {
		r.plan.hasProtocols, r.plan.protocolsAt = true, protocols.Line
		var ok bool
		if r.plan.protocols, ok = wildflyProtocols(protocols.Value); ok {
			r.rec("protocols", strings.Join(r.plan.protocols, " "), protocols.Line, "")
		} else {
			r.note("the value of protocols on the ssl-context is not interpreted")
		}
	}
	if a["providers"].Value != "" || a["provider-name"].Value != "" {
		r.note("the ssl-context sets providers or provider-name (a TLS implementation other than the JDK's default), which has not been measured (with providers=openssl the server did not start)")
	}
	for _, km := range r.in.file.KeyManagers {
		if km.Attr["name"].Value != a["key-manager"].Value || a["key-manager"].Value == "" {
			continue
		}
		for _, ks := range r.in.file.KeyStores {
			if ks.Name == km.Attr["key-store"].Value && ks.Path.Value != "" {
				r.recStore(ks.Path, ks.RelativeTo)
			}
		}
	}
}

// legacy は、古い形式（https-listener が、security-realm を指す。WildFly 24 まで）の記載を読む。
func (r *wildflyReader) legacy(l standalonexml.Listener, realmName standalonexml.Attr) {
	lp, hasLP := l.Attr["enabled-protocols"]
	lc, hasLC := l.Attr["enabled-cipher-suites"]
	var realm *standalonexml.Realm
	for i := range r.in.file.Realms {
		if r.in.file.Realms[i].Name == realmName.Value {
			realm = &r.in.file.Realms[i]
			break
		}
	}
	if realm == nil || !realm.HasSSL {
		r.note("the security-realm named by the https-listener has no ssl element in the configuration file")
		return
	}
	ep, hasEP := realm.Engine["enabled-protocols"]
	ec, hasEC := realm.Engine["enabled-cipher-suites"]
	if wildflyExpression(realm.SSL["protocol"].Value, ep.Value, ec.Value) {
		r.note("an attribute of the security-realm is written as an expression (${...}); its value is decided when the server starts")
	}
	// ssl の protocol は、TLS の実装（SSLContext）の名前。測った 5 つの値では、受け入れるものを変えなかった。
	// JDK にない名前では、サーバーが起動しなかった（その JDK にあるかどうかは、wildflyWith で確かめる）
	if p, ok := realm.SSL["protocol"]; ok {
		if !wildflyContextProtocols[p.Value] {
			r.note("the ssl element of the security-realm sets protocol to a value that has not been measured (with a name the JDK does not have, the server did not start)")
		}
		r.plan.contextProtocol = p.Value
	}
	// security-realm の側（engine）。JDK の知らない名前は落ちる（wildflyWith）
	list := func(value string, max int) ([]string, bool) {
		l := strings.Fields(value)
		return l, len(l) > 0 && len(l) <= max
	}
	if hasEP {
		r.plan.hasProtocols, r.plan.protocolsAt, r.plan.hasRealmProtocols = true, ep.Line, true
		var ok bool
		if r.plan.realmProtocols, ok = list(ep.Value, 16); ok {
			r.rec("enabled-protocols", strings.Join(r.plan.realmProtocols, " "), ep.Line, "")
		} else {
			r.note("the value of enabled-protocols in the security-realm is not interpreted")
		}
	}
	if hasEC {
		r.plan.hasSuites, r.plan.suitesAt, r.plan.hasRealmSuites = true, ec.Line, true
		var ok bool
		if r.plan.realmSuites, ok = list(ec.Value, 256); ok {
			r.rec("enabled-cipher-suites", strings.Join(r.plan.realmSuites, " "), ec.Line, "")
		} else {
			r.note("the value of enabled-cipher-suites in the security-realm is not interpreted")
		}
	}
	// 待ち受けの側。書かれていれば、security-realm の側の指定を置き換える（実測。共通部分ではない）
	if hasLP {
		r.plan.hasProtocols, r.plan.protocolsAt, r.plan.hasListenerProtocols = true, lp.Line, true
		// カンマで区切り、前後の空白を落とす（空白は区切りではない）
		for _, v := range strings.Split(lp.Value, ",") {
			r.plan.listenerProtocols = append(r.plan.listenerProtocols, strings.TrimSpace(v))
		}
		if strings.TrimSpace(lp.Value) == "" || len(r.plan.listenerProtocols) > 16 {
			r.note("the value of enabled-protocols on the https-listener is not interpreted")
		} else {
			r.rec("enabled-protocols", strings.Join(r.plan.listenerProtocols, " "), lp.Line, "")
		}
	}
	if hasLC {
		r.plan.hasSuites, r.plan.suitesAt, r.plan.hasListenerFilter, r.plan.listenerFilter = true, lc.Line, true, lc
		if strings.TrimSpace(lc.Value) == "" {
			r.note("the value of enabled-cipher-suites on the https-listener is not interpreted")
		} else {
			r.rec("enabled-cipher-suites", lc.Value, lc.Line, "")
		}
	}
	if p, ok := realm.Keystore["path"]; ok {
		r.recStore(p, realm.Keystore["relative-to"].Value)
	}
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
	// 設定で有効にされるプロトコルと暗号スイート（JDK が無効にしているものを除く前）
	var want, protocols []string
	if plan.elytron {
		protocols, want = wildflyElytron(in.table, plan, jdk)
	} else if protocols, want, res.reason = wildflyLegacy(in.table, plan, jdk); res.reason != "" {
		return res
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

// wildflyElytron は、いまの形式（Elytron の server-ssl-context）で、有効にされるプロトコルと暗号スイートを求める（JDK が無効にしているものを除く前）。
// 式が Elytron に受け付けられることは、先に確かめてある（wildflyCheck）。
func wildflyElytron(tb *ruleset.WildFlyTable, plan wildflyPlan, jdk jdkContext) (protocols, want []string) {
	supported := make([]string, 0, len(jdk.table.Suites))
	for _, s := range jdk.table.Suites {
		supported = append(supported, s.Name)
	}
	filter := tb.DefaultCipherSuiteFilter
	if plan.hasFilter {
		filter = plan.filter.Value
	}
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
	return protocols, want
}

// wildflyLegacy は、古い形式（security-realm）で、有効にされるプロトコルと暗号スイートを求める（JDK が無効にしているものを除く前）。
// 値を求められない場合は、理由を返す。決まりは、19.0.0〜24.0.1 の 14 版の測定による（lab/out/tlsapp/wildfly-legacy）。
func wildflyLegacy(tb *ruleset.WildFlyTable, plan wildflyPlan, jdk jdkContext) (protocols, want []string, reason string) {
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
		return nil, nil, "the ssl element of the security-realm sets protocol to " + cp + ", which this JDK does not have (as measured, the server does not start with a name the JDK does not have)"
	}
	// security-realm の側。書かれた名前のうち、JDK が知っているものだけが残る。1 つも残らない場合は、キーストアによって結果が違う
	const none = ": as measured, the server does not start when the keystore exists, and applies no restriction at all when the certificate is generated on first use"
	protocols = append([]string{}, tb.LegacyDefaultProtocols...)
	if plan.hasRealmProtocols {
		if protocols = keep(plan.realmProtocols, hasProtocol); len(protocols) == 0 {
			return nil, nil, "none of the enabled-protocols in the security-realm is a protocol of this JDK" + none
		}
	}
	// 名指しがなければ、JDK の既定の暗号スイート
	for _, s := range jdk.table.Suites {
		if s.Default {
			want = append(want, s.Name)
		}
	}
	if plan.hasRealmSuites {
		if want = keep(plan.realmSuites, hasSuite); len(want) == 0 {
			return nil, nil, "none of the enabled-cipher-suites in the security-realm is a cipher suite of this JDK" + none
		}
	}
	// 待ち受けの側の指定は、security-realm の側の指定を置き換える。JDK の知らないプロトコルは落ち、1 つも残らなければ、何も受け入れない
	if plan.hasListenerProtocols {
		protocols = keep(plan.listenerProtocols, hasProtocol)
	}
	// 暗号は、Elytron の式として、JDK が対応しているスイートの中から選ばれる（式が受け付けられることは、先に確かめてある）
	if plan.hasListenerFilter {
		want, _ = elytronciphers.Evaluate(tb, plan.listenerFilter.Value, supported)
	}
	return protocols, want, ""
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
