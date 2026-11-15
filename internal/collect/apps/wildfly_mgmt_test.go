package apps

import (
	"strings"
	"testing"

	"kagiya/internal/model"
)

// WildFly の管理用の待ち受け（management-interfaces の http-interface。TLS のポートは、既定では 9993）。
// 場面の名前（m-...）は、検証ラボの測定（lab/out/tlsapp/wildfly-mgmt。lab/phase2/wildfly-mgmt-scenes.sh）のもの。
//
// TLS で待ち受けるのは、http-interface に、TLS の設定（ssl-context。24 までは security-realm の ssl も）と、TLS 用のソケット
// （socket-binding の https）の両方があるときだけ（開発元のソース wildfly-core の HttpManagementAddHandler / ManagementHttpServer と、実測）。

// wfMgmt は、standalone.xml に、管理用の待ち受け（management-interfaces の中身）を足す。
func wfMgmt(xml, interfaces string) string {
	block := "        <management-interfaces>\n            " + interfaces + "\n        </management-interfaces>\n"
	if strings.Contains(xml, "    </management>\n") {
		return strings.Replace(xml, "    </management>\n", block+"    </management>\n", 1)
	}
	return strings.Replace(xml, "    <profile>\n", "    <management>\n"+block+"    </management>\n    <profile>\n", 1)
}

// wfHTTPInterface は、http-interface を組み立てる（attrs は追加の属性、binding は socket-binding の属性）。
func wfHTTPInterface(attrs, binding string) string {
	return `<http-interface http-authentication-factory="management-http-authentication" ` + attrs + `>
                <http-upgrade enabled="true" sasl-authentication-factory="management-sasl-authentication"/>
                <socket-binding ` + binding + `/>
            </http-interface>`
}

const wfBothSockets = `http="management-http" https="management-https"`

func wfMgmtEff(t *testing.T, inv *model.Inventory, param string) model.EffectiveValue {
	t.Helper()
	return eff(t, inv, "svc:wildfly:"+wfHome, param, wfMgmtScope)
}

// wfMgmtCount は、管理用の待ち受けについて記録されたもの（値と「不明」、設定の記載）の数を返す。
func wfMgmtCount(inv *model.Inventory) (effective, settings int) {
	for _, e := range inv.EffectiveValues {
		if strings.HasPrefix(e.Scope, "management ") {
			effective++
		}
	}
	for _, s := range inv.Settings {
		if strings.HasPrefix(s.Scope, "management ") {
			settings++
		}
	}
	return effective, settings
}

func wfMgmtUnresolved(t *testing.T, name string, inv *model.Inventory, scope, want string) {
	t.Helper()
	for _, p := range []string{"tls.protocols", "tls.ciphers", "tls.ciphersuites-tls13", "tls.groups"} {
		e := eff(t, inv, "svc:wildfly:"+wfHome, p, scope)
		if e.Status != "unresolved" || !strings.Contains(e.Reason, want) || len(e.Values) != 0 {
			t.Errorf("%s: %s: status=%s reason=%q values=%d, want unresolved with %q", name, p, e.Status, e.Reason, len(e.Values), want)
		}
	}
}

// TLS で待ち受けない設定では、管理用の待ち受けについて、何も出さない（値も「不明」も）。アプリ用の待ち受けの結果は、変わらない。
func TestWildFlyManagementWithoutTLS(t *testing.T) {
	base := wfElytron("", `ssl-context="labSSC"`)
	for name, xml := range map[string]string{
		// 場面 m-default: 配布物のままの設定
		"the default": wfMgmt(base, wfHTTPInterface("", `http="management-http"`)),
		// 場面 m-e-nobinding: TLS の設定はあるが、TLS 用のソケットがない（9993 は開かなかった）
		"an ssl-context without a socket for TLS": wfMgmt(base, wfHTTPInterface(`ssl-context="labSSC"`, `http="management-http"`)),
		// native-interface に、TLS の設定がない
		"a native-interface without TLS settings": wfMgmt(base, wfHTTPInterface("", `http="management-http"`)+`
            <native-interface sasl-authentication-factory="management-sasl-authentication"><socket-binding native="management-native"/></native-interface>`),
	} {
		_, inv := collect(t, "", wfHost(t, "42.0.0.Final", xml, nil))
		if n, s := wfMgmtCount(inv); n != 0 || s != 0 {
			t.Errorf("%s: %d effective values and %d settings are recorded for the management interface, want none", name, n, s)
		}
		wfCheck(t, wfEff(t, inv, "tls.ciphers"), "high", "RSA", 14, wfRSA12)
	}
	// 測っていない版でも、TLS で待ち受けない設定なら、管理用の待ち受けについては何も出さない
	_, inv := collect(t, "", wfHost(t, "43.0.0.Final", wfMgmt(base, wfHTTPInterface("", `http="management-http"`)), nil))
	if n, _ := wfMgmtCount(inv); n != 0 {
		t.Errorf("a version that is not measured, without TLS: %d effective values, want none", n)
	}
}

// いまの形式（Elytron の ssl-context）。受け入れるものは、アプリ用の待ち受けと同じ決まりで求まる（測定で、同じ場面の結果が同じだった）。
func TestWildFlyManagementElytron(t *testing.T) {
	// 場面 m-e-default
	prefix, inv := collect(t, "", wfHost(t, "42.0.0.Final", wfMgmt(wfElytron("", `ssl-context="labSSC"`), wfHTTPInterface(`ssl-context="labSSC"`, wfBothSockets)), nil))
	p := wfMgmtEff(t, inv, "tls.protocols")
	if p.Status != "resolved" || strings.Join(p.Values, ",") != "TLSv1.2" || p.Confidence != "high" || !hasQualifier(p, model.QualifierAnyJDKFound) || p.Direction != "inbound" {
		t.Errorf("protocols = %+v", p)
	}
	e := wfMgmtEff(t, inv, "tls.ciphers")
	wfCheck(t, e, "high", "RSA", 14, wfRSA12)
	wfCheck(t, e, "high", "EC", 7, wfEC12) // 場面 m-e-eccert
	if l := layers(e); l != "app-default/default library/intersect app-config/remove" {
		t.Errorf("steps = %s", l)
	}
	if s := e.Steps[0].Source; s == nil || s.Package != "wildfly" || s.Version != "42.0.0.Final" {
		t.Errorf("WildFly source = %+v", e.Steps[0].Source)
	}
	if e13 := wfMgmtEff(t, inv, "tls.ciphersuites-tls13"); e13.Status != "resolved" || len(e13.Values) != 0 || !strings.Contains(strings.Join(e13.Notes, " "), "cipher-suite-names") {
		t.Errorf("tls13 = %+v", e13)
	}
	if g := wfMgmtEff(t, inv, "tls.groups"); g.Status != "resolved" || sortedJoin(g.Values) != "P-256,P-384,P-521,X25519,X448" {
		t.Errorf("groups = %+v", g)
	}
	// 「管理用の待ち受けは読まない」という注記は、もう付けない
	for _, param := range []string{"tls.protocols", "tls.ciphers"} {
		if n := strings.Join(wfMgmtEff(t, inv, param).Notes, " | ") + strings.Join(wfEff(t, inv, param).Notes, " | "); strings.Contains(n, "management interface") {
			t.Errorf("%s: a note still says that the management interface is not read: %s", param, n)
		}
	}
	// キーストアの場所は、管理用の待ち受けの記載としても記録する
	found := false
	for _, s := range inv.Settings {
		if s.Scope == wfMgmtScope && s.Parameter == "tls.keystore" {
			found = len(s.ReferencedPaths) == 1 && s.ReferencedPaths[0] == prefix+wfHome+"/standalone/configuration/application.keystore"
		}
	}
	if !found {
		t.Errorf("the keystore of the management interface is not recorded: %+v", inv.Settings)
	}
	// アプリ用の待ち受けの結果は、変わらない
	wfCheck(t, wfEff(t, inv, "tls.ciphers"), "high", "RSA", 14, wfRSA12)

	// 場面 m-e-httpsonly: TLS 用のソケットだけ
	_, inv = collect(t, "", wfHost(t, "42.0.0.Final", wfMgmt(wfElytron("", `ssl-context="labSSC"`), wfHTTPInterface(`ssl-context="labSSC"`, `https="management-https"`)), nil))
	wfCheck(t, wfMgmtEff(t, inv, "tls.ciphers"), "high", "RSA", 14, wfRSA12)

	// 場面 m-e-filter-names13: 暗号の指定と、TLS 1.3 用の指定
	_, inv = collect(t, "", wfHost(t, "42.0.0.Final", wfMgmt(wfElytron(`cipher-suite-filter="ECDHE+AESGCM" cipher-suite-names="TLS_AES_128_GCM_SHA256"`, `ssl-context="labSSC"`),
		wfHTTPInterface(`ssl-context="labSSC"`, wfBothSockets)), nil))
	if p := wfMgmtEff(t, inv, "tls.protocols"); strings.Join(p.Values, ",") != "TLSv1.3,TLSv1.2" {
		t.Errorf("protocols = %+v", p)
	}
	e = wfMgmtEff(t, inv, "tls.ciphers")
	if got := sortedJoin(wfKind(e.Values, "RSA")); got != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" || e.Confidence != "high" {
		t.Errorf("ciphers = %s (%s)", got, e.Confidence)
	}
	if l := layers(e); l != "app-config/override library/intersect app-config/remove" || e.Steps[0].Setting == "" {
		t.Errorf("steps = %s %+v", l, e.Steps[0])
	}
	if e13 := wfMgmtEff(t, inv, "tls.ciphersuites-tls13"); strings.Join(e13.Values, ",") != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("tls13 = %+v", e13)
	}

	// 場面 m-e-protocols13: プロトコルを TLS 1.3 だけにして、TLS 1.3 用の指定を書かないと、何も受け入れない
	_, inv = collect(t, "", wfHost(t, "42.0.0.Final", wfMgmt(wfElytron(`protocols="TLSv1.3"`, `ssl-context="labSSC"`), wfHTTPInterface(`ssl-context="labSSC"`, wfBothSockets)), nil))
	for _, param := range []string{"tls.protocols", "tls.ciphers", "tls.ciphersuites-tls13"} {
		if e := wfMgmtEff(t, inv, param); e.Status != "resolved" || len(e.Values) != 0 {
			t.Errorf("%s = %+v", param, e)
		}
	}

	// アプリ用の待ち受けとは別の ssl-context を指す場合は、それぞれの設定で求める
	two := strings.Replace(wfElytron("", `ssl-context="labSSC"`), `<server-ssl-contexts>`,
		`<server-ssl-contexts>
                    <server-ssl-context name="mgmtSSC" key-manager="labKM" cipher-suite-filter="ECDHE+AESGCM"/>`, 1)
	_, inv = collect(t, "", wfHost(t, "42.0.0.Final", wfMgmt(two, wfHTTPInterface(`ssl-context="mgmtSSC"`, wfBothSockets)), nil))
	if got := len(wfKind(wfMgmtEff(t, inv, "tls.ciphers").Values, "RSA")); got != 2 {
		t.Errorf("management: %d suites for RSA, want 2", got)
	}
	wfCheck(t, wfEff(t, inv, "tls.ciphers"), "high", "RSA", 14, wfRSA12)
}

// 値を求めない場合
func TestWildFlyManagementUnresolved(t *testing.T) {
	base := wfElytron("", `ssl-context="labSSC"`)
	for name, c := range map[string]struct{ version, xml, scope, want string }{
		// 場面 m-binding-only: TLS 用のソケットがあるのに、TLS の設定がない（42.0.0 では設定そのものを拒まれ、24.0.1 ではサーバーが起動しなかった）
		"a socket for TLS without TLS settings": {"42.0.0.Final", wfMgmt(base, wfHTTPInterface("", wfBothSockets)), wfMgmtScope, "ssl-context"},
		"a context that does not exist":         {"42.0.0.Final", wfMgmt(base, wfHTTPInterface(`ssl-context="nosuch"`, wfBothSockets)), wfMgmtScope, "not found"},
		"an SNI context":                        {"42.0.0.Final", wfMgmt(base, wfHTTPInterface(`ssl-context="labSNI"`, wfBothSockets)), wfMgmtScope, "server-ssl-sni-context"},
		"an expression in the context":          {"42.0.0.Final", wfMgmt(base, wfHTTPInterface(`ssl-context="${mgmt.context:labSSC}"`, wfBothSockets)), wfMgmtScope, "expression"},
		"an expression in the socket":           {"42.0.0.Final", wfMgmt(base, wfHTTPInterface(`ssl-context="labSSC"`, `http="management-http" https="${mgmt.socket:management-https}"`)), wfMgmtScope, "expression"},
		// 場面 m-e-filter-bad: Elytron が受け付けない指定
		"a filter Elytron rejects": {"42.0.0.Final", wfMgmt(wfElytron(`cipher-suite-filter="NO_SUCH_SUITE"`, `ssl-context="labSSC"`), wfHTTPInterface(`ssl-context="labSSC"`, wfBothSockets)), wfMgmtScope, "cipher-suite-filter"},
		// 場面 m-e-openssl
		"providers":                      {"42.0.0.Final", wfMgmt(wfElytron(`providers="openssl"`, `ssl-context="labSSC"`), wfHTTPInterface(`ssl-context="labSSC"`, wfBothSockets)), wfMgmtScope, "providers"},
		"a version that is not measured": {"43.0.0.Final", wfMgmt(base, wfHTTPInterface(`ssl-context="labSSC"`, wfBothSockets)), wfMgmtScope, "no WildFly table"},
		// 古い書き方（socket 要素に、interface と port を直接書く）は、測っていない
		"the socket element": {"42.0.0.Final", wfMgmt(base, `<http-interface ssl-context="labSSC"><socket interface="management" port="9990" secure-port="9993"/></http-interface>`), wfMgmtScope, "socket element"},
		// native-interface（管理用の独自のプロトコル）の TLS は、測っていない
		"a native-interface with an ssl-context": {"42.0.0.Final", wfMgmt(base, wfHTTPInterface("", `http="management-http"`)+`
            <native-interface ssl-context="labSSC"><socket-binding native="management-native"/></native-interface>`), "management native-interface", "not been measured"},
	} {
		_, inv := collect(t, "", wfHost(t, c.version, c.xml, nil))
		wfMgmtUnresolved(t, name, inv, c.scope, c.want)
	}
}

// wfMgmtLegacy は、古い形式（security-realm。24 まで）で、管理用の待ち受けを組み立てる。ManagementRealm に、ssl（ssl は ssl 要素の属性、
// engine は engine 要素）を足す。ssl が "-" なら、ManagementRealm に ssl を書かない（配布物のままの形）。
func wfMgmtLegacy(ssl, engine, attrs, binding string) string {
	identity := `<server-identities>
                    <ssl ` + ssl + `>
                        ` + engine + `
                        <keystore path="/etc/lab/mgmt.p12" keystore-password="SECRET-PASSWORD" alias="lab"/>
                    </ssl>
                </server-identities>`
	if ssl == "-" {
		identity = ""
	}
	realm := `<security-realm name="ManagementRealm">
                ` + identity + `
                <authentication><local default-user="$local" skip-group-loading="true"/></authentication>
            </security-realm>
        </security-realms>`
	xml := strings.Replace(wfLegacy("", "", ""), "</security-realms>", realm, 1)
	return wfMgmt(xml, `<http-interface `+attrs+`>
                <http-upgrade enabled="true"/>
                <socket-binding `+binding+`/>
            </http-interface>`)
}

// 古い形式（security-realm。24 まで）。受け入れるものは、アプリ用の待ち受けの security-realm と同じ決まりで求まる
// （待ち受けの側の指定は、管理用の待ち受けにはない）。
func TestWildFlyManagementLegacyRealm(t *testing.T) {
	const realm = `security-realm="ManagementRealm"`
	host := func(version, xml string) *model.Inventory {
		_, inv := collect(t, "", wfHost(t, version, xml, nil, pkgJava11Ubu))
		return inv
	}
	// 場面 m-k-default: TLS 1.2 だけ。暗号スイートは JDK の既定
	inv := host("24.0.1.Final", wfMgmtLegacy("", "", realm, wfBothSockets))
	if p := wfMgmtEff(t, inv, "tls.protocols"); p.Status != "resolved" || strings.Join(p.Values, ",") != "TLSv1.2" || p.Confidence != "high" {
		t.Errorf("protocols = %+v", p)
	}
	wfCheck(t, wfMgmtEff(t, inv, "tls.ciphers"), "high", "RSA", 14, wfRSA12)
	if e13 := wfMgmtEff(t, inv, "tls.ciphersuites-tls13"); e13.Status != "resolved" || len(e13.Values) != 0 {
		t.Errorf("tls13 = %+v", e13)
	}
	// キーストアの場所を記録する。パスワードは、どこにも出ない
	found := false
	for _, s := range inv.Settings {
		if s.Scope == wfMgmtScope && s.Parameter == "tls.keystore" {
			found = len(s.ReferencedPaths) == 1 && strings.HasSuffix(s.ReferencedPaths[0], "/etc/lab/mgmt.p12")
		}
	}
	if !found {
		t.Errorf("the keystore of the management interface is not recorded: %+v", inv.Settings)
	}
	// アプリ用の待ち受け（ApplicationRealm）の結果は、変わらない
	wfCheck(t, wfEff(t, inv, "tls.ciphers"), "high", "RSA", 14, wfRSA12)

	// 場面 m-k-protocols13: engine の enabled-protocols に TLSv1.3 を入れると、JDK の TLS 1.3 のスイートを受け入れる
	inv = host("24.0.1.Final", wfMgmtLegacy("", `<engine enabled-protocols="TLSv1.2 TLSv1.3"/>`, realm, wfBothSockets))
	if p, e13 := wfMgmtEff(t, inv, "tls.protocols"), wfMgmtEff(t, inv, "tls.ciphersuites-tls13"); strings.Join(p.Values, ",") != "TLSv1.3,TLSv1.2" || setDigest(e13.Values) != wfTLS13All {
		t.Errorf("protocols=%v tls13=%v", p.Values, e13.Values)
	}
	// アプリ用の待ち受けは、ApplicationRealm の設定のまま（TLS 1.2 だけ）
	if p := wfEff(t, inv, "tls.protocols"); strings.Join(p.Values, ",") != "TLSv1.2" {
		t.Errorf("the https-listener must keep its own realm: protocols = %v", p.Values)
	}
	// 場面 m-k-ciphers: engine の enabled-cipher-suites（Java での名前）
	inv = host("24.0.1.Final", wfMgmtLegacy("", `<engine enabled-cipher-suites="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"/>`, realm, wfBothSockets))
	if got := sortedJoin(wfMgmtEff(t, inv, "tls.ciphers").Values); got != "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
		t.Errorf("ciphers = %s", got)
	}
	// 場面 m-k-protocol-12: ssl の protocol は、受け入れるものを変えなかった
	inv = host("24.0.1.Final", wfMgmtLegacy(`protocol="TLSv1.2"`, "", realm, wfBothSockets))
	if p := wfMgmtEff(t, inv, "tls.protocols"); strings.Join(p.Values, ",") != "TLSv1.2" {
		t.Errorf("protocols = %+v", p)
	}

	// 場面 m-k-nobinding: security-realm に ssl があっても、TLS 用のソケットがなければ、TLS で待ち受けない
	inv = host("24.0.1.Final", wfMgmtLegacy("", "", realm, `http="management-http"`))
	if n, s := wfMgmtCount(inv); n != 0 || s != 0 {
		t.Errorf("no socket for TLS: %d effective values and %d settings, want none", n, s)
	}
	// 配布物のままの形（ManagementRealm に ssl がなく、TLS 用のソケットもない）
	inv = host("24.0.1.Final", wfMgmtLegacy("-", "", realm, `http="management-http"`))
	if n, s := wfMgmtCount(inv); n != 0 || s != 0 {
		t.Errorf("the default: %d effective values and %d settings, want none", n, s)
	}

	// 場面 m-e-default など（24.0.1）: 24 までの配布物では、http-interface に、認証のための security-realm（ssl はない）が書かれている。
	// そこに ssl-context を足した形では、ssl-context の設定で待ち受ける
	withContext := strings.Replace(wfMgmtLegacy("-", "", realm+` ssl-context="mgmtSSC"`, wfBothSockets), "    <profile>\n", `    <profile>
        <subsystem xmlns="urn:wildfly:elytron:13.0">
            <tls>
                <key-managers><key-manager name="mgmtKM" key-store="mgmtKS"><credential-reference clear-text="SECRET-PASSWORD"/></key-manager></key-managers>
                <server-ssl-contexts>
                    <server-ssl-context name="mgmtSSC" key-manager="mgmtKM" cipher-suite-filter="ECDHE+AESGCM" cipher-suite-names="TLS_AES_128_GCM_SHA256"/>
                </server-ssl-contexts>
            </tls>
        </subsystem>
`, 1)
	inv = host("24.0.1.Final", withContext)
	if p, e, e13 := wfMgmtEff(t, inv, "tls.protocols"), wfMgmtEff(t, inv, "tls.ciphers"), wfMgmtEff(t, inv, "tls.ciphersuites-tls13"); strings.Join(p.Values, ",") != "TLSv1.3,TLSv1.2" ||
		len(wfKind(e.Values, "RSA")) != 2 || strings.Join(e13.Values, ",") != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("a realm without ssl and an ssl-context: protocols=%v ciphers=%v tls13=%v (%s)", p.Values, e.Values, e13.Values, p.Reason)
	}

	// 値を求めない場合
	for name, c := range map[string]struct{ version, xml, want string }{
		// 場面 m-binding-only: TLS 用のソケットがあるのに、security-realm に ssl がない（サーバーが起動しなかった）
		"a socket for TLS, and a realm without ssl": {"24.0.1.Final", wfMgmtLegacy("-", "", realm, wfBothSockets), "no ssl element"},
		// 場面 m-k-protocols-bad: どの名前も JDK の知らないもの（実在するキーストアでは、サーバーが起動しなかった）
		"protocols the JDK does not know": {"24.0.1.Final", wfMgmtLegacy("", `<engine enabled-protocols="TLSv9"/>`, realm, wfBothSockets), "none of"},
		// 場面 m-k-ciphers-ossl: OpenSSL 式の名前は、JDK の知らない名前
		"cipher suites the JDK does not know": {"24.0.1.Final", wfMgmtLegacy("", `<engine enabled-cipher-suites="ECDHE-RSA-AES256-GCM-SHA384"/>`, realm, wfBothSockets), "none of"},
		// 場面 m-k-protocol-bad
		"an ssl protocol the JDK does not have": {"24.0.1.Final", wfMgmtLegacy(`protocol="TLSv9"`, "", realm, wfBothSockets), "protocol"},
		"an expression in the realm":            {"24.0.1.Final", wfMgmtLegacy("", `<engine enabled-protocols="${mgmt.protocols:TLSv1.2}"/>`, realm, wfBothSockets), "expression"},
		// 25 以降には、この形式がない
		"a realm on a version without realms": {"25.0.0.Final", wfMgmtLegacy("", "", realm, wfBothSockets), "security-realm"},
	} {
		wfMgmtUnresolved(t, name, host(c.version, c.xml), wfMgmtScope, c.want)
	}
}
