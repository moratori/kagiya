//go:build unix

package apps

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"kagiya/internal/inventory"
	"kagiya/internal/model"
)

// 以下の期待値は、検証ラボで、WildFly の配布物（19.0.0.Final〜42.0.0.Final の 54 版）を Ubuntu 24.04 に展開して場面ごとに起動し、
// 同じコンテナ内からのハンドシェイクで数え上げた結果（lab/phase2/wildfly.sh）。JDK は、26 までは openjdk-11 11.0.33+9-1ubuntu1~24.04.1、
// 27 以降は openjdk-17 17.0.21.0.3+1-1~24.04.1。サーバーの証明書は、RSA（場面 e-eccert だけ EC）。
// キーストアの中は読まないので、kagiya の結果は証明書の種類で絞り込まれていない。測定結果とは、RSA の証明書で使えるスイートだけを取り出して比べる。

const (
	wfHome      = "/opt/wildfly"
	wfConf      = wfHome + "/standalone/configuration/standalone.xml"
	wfProduct   = wfHome + "/modules/system/layers/base/org/jboss/as/product/main"
	wfScope     = "https-listener default-server/https"
	wfMgmtScope = "management http-interface"
	wfJava17    = "/usr/lib/jvm/java-17-openjdk-arm64"
	wfJava11    = "/usr/lib/jvm/java-11-openjdk-arm64"
	wfRSA12     = "71168486bfa11015" // 既定、RSA の証明書（14）
	wfEC12      = "96f46569772374f7" // 既定、EC の証明書（7）
	wfECDHE12   = "0e092f295e359427" // ECDHE だけ、RSA の証明書（7）
	wfTLS13All  = "0298a462f55e65f8" // JDK の TLS 1.3 のスイート（3）
	// 配布物に入っている standalone.conf の、コメントでない行（19.0.0.Final。JAVA_HOME の行はコメントになっている）
	wfStandaloneConf = "#JAVA_HOME=\"/opt/java/jdk\"\nif [ \"x$JBOSS_MODULES_SYSTEM_PKGS\" = \"x\" ]; then\n   JBOSS_MODULES_SYSTEM_PKGS=\"org.jboss.byteman\"\nfi\n" +
		"if [ \"x$JAVA_OPTS\" = \"x\" ]; then\n   JAVA_OPTS=\"-Xms64m -Xmx512m -XX:MetaspaceSize=96M -XX:MaxMetaspaceSize=256m -Djava.net.preferIPv4Stack=true\"\n" +
		"   JAVA_OPTS=\"$JAVA_OPTS -Djboss.modules.system.pkgs=$JBOSS_MODULES_SYSTEM_PKGS -Djava.awt.headless=true\"\nelse\n" +
		"   echo \"JAVA_OPTS already set in environment; overriding default settings with values: $JAVA_OPTS\"\nfi\n"
)

var (
	pkgJava17Ubu = model.Package{Manager: "dpkg", Name: "openjdk-17-jre-headless", Version: "17.0.21.0.3+1-1~24.04.1"}
	pkgJava11Ubu = model.Package{Manager: "dpkg", Name: "openjdk-11-jre-headless", Version: "11.0.33+9-1ubuntu1~24.04.1"}
)

// wfElytron は、いまの形式（Elytron の server-ssl-context）の standalone.xml を組み立てる。context は server-ssl-context の追加の属性、listener は https-listener の追加の属性。
// パスワードの記載は、実物にもある（読まないことを確かめるために入れている）。
func wfElytron(context, listener string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<server xmlns="urn:jboss:domain:community:20.0">
    <profile>
        <subsystem xmlns="urn:wildfly:elytron:community:19.0">
            <tls>
                <key-stores>
                    <key-store name="labKS">
                        <credential-reference clear-text="SECRET-PASSWORD"/>
                        <implementation type="PKCS12"/>
                        <file path="application.keystore" relative-to="jboss.server.config.dir"/>
                    </key-store>
                </key-stores>
                <key-managers>
                    <key-manager name="labKM" key-store="labKS"><credential-reference clear-text="SECRET-PASSWORD"/></key-manager>
                </key-managers>
                <server-ssl-contexts>
                    <server-ssl-context name="labSSC" key-manager="labKM" ` + context + `/>
                </server-ssl-contexts>
                <server-ssl-sni-contexts><server-ssl-sni-context name="labSNI" default-ssl-context="labSSC"/></server-ssl-sni-contexts>
            </tls>
        </subsystem>
        <subsystem xmlns="urn:jboss:domain:undertow:15.0">
            <server name="default-server">
                <http-listener name="default" socket-binding="http"/>
                <https-listener name="https" socket-binding="https" ` + listener + `/>
            </server>
        </subsystem>
    </profile>
    <socket-binding-group name="standard-sockets" default-interface="public">
        <socket-binding name="https" port="${jboss.https.port:8443}"/>
    </socket-binding-group>
</server>
`
}

// wfLegacy は、古い形式（security-realm。WildFly 24 まで）の standalone.xml を組み立てる。
func wfLegacy(ssl, engine, listener string) string {
	return `<?xml version='1.0' encoding='UTF-8'?>
<server xmlns="urn:jboss:domain:17.0">
    <management>
        <security-realms>
            <security-realm name="ApplicationRealm">
                <server-identities>
                    <ssl ` + ssl + `>
                        ` + engine + `
                        <keystore path="application.keystore" relative-to="jboss.server.config.dir" keystore-password="SECRET-PASSWORD" alias="server" key-password="SECRET-PASSWORD"/>
                    </ssl>
                </server-identities>
            </security-realm>
        </security-realms>
    </management>
    <profile>
        <subsystem xmlns="urn:jboss:domain:undertow:12.0">
            <server name="default-server">
                <https-listener name="https" socket-binding="https" security-realm="ApplicationRealm" ` + listener + `/>
            </server>
        </subsystem>
    </profile>
</server>
`
}

// wfHost は、WildFly を展開した配置（設定、版の分かるファイル、standalone.conf）と、JDK を作る。
// 版の分かるファイルは、30 までは製品のマニフェスト、31 以降は製品の JAR の中のマニフェスト（検証ラボで、54 版の配布物で確かめた）。
func wfHost(t *testing.T, version, xml string, extra map[string]string, pkgs ...model.Package) func(p string, b *inventory.Builder) {
	manifest := "Manifest-Version: 1.0\r\nJBoss-Product-Release-Name: WildFly Full\r\nJBoss-Product-Release-Version: " + version + "\r\nJBossAS-Release-Version: " + version + "\r\n"
	files := map[string]string{wfConf: xml, wfHome + "/bin/standalone.conf": wfStandaloneConf,
		wfJava17 + "/conf/security/java.security": "security.provider.1=SUN\n" + jdkUpstreamDisabled,
		wfJava11 + "/conf/security/java.security": "security.provider.1=SUN\n" + jdkUpstreamDisabled}
	major := 0
	for _, c := range version {
		if c < '0' || c > '9' {
			break
		}
		major = major*10 + int(c-'0')
	}
	if major <= 30 {
		files[wfProduct+"/dir/META-INF/MANIFEST.MF"] = manifest
	} else {
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)
		f, _ := w.Create("META-INF/MANIFEST.MF")
		f.Write([]byte(manifest))
		w.Close()
		files[wfProduct+"/wildfly-feature-pack-product-conf-"+version+".jar"] = buf.String()
	}
	for k, v := range extra {
		if v == "" {
			delete(files, k)
		} else {
			files[k] = v
		}
	}
	if len(pkgs) == 0 {
		pkgs = []model.Package{pkgJava17Ubu}
	}
	// JDK は、渡されたパッケージのものだけを置く
	has := map[string]bool{}
	for _, p := range pkgs {
		has[p.Name] = true
	}
	if !has[pkgJava17Ubu.Name] {
		delete(files, wfJava17+"/conf/security/java.security")
	}
	if !has[pkgJava11Ubu.Name] {
		delete(files, wfJava11+"/conf/security/java.security")
	}
	return jdkHost(t, files, pkgs...)
}

func wfEff(t *testing.T, inv *model.Inventory, param string) model.EffectiveValue {
	t.Helper()
	return eff(t, inv, "svc:wildfly:"+wfHome, param, wfScope)
}

// wfKind は、スイートのうち、その種類の証明書で使えるもの（RSA: 名前に _RSA_WITH_ がある / EC: _ECDSA_WITH_）を返す。
func wfKind(values []string, kind string) []string {
	mark := map[string]string{"RSA": "_RSA_WITH_", "EC": "_ECDSA_WITH_"}[kind]
	var out []string
	for _, v := range values {
		if strings.Contains(v, mark) {
			out = append(out, v)
		}
	}
	return out
}

func wfCheck(t *testing.T, e model.EffectiveValue, confidence string, kind string, count int, digest string) {
	t.Helper()
	got := wfKind(e.Values, kind)
	if e.Status != "resolved" || e.Confidence != confidence || len(got) != count || setDigest(got) != digest {
		t.Errorf("%s: status=%s confidence=%s reason=%q: %d suites for %s (%s), want %d (%s)", e.Parameter, e.Status, e.Confidence, e.Reason, len(got), kind, setDigest(got), count, digest)
	}
}

func wfUnresolved(t *testing.T, inv *model.Inventory, want string) {
	t.Helper()
	wfUnresolvedIn(t, "https-listener", inv, wfScope, want)
}

// wfUnresolvedIn は、その範囲（待ち受け）の 4 つの項目が、どれも、理由に want を含む「不明」であることを確かめる。
func wfUnresolvedIn(t *testing.T, name string, inv *model.Inventory, scope, want string) {
	t.Helper()
	for _, p := range []string{"tls.protocols", "tls.ciphers", "tls.ciphersuites-tls13", "tls.groups"} {
		e := eff(t, inv, "svc:wildfly:"+wfHome, p, scope)
		if e.Status != "unresolved" || !strings.Contains(e.Reason, want) || len(e.Values) != 0 {
			t.Errorf("%s: %s: status=%s reason=%q values=%d, want unresolved with %q", name, p, e.Status, e.Reason, len(e.Values), want)
		}
	}
}

// 既定（暗号の指定なし）: TLS 1.2 だけ。暗号スイートは、Elytron の「DEFAULT」のうち、JDK が対応していて無効にしていないもの。
// TLS 1.3 は、TLS 1.3 用の指定（cipher-suite-names）がなければ受け入れない（場面 e-default）。
func TestWildFlyElytronDefault(t *testing.T) {
	prefix, inv := collect(t, "", wfHost(t, "42.0.0.Final", wfElytron("", `ssl-context="labSSC"`), nil))
	svc := service(t, inv, "wildfly")
	if svc.ID != "svc:wildfly:"+wfHome || len(svc.ConfigFiles) != 1 || svc.ConfigFiles[0] != prefix+wfConf {
		t.Errorf("service = %+v", svc)
	}
	p := wfEff(t, inv, "tls.protocols")
	// どの JDK で動くかは決められない（JAVA_HOME の指定がない）。見つかった JDK で同じになる値を出し、そのことを説明として付ける（確度は下げない）
	if p.Status != "resolved" || strings.Join(p.Values, ",") != "TLSv1.2" || p.Confidence != "high" || !hasQualifier(p, model.QualifierAnyJDKFound) || p.Direction != "inbound" {
		t.Errorf("protocols = %+v", p)
	}
	e := wfEff(t, inv, "tls.ciphers")
	wfCheck(t, e, "high", "RSA", 14, wfRSA12)
	wfCheck(t, e, "high", "EC", 7, wfEC12) // 場面 e-eccert
	if l := layers(e); l != "app-default/default library/intersect app-config/remove" {
		t.Errorf("steps = %s", l)
	}
	if s := e.Steps[0].Source; s == nil || s.Package != "wildfly" || s.Version != "42.0.0.Final" || !strings.HasPrefix(s.Image, "ubuntu@sha256:") {
		t.Errorf("WildFly source = %+v", e.Steps[0].Source)
	}
	if s := e.Steps[1].Source; s == nil || s.Package != "openjdk-17-jre-headless" {
		t.Errorf("JDK source = %+v", e.Steps[1].Source)
	}
	if !strings.Contains(strings.Join(e.Notes, " | "), "certificate") {
		t.Errorf("no note about the kind of the certificate: %v", e.Notes)
	}
	if e13 := wfEff(t, inv, "tls.ciphersuites-tls13"); e13.Status != "resolved" || len(e13.Values) != 0 || !strings.Contains(strings.Join(e13.Notes, " "), "cipher-suite-names") {
		t.Errorf("tls13 = %+v", e13)
	}
	if g := wfEff(t, inv, "tls.groups"); g.Status != "resolved" || sortedJoin(g.Values) != "P-256,P-384,P-521,X25519,X448" { // 測定での、TLS 1.2 の ECDHE のグループ（secp256r1 secp384r1 secp521r1 x25519 x448。本体での正式な名前で比べる）
		t.Errorf("groups = %+v", g)
	}
	// キーストアの場所は記録する。パスワードは、どこにも出ない
	found := false
	for _, s := range inv.Settings {
		if s.Service == svc.ID && s.Parameter == "tls.keystore" {
			found = len(s.ReferencedPaths) == 1 && s.ReferencedPaths[0] == prefix+wfHome+"/standalone/configuration/application.keystore"
		}
	}
	if !found {
		t.Errorf("the keystore is not recorded: %+v", inv.Settings)
	}
	if raw, _ := json.Marshal(inv); strings.Contains(string(raw), "SECRET") {
		t.Error("a password is in the result")
	}
}

// 暗号の指定（cipher-suite-filter）は、Elytron の規則で解釈する。TLS 1.3 用の指定（cipher-suite-names）を書くと、TLS 1.3 も受け入れる。
func TestWildFlyElytronConfigured(t *testing.T) {
	// 場面 e-filter-names13
	_, inv := collect(t, "", wfHost(t, "42.0.0.Final", wfElytron(`cipher-suite-filter="ECDHE+AESGCM" cipher-suite-names="TLS_AES_128_GCM_SHA256"`, `ssl-context="labSSC"`), nil))
	if p := wfEff(t, inv, "tls.protocols"); strings.Join(p.Values, ",") != "TLSv1.3,TLSv1.2" {
		t.Errorf("protocols = %+v", p)
	}
	e := wfEff(t, inv, "tls.ciphers")
	if got := sortedJoin(wfKind(e.Values, "RSA")); got != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" || e.Confidence != "high" {
		t.Errorf("ciphers = %s (%s)", got, e.Confidence)
	}
	if l := layers(e); l != "app-config/override library/intersect app-config/remove" || e.Steps[0].Setting == "" {
		t.Errorf("steps = %s %+v", l, e.Steps[0])
	}
	if e13 := wfEff(t, inv, "tls.ciphersuites-tls13"); strings.Join(e13.Values, ",") != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("tls13 = %+v", e13)
	}
	// 場面 e-filter-openssl: 「ECDHE+CHACHA20」の CHACHA20 は Elytron の知らない語で、無視される（ECDHE すべてになる）
	_, inv = collect(t, "", wfHost(t, "42.0.0.Final", wfElytron(`cipher-suite-filter="ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL"`, `ssl-context="labSSC"`), nil))
	wfCheck(t, wfEff(t, inv, "tls.ciphers"), "high", "RSA", 7, wfECDHE12)
	// 場面 e-filter-alias: OpenSSL 式の名前
	_, inv = collect(t, "", wfHost(t, "42.0.0.Final", wfElytron(`cipher-suite-filter="ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-SHA"`, `ssl-context="labSSC"`), nil))
	if got := sortedJoin(wfEff(t, inv, "tls.ciphers").Values); got != "TLS_DHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" {
		t.Errorf("ciphers = %s", got)
	}
	// 場面 e-names-proto13: TLS 1.3 だけ
	_, inv = collect(t, "", wfHost(t, "42.0.0.Final", wfElytron(`cipher-suite-names="TLS_AES_256_GCM_SHA384" protocols="TLSv1.3"`, `ssl-context="labSSC"`), nil))
	if p, e, e13 := wfEff(t, inv, "tls.protocols"), wfEff(t, inv, "tls.ciphers"), wfEff(t, inv, "tls.ciphersuites-tls13"); strings.Join(p.Values, ",") != "TLSv1.3" ||
		e.Status != "resolved" || len(e.Values) != 0 || strings.Join(e13.Values, ",") != "TLS_AES_256_GCM_SHA384" {
		t.Errorf("protocols=%v ciphers=%v tls13=%v", p.Values, e.Values, e13.Values)
	}
	// 場面 e-names-proto12: TLS 1.3 用の指定があっても、プロトコルが TLS 1.2 だけなら、TLS 1.3 は受け入れない
	_, inv = collect(t, "", wfHost(t, "42.0.0.Final", wfElytron(`cipher-suite-names="TLS_AES_256_GCM_SHA384" protocols="TLSv1.2"`, `ssl-context="labSSC"`), nil))
	if p, e13 := wfEff(t, inv, "tls.protocols"), wfEff(t, inv, "tls.ciphersuites-tls13"); strings.Join(p.Values, ",") != "TLSv1.2" || len(e13.Values) != 0 {
		t.Errorf("protocols=%v tls13=%v", p.Values, e13.Values)
	}
	// 場面 e-protocols13: プロトコルを TLS 1.3 だけにして、TLS 1.3 用の指定を書かないと、何も受け入れない
	_, inv = collect(t, "", wfHost(t, "42.0.0.Final", wfElytron(`protocols="TLSv1.3"`, `ssl-context="labSSC"`), nil))
	for _, param := range []string{"tls.protocols", "tls.ciphers", "tls.ciphersuites-tls13"} {
		if e := wfEff(t, inv, param); e.Status != "resolved" || len(e.Values) != 0 {
			t.Errorf("%s = %+v", param, e)
		}
	}
	// 場面 e-protocols-old: TLS 1.0 / 1.1 は、JDK が無効にしている
	_, inv = collect(t, "", wfHost(t, "42.0.0.Final", wfElytron(`protocols="TLSv1 TLSv1.1 TLSv1.2"`, `ssl-context="labSSC"`), nil))
	if p := wfEff(t, inv, "tls.protocols"); strings.Join(p.Values, ",") != "TLSv1.2" {
		t.Errorf("protocols = %+v", p)
	}
}

// どの JDK で動くか: standalone.conf に JAVA_HOME があれば、その JDK（確度は下げない）。なければ、見つかった JDK すべてで同じになる項目だけ確定とする。
func TestWildFlyJDK(t *testing.T) {
	conf := "JAVA_HOME=\"" + wfJava17 + "\"\n" + wfStandaloneConf
	_, inv := collect(t, "", wfHost(t, "42.0.0.Final", wfElytron("", `ssl-context="labSSC"`), map[string]string{wfHome + "/bin/standalone.conf": conf}, pkgJava17Ubu, pkgJava11Ubu))
	if p := wfEff(t, inv, "tls.protocols"); p.Status != "resolved" || p.Confidence != "high" || !strings.Contains(strings.Join(p.Notes, " "), wfJava17) {
		t.Errorf("protocols = %+v", p)
	}
	// 証明書の種類は分からないが、そのことでは確度を下げない（合わせた一覧を出し、説明を付ける）
	if e := wfEff(t, inv, "tls.ciphers"); e.Confidence != "high" || e.Steps[1].Source.Package != "openjdk-17-jre-headless" {
		t.Errorf("ciphers = %s %+v", e.Confidence, e.Steps)
	}
	// JAVA_HOME の指定がなく、JDK が 2 つある: どちらでも同じ結果なので確定（確度は中）
	_, inv = collect(t, "", wfHost(t, "42.0.0.Final", wfElytron("", `ssl-context="labSSC"`), nil, pkgJava17Ubu, pkgJava11Ubu))
	e := wfEff(t, inv, "tls.ciphers")
	wfCheck(t, e, "high", "RSA", 14, wfRSA12)
	if !strings.Contains(strings.Join(e.Notes, " "), wfJava11) || !strings.Contains(strings.Join(e.Notes, " "), wfJava17) {
		t.Errorf("notes = %v", e.Notes)
	}
	// JDK が見つからない
	_, inv = collect(t, "", wfHost(t, "42.0.0.Final", wfElytron("", `ssl-context="labSSC"`), map[string]string{wfJava17 + "/conf/security/java.security": ""}))
	wfUnresolved(t, inv, "JDK")
	// Java の起動時の指定で、TLS の設定を変えうるものがある
	_, inv = collect(t, "", wfHost(t, "42.0.0.Final", wfElytron("", `ssl-context="labSSC"`),
		map[string]string{wfHome + "/bin/standalone.conf": wfStandaloneConf + "JAVA_OPTS=\"$JAVA_OPTS -Djdk.tls.server.protocols=TLSv1.3\"\n"}))
	wfUnresolved(t, inv, "-Djdk.tls")
}

// 古い形式（security-realm。24 まで）。測った書き方だけを求める。
func TestWildFlyLegacyRealm(t *testing.T) {
	host := func(ssl, engine, listener string) *model.Inventory {
		_, inv := collect(t, "", wfHost(t, "24.0.1.Final", wfLegacy(ssl, engine, listener), nil, pkgJava11Ubu))
		return inv
	}
	// 場面 default: TLS 1.2 だけ。暗号スイートは JDK の既定
	inv := host("", "", "")
	if p := wfEff(t, inv, "tls.protocols"); strings.Join(p.Values, ",") != "TLSv1.2" {
		t.Errorf("protocols = %+v", p)
	}
	wfCheck(t, wfEff(t, inv, "tls.ciphers"), "high", "RSA", 14, wfRSA12)
	if e13 := wfEff(t, inv, "tls.ciphersuites-tls13"); e13.Status != "resolved" || len(e13.Values) != 0 {
		t.Errorf("tls13 = %+v", e13)
	}
	// 場面 l-protocols13: engine の enabled-protocols に TLSv1.3 を入れると、JDK の TLS 1.3 のスイートを受け入れる
	inv = host("", `<engine enabled-protocols="TLSv1.2 TLSv1.3"/>`, "")
	if p, e13 := wfEff(t, inv, "tls.protocols"), wfEff(t, inv, "tls.ciphersuites-tls13"); strings.Join(p.Values, ",") != "TLSv1.3,TLSv1.2" || len(e13.Values) != 3 || setDigest(e13.Values) != wfTLS13All {
		t.Errorf("protocols=%v tls13=%v", p.Values, e13.Values)
	}
	wfCheck(t, wfEff(t, inv, "tls.ciphers"), "high", "RSA", 14, wfRSA12)
	// 場面 l-ciphers: engine の enabled-cipher-suites（Java での名前）
	inv = host("", `<engine enabled-cipher-suites="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"/>`, "")
	if got := sortedJoin(wfEff(t, inv, "tls.ciphers").Values); got != "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
		t.Errorf("ciphers = %s", got)
	}
	// 場面 l-h-protocols13: https-listener の enabled-protocols
	inv = host("", "", `enabled-protocols="TLSv1.3"`)
	if p, e, e13 := wfEff(t, inv, "tls.protocols"), wfEff(t, inv, "tls.ciphers"), wfEff(t, inv, "tls.ciphersuites-tls13"); strings.Join(p.Values, ",") != "TLSv1.3" ||
		len(e.Values) != 0 || setDigest(e13.Values) != wfTLS13All {
		t.Errorf("protocols=%v ciphers=%v tls13=%v", p.Values, e.Values, e13.Values)
	}
	// 場面 l-h-ciphers: https-listener の enabled-cipher-suites（Java での名前 1 つ）
	inv = host("", "", `enabled-cipher-suites="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"`)
	if got := sortedJoin(wfEff(t, inv, "tls.ciphers").Values); got != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
		t.Errorf("ciphers = %s", got)
	}
	// 場面 l-protocol: ssl の protocol="TLSv1.3" は、受け入れるものを変えなかった
	inv = host(`protocol="TLSv1.3"`, "", "")
	if p := wfEff(t, inv, "tls.protocols"); strings.Join(p.Values, ",") != "TLSv1.2" {
		t.Errorf("protocols = %+v", p)
	}
	// 25 以降には、この形式がない
	_, inv = collect(t, "", wfHost(t, "25.0.0.Final", wfLegacy("", "", ""), nil, pkgJava11Ubu))
	wfUnresolved(t, inv, "security-realm")
}

// 古い形式の、測り足した書き方（検証ラボの wildfly-legacy。19.0.0〜24.0.1 の 14 版で、同じ結果だった）。
// 場面の名前は、lab/phase2/wildfly.sh のもの。
func TestWildFlyLegacyRealmMore(t *testing.T) {
	const (
		a  = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
		b  = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
		d  = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
		t3 = "TLS_AES_128_GCM_SHA256"
	)
	host := func(ssl, engine, listener string) *model.Inventory {
		_, inv := collect(t, "", wfHost(t, "24.0.1.Final", wfLegacy(ssl, engine, listener), nil, pkgJava11Ubu))
		return inv
	}
	// got は、プロトコル、TLS 1.2 以下のスイート（RSA の証明書で使えるもの）、TLS 1.3 のスイートを、並べ替えて返す
	got := func(inv *model.Inventory) (protocols, tls12, tls13 string) {
		p, e, e13 := wfEff(t, inv, "tls.protocols"), wfEff(t, inv, "tls.ciphers"), wfEff(t, inv, "tls.ciphersuites-tls13")
		if p.Status != "resolved" || e.Status != "resolved" || e13.Status != "resolved" {
			return "unresolved: " + e.Reason, "", ""
		}
		return sortedJoin(p.Values), sortedJoin(wfKind(e.Values, "RSA")), sortedJoin(e13.Values)
	}
	const all13 = "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256"
	defaultInv := host("", "", "")
	_, default12, _ := got(defaultInv) // 既定（JDK の既定の 14 個。TestWildFlyLegacyRealm で確かめている）
	for name, c := range map[string]struct {
		ssl, engine, listener   string
		protocols, tls12, tls13 string
	}{
		// (1) ssl の protocol は、TLS の実装の名前。測った 5 つの値では、受け入れるものを変えなかった
		"l-protocol-tls":     {`protocol="TLS"`, "", "", "TLSv1.2", default12, ""},
		"l-protocol-12":      {`protocol="TLSv1.2"`, "", "", "TLSv1.2", default12, ""},
		"l-protocol-11":      {`protocol="TLSv1.1"`, "", "", "TLSv1.2", default12, ""},
		"l-protocol-10":      {`protocol="TLSv1"`, "", "", "TLSv1.2", default12, ""},
		"l-protocol-12-ep13": {`protocol="TLSv1.2"`, `<engine enabled-protocols="TLSv1.2 TLSv1.3"/>`, "", "TLSv1.2,TLSv1.3", default12, all13},
		"l-protocol-13-ep13": {`protocol="TLSv1.3"`, `<engine enabled-protocols="TLSv1.2 TLSv1.3"/>`, "", "TLSv1.2,TLSv1.3", default12, all13},
		// (2) 待ち受けの側のプロトコル: カンマで区切り、前後の空白を落とす。JDK が知らない名前は落ちる
		"l-h-protocols-two":   {"", "", `enabled-protocols="TLSv1.2,TLSv1.3"`, "TLSv1.2,TLSv1.3", default12, all13},
		"l-h-protocols-space": {"", "", `enabled-protocols="TLSv1.2, TLSv1.3"`, "TLSv1.2,TLSv1.3", default12, all13},
		"l-h-protocols-old":   {"", "", `enabled-protocols="TLSv1.1,TLSv1.2"`, "TLSv1.2", default12, ""}, // TLS 1.1 は、JDK が無効にしている
		"l-h-protocols-bad":   {"", "", `enabled-protocols="TLSv9"`, "", "", ""},                         // 起動するが、何も受け入れない
		"l-h-protocols-blank": {"", "", `enabled-protocols="TLSv1.2 TLSv1.3"`, "", "", ""},               // 空白は区切りではない（1 つの知らない名前になる）
		// (3) 待ち受けの側の暗号: Elytron の式として解釈される（cipher-suite-filter と同じ決まり）。TLS 1.3 のスイートは選ばれない
		"l-h-ciphers-two":        {"", "", `enabled-cipher-suites="` + a + "," + b + `"`, "TLSv1.2", a + "," + b, ""},
		"l-h-ciphers-space":      {"", "", `enabled-cipher-suites="` + a + ", " + b + `"`, "TLSv1.2", a + "," + b, ""},
		"l-h-ciphers-colon":      {"", "", `enabled-cipher-suites="` + a + ":" + b + `"`, "TLSv1.2", a + "," + b, ""},
		"l-h-ciphers-ossl":       {"", "", `enabled-cipher-suites="ECDHE-RSA-AES256-GCM-SHA384"`, "TLSv1.2", b, ""},
		"l-h-ciphers-ossl-two":   {"", "", `enabled-cipher-suites="ECDHE-RSA-AES256-GCM-SHA384,ECDHE-RSA-AES128-GCM-SHA256"`, "TLSv1.2", a + "," + b, ""},
		"l-h-ciphers-ossl-colon": {"", "", `enabled-cipher-suites="ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"`, "TLSv1.2", a + "," + b, ""},
		"l-h-ciphers-ossl-expr":  {"", "", `enabled-cipher-suites="ECDHE+AESGCM"`, "TLSv1.2", a + "," + b, ""},
		"l-h-ciphers-ossl-high":  {"", "", `enabled-cipher-suites="HIGH:!aNULL:!MD5"`, "TLSv1.2", default12, ""},
		"l-h-ciphers-empty":      {"", "", `enabled-cipher-suites="RC4-MD5"`, "", "", ""}, // JDK が対応しているものが残らない: 起動するが、何も受け入れない
		"l-h-ciphers-p-two":      {"", "", `enabled-cipher-suites="` + a + `" enabled-protocols="TLSv1.2,TLSv1.3"`, "TLSv1.2", a, ""},
		// security-realm の側の暗号: JDK が知らない名前は落ちる（残るものがあれば、それだけになる）
		"l-ciphers-bad": {"", `<engine enabled-cipher-suites="NO_SUCH_SUITE ` + a + `"/>`, "", "TLSv1.2", a, ""},
		"l-ciphers-13":  {"", `<engine enabled-cipher-suites="` + t3 + " " + a + `" enabled-protocols="TLSv1.2 TLSv1.3"/>`, "", "TLSv1.2,TLSv1.3", a, t3},
		// security-realm の側のプロトコル: 同じ
		"l-protocols-bad-mix": {"", `<engine enabled-protocols="TLSv9 TLSv1.2"/>`, "", "TLSv1.2", default12, ""},
		// (4) 両方に書くと、待ち受けの側の指定が、security-realm の側の指定を置き換える（共通部分ではない）
		"l-both-protocols":      {"", `<engine enabled-protocols="TLSv1.2 TLSv1.3"/>`, `enabled-protocols="TLSv1.3"`, "TLSv1.3", "", all13},
		"l-both-protocols-rev":  {"", `<engine enabled-protocols="TLSv1.2"/>`, `enabled-protocols="TLSv1.3"`, "TLSv1.3", "", all13},
		"l-both-protocols-wide": {"", `<engine enabled-protocols="TLSv1.2"/>`, `enabled-protocols="TLSv1.2,TLSv1.3"`, "TLSv1.2,TLSv1.3", default12, all13},
		"l-both-ciphers":        {"", `<engine enabled-cipher-suites="` + a + " " + d + `"/>`, `enabled-cipher-suites="` + a + `"`, "TLSv1.2", a, ""},
		"l-both-ciphers-rev":    {"", `<engine enabled-cipher-suites="` + a + `"/>`, `enabled-cipher-suites="` + b + `"`, "TLSv1.2", b, ""},
		// 別の項目を、片方ずつに書く
		"l-mixed-ep-lc":   {"", `<engine enabled-protocols="TLSv1.2 TLSv1.3"/>`, `enabled-cipher-suites="` + a + `"`, "TLSv1.2", a, ""},
		"l-mixed-ec-lp":   {"", `<engine enabled-cipher-suites="` + a + " " + d + `"/>`, `enabled-protocols="TLSv1.2"`, "TLSv1.2", d + "," + a, ""},
		"l-mixed-ec-lp13": {"", `<engine enabled-cipher-suites="` + a + " " + t3 + `"/>`, `enabled-protocols="TLSv1.3"`, "TLSv1.3", "", t3},
	} {
		if p, e, e13 := got(host(c.ssl, c.engine, c.listener)); p != c.protocols || e != c.tls12 || e13 != c.tls13 {
			t.Errorf("%s:\n  got  protocols=%s tls12=%s tls13=%s\n  want protocols=%s tls12=%s tls13=%s", name, p, e, e13, c.protocols, c.tls12, c.tls13)
		}
	}
	// 何も受け入れない設定は、その旨を付けて、空の一覧を出す
	if p := wfEff(t, host("", "", `enabled-protocols="TLSv9"`), "tls.protocols"); p.Status != "resolved" || len(p.Values) != 0 || len(p.Qualifiers) == 0 {
		t.Errorf("nothing accepted: %+v", p)
	}
	// 値を求めない書き方
	for name, c := range map[string]struct{ ssl, engine, listener, want string }{
		// サーバーが起動しない（実測）
		"l-protocol-bad":     {`protocol="TLSv9"`, "", "", "protocol"},
		"l-h-ciphers-13":     {"", "", `enabled-cipher-suites="` + t3 + `"`, "enabled-cipher-suites"},
		"l-h-ciphers-13-p13": {"", "", `enabled-cipher-suites="` + t3 + `" enabled-protocols="TLSv1.3"`, "enabled-cipher-suites"},
		"l-h-ciphers-bad":    {"", "", `enabled-cipher-suites="NO_SUCH_SUITE"`, "enabled-cipher-suites"},
		// security-realm の側の名前が、どれも JDK の知らない名前: 実在するキーストアでは起動しない（k-ciphers-ossl、k-protocols-bad）。
		// 証明書を最初の接続のときに自動で作る設定では、制限が外れた（l-ciphers-ossl、l-protocols-bad）。どちらかを決められないので、求めない
		"l-ciphers-ossl":  {"", `<engine enabled-cipher-suites="ECDHE-RSA-AES256-GCM-SHA384"/>`, "", "none of"},
		"l-protocols-bad": {"", `<engine enabled-protocols="TLSv9"/>`, "", "none of"},
		// 待ち受けの側で置き換えていても、security-realm の側で起動に失敗する
		"realm names unknown, listener set": {"", `<engine enabled-cipher-suites="NO_SUCH_SUITE"/>`, `enabled-cipher-suites="` + a + `"`, "none of"},
		// 測っていない値
		"protocol SSLv3": {`protocol="SSLv3"`, "", "", "protocol"},
	} {
		inv := host(c.ssl, c.engine, c.listener)
		for _, param := range []string{"tls.protocols", "tls.ciphers", "tls.ciphersuites-tls13"} {
			if e := wfEff(t, inv, param); e.Status != "unresolved" || !strings.Contains(e.Reason, c.want) || !strings.Contains(e.Reason, "measured") {
				t.Errorf("%s: %s: status=%s reason=%q, want unresolved with %q", name, param, e.Status, e.Reason, c.want)
			}
		}
	}
	// 設定の記載は、security-realm の側と待ち受けの側の両方を記録する
	inv := host("", `<engine enabled-protocols="TLSv1.2"/>`, `enabled-protocols="TLSv1.2,TLSv1.3"`)
	var recorded []string
	for _, s := range inv.Settings {
		if s.Parameter == "tls.protocols" {
			recorded = append(recorded, strings.Join(s.Values, " "))
		}
	}
	if sortedJoin(recorded) != "TLSv1.2,TLSv1.2 TLSv1.3" {
		t.Errorf("recorded settings = %q", recorded)
	}
}

func TestWildFlyUnresolved(t *testing.T) {
	for name, c := range map[string]struct{ version, xml, want string }{
		"a version that is not measured": {"43.0.0.Final", wfElytron("", `ssl-context="labSSC"`), "no WildFly table"},
		"providers":                      {"42.0.0.Final", wfElytron(`providers="openssl"`, `ssl-context="labSSC"`), "providers"},
		"an SNI context":                 {"42.0.0.Final", wfElytron("", `ssl-context="labSNI"`), "server-ssl-sni-context"},
		"a context that does not exist":  {"42.0.0.Final", wfElytron("", `ssl-context="nosuch"`), "not found"},
		"an expression":                  {"42.0.0.Final", wfElytron(`cipher-suite-filter="${tls.ciphers:HIGH}"`, `ssl-context="labSSC"`), "expression"},
		"a filter Elytron rejects":       {"42.0.0.Final", wfElytron(`cipher-suite-filter="HIGH:nosuch"`, `ssl-context="labSSC"`), "cipher-suite-filter"},
		"names Elytron rejects":          {"42.0.0.Final", wfElytron(`cipher-suite-names="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"`, `ssl-context="labSSC"`), "cipher-suite-names"},
		"an unknown protocol":            {"42.0.0.Final", wfElytron(`protocols="TLSv1.4"`, `ssl-context="labSSC"`), "protocols"},
		"listener attributes with a context (the server refuses it)": {"42.0.0.Final", wfElytron("", `ssl-context="labSSC" enabled-protocols="TLSv1.2"`), "enabled-protocols"},
		"neither a context nor a realm":                              {"42.0.0.Final", wfElytron("", ""), "ssl-context"},
		"a DOCTYPE":                                                  {"42.0.0.Final", strings.Replace(wfElytron("", `ssl-context="labSSC"`), "<server ", "<!DOCTYPE server [<!ENTITY x \"y\">]>\n<server ", 1), "DOCTYPE"},
	} {
		_, inv := collect(t, "", wfHost(t, c.version, c.xml, nil))
		e := wfEff(t, inv, "tls.ciphers")
		if e.Status != "unresolved" || !strings.Contains(e.Reason, c.want) {
			t.Errorf("%s: status=%s reason=%q, want unresolved with %q", name, e.Status, e.Reason, c.want)
		}
	}
	// 測っていない版は、「測定が要る版」に残す
	_, inv := collect(t, "", wfHost(t, "43.0.0.Final", wfElytron("", `ssl-context="labSSC"`), nil))
	found := false
	for _, u := range inv.Unmeasured {
		found = found || (u.Kind == "wildfly" && u.Name == "wildfly" && u.Version == "43.0.0.Final" && u.Status == "missing")
	}
	if !found {
		t.Errorf("unmeasured = %+v", inv.Unmeasured)
	}
	// 版を読み取れない / WildFly でない製品
	_, inv = collect(t, "", wfHost(t, "42.0.0.Final", wfElytron("", `ssl-context="labSSC"`), map[string]string{wfProduct + "/wildfly-feature-pack-product-conf-42.0.0.Final.jar": ""}))
	wfUnresolved(t, inv, "version")
	_, inv = collect(t, "", wfHost(t, "30.0.0.Final", wfElytron("", `ssl-context="labSSC"`),
		map[string]string{wfProduct + "/dir/META-INF/MANIFEST.MF": "JBoss-Product-Release-Name: JBoss EAP\r\nJBoss-Product-Release-Version: 8.0.0.GA\r\n"}))
	wfUnresolved(t, inv, "not WildFly")
}

// どの設定ファイルで起動するかは、配布物に付いている systemd のユニットの形（launch.sh に、設定ファイルの名前を渡す）なら読む。
func TestWildFlyUnit(t *testing.T) {
	unit := "[Service]\nEnvironmentFile=-/etc/wildfly/wildfly.conf\nExecStart=/opt/wildfly/bin/launch.sh $WILDFLY_MODE $WILDFLY_CONFIG $WILDFLY_BIND\n"
	full := wfHome + "/standalone/configuration/standalone-full.xml"
	extra := map[string]string{
		"/etc/systemd/system/wildfly.service": unit,
		"/etc/wildfly/wildfly.conf":           "WILDFLY_CONFIG=standalone-full.xml\nWILDFLY_MODE=standalone\nWILDFLY_BIND=0.0.0.0\n",
		full:                                  wfElytron(`cipher-suite-filter="ECDHE+AESGCM"`, `ssl-context="labSSC"`),
	}
	host := wfHost(t, "42.0.0.Final", wfElytron("", `ssl-context="labSSC"`), extra)
	prefix, inv := collect(t, "", func(p string, b *inventory.Builder) {
		host(p, b)
		link(t, p, "/etc/systemd/system/wildfly.service", "/etc/systemd/system/multi-user.target.wants/wildfly.service")
	})
	svc := service(t, inv, "wildfly")
	if len(svc.ConfigFiles) != 1 || svc.ConfigFiles[0] != prefix+full || svc.Activity.Level != model.ActivityEnabled {
		t.Errorf("service = %+v", svc)
	}
	if got := sortedJoin(wfKind(wfEff(t, inv, "tls.ciphers").Values, "RSA")); got != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" {
		t.Errorf("ciphers = %s", got)
	}
	// ドメインのモードは、読まない（サービスの注記に残す）
	extra["/etc/wildfly/wildfly.conf"] = "WILDFLY_CONFIG=domain.xml\nWILDFLY_MODE=domain\nWILDFLY_BIND=0.0.0.0\n"
	_, inv = collect(t, "", wfHost(t, "42.0.0.Final", wfElytron("", `ssl-context="labSSC"`), extra))
	svc = service(t, inv, "wildfly")
	if !strings.Contains(strings.Join(svc.Notes, " "), "domain") {
		t.Errorf("notes = %v", svc.Notes)
	}
	for _, e := range inv.EffectiveValues {
		if e.Service == svc.ID {
			t.Errorf("a value is recorded in domain mode: %+v", e)
		}
	}
}

func TestWildFlyAbsentAndSeveral(t *testing.T) {
	_, inv := collect(t, "", nil)
	for _, s := range inv.Services {
		if s.App == "wildfly" {
			t.Errorf("service without WildFly: %+v", s)
		}
	}
	// 2 つ置かれていれば、それぞれを別のサービスとして記録する
	other := "/opt/wildfly-30.0.0.Final"
	host := wfHost(t, "42.0.0.Final", wfElytron("", `ssl-context="labSSC"`), map[string]string{
		other + "/standalone/configuration/standalone.xml":                                       wfElytron(`protocols="TLSv1.2"`, `ssl-context="labSSC"`),
		other + "/modules/system/layers/base/org/jboss/as/product/main/dir/META-INF/MANIFEST.MF": "JBoss-Product-Release-Name: WildFly Full\r\nJBoss-Product-Release-Version: 30.0.0.Final\r\n",
	})
	_, inv = collect(t, "", host)
	n := 0
	for _, s := range inv.Services {
		if s.App == "wildfly" {
			n++
		}
	}
	if e := eff(t, inv, "svc:wildfly:"+other, "tls.ciphers", wfScope); n != 2 || e.Status != "resolved" || e.Steps[0].Source.Version != "30.0.0.Final" {
		t.Errorf("services=%d other=%+v", n, e)
	}
}
