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
	wfHome     = "/opt/wildfly"
	wfConf     = wfHome + "/standalone/configuration/standalone.xml"
	wfProduct  = wfHome + "/modules/system/layers/base/org/jboss/as/product/main"
	wfScope    = "https-listener default-server/https"
	wfJava17   = "/usr/lib/jvm/java-17-openjdk-arm64"
	wfJava11   = "/usr/lib/jvm/java-11-openjdk-arm64"
	wfRSA12    = "71168486bfa11015" // 既定、RSA の証明書（14）
	wfEC12     = "96f46569772374f7" // 既定、EC の証明書（7）
	wfECDHE12  = "0e092f295e359427" // ECDHE だけ、RSA の証明書（7）
	wfTLS13All = "0298a462f55e65f8" // JDK の TLS 1.3 のスイート（3）
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
	for _, p := range []string{"tls.protocols", "tls.ciphers", "tls.ciphersuites-tls13", "tls.groups"} {
		e := wfEff(t, inv, p)
		if e.Status != "unresolved" || !strings.Contains(e.Reason, want) || len(e.Values) != 0 {
			t.Errorf("%s: status=%s reason=%q values=%d, want unresolved with %q", p, e.Status, e.Reason, len(e.Values), want)
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
	// どの JDK で動くかは決められない（JAVA_HOME の指定がない）ので、見つかった JDK で同じになる値として、確度は中
	if p.Status != "resolved" || strings.Join(p.Values, ",") != "TLSv1.2" || p.Confidence != "medium" || p.Direction != "inbound" {
		t.Errorf("protocols = %+v", p)
	}
	e := wfEff(t, inv, "tls.ciphers")
	wfCheck(t, e, "medium", "RSA", 14, wfRSA12)
	wfCheck(t, e, "medium", "EC", 7, wfEC12) // 場面 e-eccert
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
	if g := wfEff(t, inv, "tls.groups"); g.Status != "resolved" || strings.Join(g.Values, ",") != "x25519,secp256r1,secp384r1,secp521r1,x448,ffdhe2048,ffdhe3072,ffdhe4096,ffdhe6144,ffdhe8192" {
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
	if got := sortedJoin(wfKind(e.Values, "RSA")); got != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" || e.Confidence != "medium" {
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
	wfCheck(t, wfEff(t, inv, "tls.ciphers"), "medium", "RSA", 7, wfECDHE12)
	// 場面 e-filter-alias: OpenSSL 式の名前
	_, inv = collect(t, "", wfHost(t, "42.0.0.Final", wfElytron(`cipher-suite-filter="ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-SHA"`, `ssl-context="labSSC"`), nil))
	if got := sortedJoin(wfEff(t, inv, "tls.ciphers").Values); got != "TLS_DHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" {
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
	// 証明書の種類は分からないので、暗号スイートの確度は中のまま
	if e := wfEff(t, inv, "tls.ciphers"); e.Confidence != "medium" || e.Steps[1].Source.Package != "openjdk-17-jre-headless" {
		t.Errorf("ciphers = %s %+v", e.Confidence, e.Steps)
	}
	// JAVA_HOME の指定がなく、JDK が 2 つある: どちらでも同じ結果なので確定（確度は中）
	_, inv = collect(t, "", wfHost(t, "42.0.0.Final", wfElytron("", `ssl-context="labSSC"`), nil, pkgJava17Ubu, pkgJava11Ubu))
	e := wfEff(t, inv, "tls.ciphers")
	wfCheck(t, e, "medium", "RSA", 14, wfRSA12)
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
	wfCheck(t, wfEff(t, inv, "tls.ciphers"), "medium", "RSA", 14, wfRSA12)
	if e13 := wfEff(t, inv, "tls.ciphersuites-tls13"); e13.Status != "resolved" || len(e13.Values) != 0 {
		t.Errorf("tls13 = %+v", e13)
	}
	// 場面 l-protocols13: engine の enabled-protocols に TLSv1.3 を入れると、JDK の TLS 1.3 のスイートを受け入れる
	inv = host("", `<engine enabled-protocols="TLSv1.2 TLSv1.3"/>`, "")
	if p, e13 := wfEff(t, inv, "tls.protocols"), wfEff(t, inv, "tls.ciphersuites-tls13"); strings.Join(p.Values, ",") != "TLSv1.3,TLSv1.2" || len(e13.Values) != 3 || setDigest(e13.Values) != wfTLS13All {
		t.Errorf("protocols=%v tls13=%v", p.Values, e13.Values)
	}
	wfCheck(t, wfEff(t, inv, "tls.ciphers"), "medium", "RSA", 14, wfRSA12)
	// 場面 l-ciphers: engine の enabled-cipher-suites（Java での名前）
	inv = host("", `<engine enabled-cipher-suites="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"/>`, "")
	if got := sortedJoin(wfEff(t, inv, "tls.ciphers").Values); got != "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
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
	// 測っていない書き方は、求めない
	for name, c := range map[string][3]string{
		"another value of protocol":        {`protocol="TLSv1.2"`, "", ""},
		"several protocols on a listener":  {"", "", `enabled-protocols="TLSv1.2,TLSv1.3"`},
		"OpenSSL names on a listener":      {"", "", `enabled-cipher-suites="ECDHE-RSA-AES256-GCM-SHA384"`},
		"both the engine and the listener": {"", `<engine enabled-protocols="TLSv1.2"/>`, `enabled-protocols="TLSv1.3"`},
		"unknown names in the engine":      {"", `<engine enabled-cipher-suites="ECDHE-RSA-AES256-GCM-SHA384"/>`, ""},
	} {
		inv = host(c[0], c[1], c[2])
		if e := wfEff(t, inv, "tls.ciphers"); e.Status != "unresolved" || !strings.Contains(e.Reason, "measured") {
			t.Errorf("%s: %+v", name, e)
		}
	}
	// 25 以降には、この形式がない
	_, inv = collect(t, "", wfHost(t, "25.0.0.Final", wfLegacy("", "", ""), nil, pkgJava11Ubu))
	wfUnresolved(t, inv, "security-realm")
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
	if got := sortedJoin(wfKind(wfEff(t, inv, "tls.ciphers").Values, "RSA")); got != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" {
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
