//go:build unix

package apps

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kagiya/internal/inventory"
	"kagiya/internal/model"
)

// 以下の期待値（プロトコル、スイートの数と要約値）は、検証ラボで各ディストリの Tomcat を導入して実際に起動し、同じコンテナ内からの
// ハンドシェイクで数え上げた結果と、参照モデル（Tomcat 自身の暗号指定の解釈 ∩ JDK の表）が一致することを確かめたうえで、
// その参照モデルから求めたもの（Debian 13 の tomcat10 10.1.60-1~deb13u1 + openjdk-21-jre-headless 21.0.13+9-1~deb13u2、
// AlmaLinux 9.8 の tomcat 9.0.121-1.el9_8 + java-1.8.0-openjdk-headless 1.8.0.504.b01-1.2.el9.alma.1、
// Ubuntu 24.04 の tomcat10 10.1.55-1ubuntu2~24.04.1 + openjdk-21-jre-headless 21.0.13.0.3+1-1~24.04.1）。

const (
	tcDebConf  = "/etc/tomcat10/server.xml"
	tcELConf   = "/etc/tomcat/server.xml"
	tcDebJava  = "/usr/lib/jvm/java-21-openjdk-arm64"
	tcScope    = "connector 8443"
	tcBoth12   = "ac7fad05bc5bcf16" // 既定の暗号指定、RSA と EC の証明書（21）
	tcAny12    = "698878ff8c0df26c" // 既定の暗号指定、証明書の種類が分からない（27）
	tcRSA12    = "71168486bfa11015" // 既定の暗号指定、RSA の証明書だけ（14）
	tcExpr12   = "67fb66c72d782074" // ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL（6）
	tcEL9RSA12 = "f816aa69be7b8671" // Java 8 + 暗号ポリシー、RSA の証明書（12）
	tcEL9TLS13 = "080c925e0b00a67d" // Java 8 の TLS 1.3 のスイート（2）
	tcLegacy12 = "d0c4642e39879585" // 古い書き方で 2 つを名指し（2）

	tcAPR      = `<Listener className="org.apache.catalina.core.AprLifecycleListener" />`
	tcCertRSA  = `<Certificate certificateKeyFile="/etc/lab/rsa.key" certificateFile="/etc/lab/rsa.crt" type="RSA"/>`
	tcCertEC   = `<Certificate certificateKeyFile="/etc/lab/ec.key" certificateFile="/etc/lab/ec.crt" type="EC"/>`
	tcNIO      = `protocol="org.apache.coyote.http11.Http11NioProtocol"`
	tcJSSEImpl = `sslImplementationName="org.apache.tomcat.util.net.jsse.JSSEImplementation"`
)

var (
	pkgTomcatDeb  = model.Package{Manager: "dpkg", Name: "tomcat10", Version: "10.1.60-1~deb13u1"}
	pkgTomcatUbu  = model.Package{Manager: "dpkg", Name: "tomcat10", Version: "10.1.55-1ubuntu2~24.04.1"}
	pkgTomcatEL9  = model.Package{Manager: "rpm", Name: "tomcat", Version: "9.0.121", Release: "1.el9_8"}
	pkgNativeDeb  = model.Package{Manager: "dpkg", Name: "libtcnative-1", Version: "1.3.1-1+b1"}
	pkgNativeUbu  = model.Package{Manager: "dpkg", Name: "libtcnative-2", Version: "2.0.14-1~24.04.1"}
	pkgJava21Deb  = model.Package{Manager: "dpkg", Name: "openjdk-21-jre-headless", Version: "21.0.13+9-1~deb13u2"}
	pkgJava21Ubu  = model.Package{Manager: "dpkg", Name: "openjdk-21-jre-headless", Version: "21.0.13.0.3+1-1~24.04.1"}
	tcDebPackages = []model.Package{pkgTomcatDeb, pkgNativeDeb, pkgJava21Deb}
)

// tcServer は、server.xml を組み立てる。connector は Connector の追加の属性、host は SSLHostConfig の属性、certs は証明書の要素。
func tcServer(listeners, connector, host, certs string) string {
	return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Server port=\"-1\">\n  " + listeners + "\n  <Service name=\"Catalina\">\n" +
		"    <Connector port=\"8080\" protocol=\"HTTP/1.1\"/>\n" +
		"    <Connector port=\"8443\" SSLEnabled=\"true\" " + connector + ">\n      <SSLHostConfig " + host + ">" + certs + "</SSLHostConfig>\n    </Connector>\n" +
		"    <Engine name=\"Catalina\" defaultHost=\"localhost\"/>\n  </Service>\n</Server>\n"
}

// tcDebian は、Debian 系の配置（設定、既定の Java へのリンク、java.security）を作る。
func tcDebian(t *testing.T, xml string, extra map[string]string, pkgs ...model.Package) func(p string, b *inventory.Builder) {
	files := map[string]string{tcDebConf: xml, tcDebJava + "/conf/security/java.security": "security.provider.1=SUN\n" + jdkUpstreamDisabled}
	for k, v := range extra {
		files[k] = v
	}
	host := jdkHost(t, files, pkgs...)
	return func(p string, b *inventory.Builder) {
		host(p, b)
		link(t, p, "java-21-openjdk-arm64", "/usr/lib/jvm/default-java")
	}
}

func tcEff(t *testing.T, inv *model.Inventory, param string) model.EffectiveValue {
	t.Helper()
	return eff(t, inv, "svc:tomcat", param, tcScope)
}

func tcUnresolved(t *testing.T, inv *model.Inventory, want string) {
	t.Helper()
	for _, p := range []string{"tls.protocols", "tls.ciphers", "tls.ciphersuites-tls13"} {
		e := tcEff(t, inv, p)
		if e.Status != "unresolved" || !strings.Contains(e.Reason, want) || len(e.Values) != 0 {
			t.Errorf("%s: status=%s reason=%q values=%d, want unresolved with %q", p, e.Status, e.Reason, len(e.Values), want)
		}
	}
}

// Debian 13: Tomcat Native が古くて読み込まれないので JDK の実装で動く。既定の暗号指定を Tomcat の表で解釈し、JDK が対応していて
// 無効にされていないものが残る。証明書が RSA と EC なら 21。
func TestTomcatDebianDefault(t *testing.T) {
	prefix, inv := collect(t, "", tcDebian(t, tcServer(tcAPR, tcNIO, "", tcCertRSA+tcCertEC), nil, tcDebPackages...))
	svc := service(t, inv, "tomcat")
	if svc.ID != "svc:tomcat" || len(svc.ConfigFiles) != 1 || svc.ConfigFiles[0] != prefix+tcDebConf {
		t.Errorf("service = %+v", svc)
	}
	p := tcEff(t, inv, "tls.protocols")
	if p.Status != "resolved" || strings.Join(p.Values, ",") != "TLSv1.3,TLSv1.2" || p.Confidence != "high" || p.Direction != "inbound" {
		t.Errorf("protocols = %+v", p)
	}
	e := tcEff(t, inv, "tls.ciphers")
	checkSuites(t, e, 21, tcBoth12, "high")
	if l := layers(e); l != "app-default/default library/intersect app-config/remove" {
		t.Errorf("steps = %s", l)
	}
	if s := e.Steps[0].Source; s == nil || s.Package != "tomcat10" || s.Version != "10.1.60-1~deb13u1" || !strings.HasPrefix(s.Image, "debian@sha256:") {
		t.Errorf("Tomcat source = %+v", e.Steps[0].Source)
	}
	if s := e.Steps[1].Source; s == nil || s.Package != "openjdk-21-jre-headless" {
		t.Errorf("JDK source = %+v", e.Steps[1].Source)
	}
	if !strings.Contains(strings.Join(e.Notes, " "), tcDebJava) || !strings.Contains(strings.Join(e.Notes, " "), "JDK") {
		t.Errorf("the notes must say which JDK and which implementation: %v", e.Notes)
	}
	checkSuites(t, tcEff(t, inv, "tls.ciphersuites-tls13"), 3, jdkTLS13, "high")
	g := tcEff(t, inv, "tls.groups")
	if g.Status != "resolved" || sortedJoin(g.Values) != jdkGroups {
		t.Errorf("groups = %+v", g)
	}
	// 証明書と鍵の記載を記録する（参照されているファイルとして扱うため）
	certs := find(inv, "tls.certificate")
	if len(certs) != 2 || certs[0].Scope != tcScope || certs[0].Location.Path != prefix+tcDebConf || certs[0].ReferencedPaths[0] != prefix+"/etc/lab/rsa.crt" {
		t.Errorf("certificate settings = %+v", certs)
	}
	if keys := find(inv, "tls.private-key"); len(keys) != 2 || keys[1].ReferencedPaths[0] != prefix+"/etc/lab/ec.key" {
		t.Errorf("key settings = %+v", keys)
	}
	// TLS を使わない Connector（8080）は対象にしない
	for _, x := range inv.EffectiveValues {
		if x.Service == "svc:tomcat" && x.Scope != tcScope {
			t.Errorf("unexpected scope %q", x.Scope)
		}
	}
}

// 設定に書かれた protocols と ciphers が効く。TLS 1.3 を外せば、TLS 1.3 のスイートは空になる。
func TestTomcatConfigured(t *testing.T) {
	xml := tcServer(tcAPR, tcNIO, `protocols="TLSv1.2" ciphers="ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL"`, tcCertRSA+tcCertEC)
	prefix, inv := collect(t, "", tcDebian(t, xml, nil, tcDebPackages...))
	if p := tcEff(t, inv, "tls.protocols"); p.Status != "resolved" || strings.Join(p.Values, ",") != "TLSv1.2" {
		t.Errorf("protocols = %+v", p)
	}
	e := tcEff(t, inv, "tls.ciphers")
	checkSuites(t, e, 6, tcExpr12, "high")
	if l := layers(e); l != "app-config/override library/intersect app-config/remove" {
		t.Errorf("steps = %s", l)
	}
	set := find(inv, "tls.ciphers")
	if len(set) != 1 || set[0].Location.Path != prefix+tcDebConf || set[0].Location.Line != 7 || strings.Join(set[0].Values, ":") != "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL" || e.Steps[0].Setting != set[0].ID {
		t.Errorf("ciphers setting = %+v (step %+v)", set, e.Steps[0])
	}
	if ps := find(inv, "tls.protocols"); len(ps) != 1 || strings.Join(ps[0].Values, ",") != "TLSv1.2" {
		t.Errorf("protocols setting = %+v", ps)
	}
	if e13 := tcEff(t, inv, "tls.ciphersuites-tls13"); e13.Status != "resolved" || len(e13.Values) != 0 {
		t.Errorf("TLS 1.3 suites = %+v", e13)
	}
	// 無効にされたプロトコルだけを書くと、何も受け入れない（実測）
	_, inv = collect(t, "", tcDebian(t, tcServer(tcAPR, tcNIO, `protocols="+TLSv1.1"`, tcCertRSA), nil, tcDebPackages...))
	if p := tcEff(t, inv, "tls.protocols"); p.Status != "resolved" || len(p.Values) != 0 {
		t.Errorf("protocols = %+v", p)
	}
	if e := tcEff(t, inv, "tls.ciphers"); e.Status != "resolved" || len(e.Values) != 0 {
		t.Errorf("ciphers = %+v", e)
	}
}

// 証明書の種類: RSA だけなら RSA で認証するスイートだけ。種類が分からなければ絞り込まず、確度を下げる。
func TestTomcatCertificateKinds(t *testing.T) {
	_, inv := collect(t, "", tcDebian(t, tcServer(tcAPR, tcNIO, "", tcCertRSA), nil, tcDebPackages...))
	checkSuites(t, tcEff(t, inv, "tls.ciphers"), 14, tcRSA12, "high")

	ks := `<Certificate certificateKeystoreFile="conf/server.p12" certificateKeystorePassword="s3cret-tomcat" certificateKeystoreType="PKCS12"/>`
	prefix, inv := collect(t, "", tcDebian(t, tcServer(tcAPR, tcNIO, "", ks), nil, tcDebPackages...))
	e := tcEff(t, inv, "tls.ciphers")
	checkSuites(t, e, 27, tcAny12, "medium")
	if !strings.Contains(strings.Join(e.Notes, " "), "certificate") {
		t.Errorf("the note must say that the kind of the certificate is not known: %v", e.Notes)
	}
	// キーストアの場所は記録する（相対パスは CATALINA_BASE から）。パスワードは、どこにも出さない
	if k := find(inv, "tls.keystore"); len(k) != 1 || k[0].ReferencedPaths[0] != prefix+"/var/lib/tomcat10/conf/server.p12" {
		t.Errorf("keystore setting = %+v", k)
	}
	out, _ := json.Marshal(inv)
	if strings.Contains(string(out), "s3cret") {
		t.Error("a password from server.xml appears in the result")
	}
}

// AlmaLinux 9: Java は /etc/tomcat/tomcat.conf の JAVA_HOME（Java 8）。暗号ポリシーが効く。古い書き方（Connector に直接）も読む。
func TestTomcatRHEL9(t *testing.T) {
	sec := jdkEL9Home8 + "/jre/lib/security/java.security"
	files := map[string]string{
		tcELConf:                  tcServer("", tcNIO, "", tcCertRSA),
		"/etc/tomcat/tomcat.conf": "TOMCAT_CFG_LOADED=\"1\"\nJAVA_HOME=\"/usr/lib/jvm/jre\"\nCATALINA_HOME=\"/usr/share/tomcat\"\nJAVA_OPTS=\"-Djavax.sql.DataSource.Factory=org.apache.commons.dbcp.BasicDataSourceFactory\"\n",
		sec:                       "security.useSystemPropertiesFile=true\n" + jdk8Disabled,
		jdkPolicyFile:             jdkPolicy(t, "alma9"),
	}
	host := func(xml string) func(p string, b *inventory.Builder) {
		files[tcELConf] = xml
		h := jdkHost(t, files, pkgTomcatEL9, pkgEL9J8)
		return func(p string, b *inventory.Builder) {
			h(p, b)
			link(t, p, filepath.Base(jdkEL9Home8)+"/jre", "/usr/lib/jvm/jre")
		}
	}
	_, inv := collect(t, "", host(files[tcELConf]))
	if p := tcEff(t, inv, "tls.protocols"); p.Status != "resolved" || strings.Join(p.Values, ",") != "TLSv1.3,TLSv1.2" {
		t.Errorf("protocols = %+v", p)
	}
	e := tcEff(t, inv, "tls.ciphers")
	checkSuites(t, e, 12, tcEL9RSA12, "high")
	if l := layers(e); l != "app-default/default library/intersect os-policy/remove" {
		t.Errorf("steps = %s", l)
	}
	checkSuites(t, tcEff(t, inv, "tls.ciphersuites-tls13"), 2, tcEL9TLS13, "high")

	// 古い書き方
	old := "<Server><Service><Connector port=\"8443\" SSLEnabled=\"true\" " + tcNIO + " keystoreFile=\"/etc/lab/rsa.p12\" keystorePass=\"s3cret-old\" keystoreType=\"PKCS12\" " +
		"sslEnabledProtocols=\"TLSv1.2\" ciphers=\"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_128_GCM_SHA256\"/></Service></Server>"
	_, inv = collect(t, "", host(old))
	if p := tcEff(t, inv, "tls.protocols"); p.Status != "resolved" || strings.Join(p.Values, ",") != "TLSv1.2" {
		t.Errorf("legacy protocols = %+v", p)
	}
	// 証明書の種類は分からない（キーストア）が、名指しされた 2 つはどちらも RSA の証明書で成り立つ
	checkSuites(t, tcEff(t, inv, "tls.ciphers"), 2, tcLegacy12, "medium")
	out, _ := json.Marshal(inv)
	if strings.Contains(string(out), "s3cret") {
		t.Error("a password from server.xml appears in the result")
	}
}

// Ubuntu 24.04: Tomcat Native が読み込まれ、OpenSSL の実装で動く。その場合の値は、まだ求めない。
// JDK の実装を明示するか、リスナーを外せば、JDK の実装で動く（実測）。
func TestTomcatImplementation(t *testing.T) {
	ubuntu := []model.Package{pkgTomcatUbu, pkgNativeUbu, pkgJava21Ubu}
	both := tcCertRSA + tcCertEC
	_, inv := collect(t, "", tcDebian(t, tcServer(tcAPR, tcNIO, "", both), nil, ubuntu...))
	tcUnresolved(t, inv, "Tomcat Native")

	_, inv = collect(t, "", tcDebian(t, tcServer(tcAPR, tcNIO+" "+tcJSSEImpl, "", both), nil, ubuntu...))
	checkSuites(t, tcEff(t, inv, "tls.ciphers"), 21, tcBoth12, "high")

	_, inv = collect(t, "", tcDebian(t, tcServer("", tcNIO, "", both), nil, ubuntu...))
	checkSuites(t, tcEff(t, inv, "tls.ciphers"), 21, tcBoth12, "high")

	// Tomcat Native が導入されていなければ、リスナーがあっても JDK の実装で動く
	_, inv = collect(t, "", tcDebian(t, tcServer(tcAPR, tcNIO, "", both), nil, pkgTomcatUbu, pkgJava21Ubu))
	checkSuites(t, tcEff(t, inv, "tls.ciphers"), 21, tcBoth12, "high")

	// OpenSSL の実装を明示している
	impl := `sslImplementationName="org.apache.tomcat.util.net.openssl.OpenSSLImplementation"`
	_, inv = collect(t, "", tcDebian(t, tcServer(tcAPR, tcNIO+" "+impl, "", both), nil, ubuntu...))
	tcUnresolved(t, inv, "OpenSSL")

	// 測っていない実装や Connector の種類
	_, inv = collect(t, "", tcDebian(t, tcServer(tcAPR, tcNIO+` sslImplementationName="com.example.MyImpl"`, "", both), nil, tcDebPackages...))
	tcUnresolved(t, inv, "sslImplementationName")
	_, inv = collect(t, "", tcDebian(t, tcServer(tcAPR, `protocol="com.example.MyProtocol"`, "", both), nil, tcDebPackages...))
	tcUnresolved(t, inv, "protocol")
}

// 求めない場合: 値を確定できない記載、Java の起動のしかたを変える設定、測っていない版。理由を残す。
func TestTomcatUnresolved(t *testing.T) {
	both := tcCertRSA + tcCertEC
	plain := tcServer(tcAPR, tcNIO, "", both)
	for name, c := range map[string]struct {
		xml   string
		extra map[string]string
		pkgs  []model.Package
		want  string
	}{
		"placeholder":    {tcServer(tcAPR, tcNIO, `ciphers="${tls.ciphers}"`, both), nil, tcDebPackages, "ciphers"},
		"bad ciphers":    {tcServer(tcAPR, tcNIO, `ciphers="HIGH&#10;x"`, both), nil, tcDebPackages, "ciphers"},
		"doctype":        {"<!DOCTYPE Server [<!ENTITY x \"HIGH\">]>" + plain, nil, tcDebPackages, "server.xml"},
		"setenv":         {plain, map[string]string{"/var/lib/tomcat10/bin/setenv.sh": "JAVA_HOME=/opt/java\n"}, tcDebPackages, "setenv.sh"},
		"java options":   {plain, map[string]string{"/etc/default/tomcat10": "JAVA_OPTS=\"-Djava.awt.headless=true -Djava.security.properties=/etc/x\"\n"}, tcDebPackages, "JAVA_OPTS"},
		"java home":      {plain, map[string]string{"/etc/default/tomcat10": "JAVA_HOME=/opt/myjava\n"}, tcDebPackages, "JAVA_HOME"},
		"no table":       {plain, nil, []model.Package{{Manager: "dpkg", Name: "tomcat10", Version: "10.1.99-1~deb13u1"}, pkgJava21Deb}, "no Tomcat table"},
		"no package":     {plain, nil, []model.Package{pkgJava21Deb}, "package"},
		"no jdk package": {plain, nil, []model.Package{pkgTomcatDeb}, "JDK"},
		"ffm listener":   {tcServer(`<Listener className="org.apache.catalina.core.OpenSSLLifecycleListener"/>`, tcNIO, "", both), nil, tcDebPackages, "OpenSSLLifecycleListener"},
		"old native":     {plain, nil, []model.Package{pkgTomcatDeb, pkgJava21Deb, {Manager: "dpkg", Name: "libtcnative-1", Version: "garbage"}}, "Tomcat Native"},
	} {
		_, inv := collect(t, "", tcDebian(t, c.xml, c.extra, c.pkgs...))
		t.Run(name, func(t *testing.T) { tcUnresolved(t, inv, c.want) })
	}
	// 既定のままの環境ファイル（コメントと、暗号に関係しないオプション）は妨げにならない
	_, inv := collect(t, "", tcDebian(t, plain, map[string]string{"/etc/default/tomcat10": "# JAVA_HOME=/usr/lib/jvm/x\nJAVA_OPTS=\"-Djava.awt.headless=true\"\n"}, tcDebPackages...))
	checkSuites(t, tcEff(t, inv, "tls.ciphers"), 21, tcBoth12, "high")
	// groups の指定がある場合は、グループだけ求めない（スイートは求める）
	_, inv = collect(t, "", tcDebian(t, tcServer(tcAPR, tcNIO, `groups="secp384r1,x25519"`, tcCertRSA), nil, tcDebPackages...))
	checkSuites(t, tcEff(t, inv, "tls.ciphers"), 14, tcRSA12, "high")
	if g := tcEff(t, inv, "tls.groups"); g.Status != "unresolved" || !strings.Contains(g.Reason, "groups") {
		t.Errorf("groups = %+v", g)
	}
}

// 表にないリリースの Tomcat は、上流の版とディストリの系列が同じ表で補い、確度を下げる。
func TestTomcatInterpolated(t *testing.T) {
	pkgs := []model.Package{{Manager: "dpkg", Name: "tomcat10", Version: "10.1.60-1~deb13u9"}, pkgJava21Deb}
	_, inv := collect(t, "", tcDebian(t, tcServer(tcAPR, tcNIO, "", tcCertRSA+tcCertEC), nil, pkgs...))
	e := tcEff(t, inv, "tls.ciphers")
	checkSuites(t, e, 21, tcBoth12, "medium")
	if !strings.Contains(strings.Join(e.Notes, " "), "10.1.60-1~deb13u1") {
		t.Errorf("notes = %v", e.Notes)
	}
}

// server.xml がなければ、何も記録しない。
func TestTomcatAbsent(t *testing.T) {
	_, inv := collect(t, "", func(p string, b *inventory.Builder) { os.MkdirAll(p+"/etc", 0o755) })
	for _, s := range inv.Services {
		if s.App == "tomcat" {
			t.Errorf("unexpected service %+v", s)
		}
	}
}

// groups を書いていて、EC の証明書がある（または証明書の種類が分からない）場合は、TLS 1.2 以下のスイートを求めない。
// EC の証明書の曲線が groups に含まれないと、ECDSA で認証するスイートは成り立たない（実測: 21 のうち 14 だけになった）。
func TestTomcatGroupsWithECCertificate(t *testing.T) {
	_, inv := collect(t, "", tcDebian(t, tcServer(tcAPR, tcNIO, `groups="secp384r1,x25519"`, tcCertRSA+tcCertEC), nil, tcDebPackages...))
	if e := tcEff(t, inv, "tls.ciphers"); e.Status != "unresolved" || !strings.Contains(e.Reason, "groups") {
		t.Errorf("ciphers = %+v", e)
	}
	// プロトコルと TLS 1.3 のスイートは求める
	if p := tcEff(t, inv, "tls.protocols"); p.Status != "resolved" || len(p.Values) != 2 {
		t.Errorf("protocols = %+v", p)
	}
	checkSuites(t, tcEff(t, inv, "tls.ciphersuites-tls13"), 3, jdkTLS13, "high")
}

// Tomcat 10.1 以降は、TLS の設定を Connector に直接書く古い書き方では起動しない（実測）。その版では値を求めない。
func TestTomcatLegacyAttributesOnNewTomcat(t *testing.T) {
	old := "<Server><Service><Connector port=\"8443\" SSLEnabled=\"true\" " + tcNIO + " keystoreFile=\"/etc/lab/rsa.p12\" keystoreType=\"PKCS12\" sslEnabledProtocols=\"TLSv1.2\"/></Service></Server>"
	_, inv := collect(t, "", tcDebian(t, old, nil, tcDebPackages...))
	tcUnresolved(t, inv, "SSLHostConfig")
}

// cipherSuites 属性（TLS 1.3 のスイートの指定）は、JDK の実装では効かなかった（実測: 指定しても 3 つとも受け入れた）。
// それを確かめた版では既定のまま求めて注記し、確かめていない版では TLS 1.3 のスイートを求めない。
func TestTomcatCipherSuitesAttribute(t *testing.T) {
	host := `cipherSuites="TLS_AES_128_GCM_SHA256"`
	_, inv := collect(t, "", tcDebian(t, tcServer(tcAPR, tcNIO, host, tcCertRSA), nil, tcDebPackages...))
	e := tcEff(t, inv, "tls.ciphersuites-tls13")
	checkSuites(t, e, 3, jdkTLS13, "high")
	if !strings.Contains(strings.Join(e.Notes, " "), "cipherSuites") {
		t.Errorf("notes = %v", e.Notes)
	}
	checkSuites(t, tcEff(t, inv, "tls.ciphers"), 14, tcRSA12, "high")
	// Ubuntu 24.04 の版（10.1.55）は、JDK の実装でこの属性を測っていない
	_, inv = collect(t, "", tcDebian(t, tcServer(tcAPR, tcNIO+" "+tcJSSEImpl, host, tcCertRSA), nil, pkgTomcatUbu, pkgNativeUbu, pkgJava21Ubu))
	if e := tcEff(t, inv, "tls.ciphersuites-tls13"); e.Status != "unresolved" || !strings.Contains(e.Reason, "cipherSuites") {
		t.Errorf("TLS 1.3 suites = %+v", e)
	}
	checkSuites(t, tcEff(t, inv, "tls.ciphers"), 14, tcRSA12, "high")
}
