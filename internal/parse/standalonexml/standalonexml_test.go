package standalonexml

import (
	"fmt"
	"strings"
	"testing"
)

// WildFly 42.0.0.Final の既定の standalone.xml の形（検証ラボで配布物を展開して確かめた）を、TLS に関わる部分だけに縮めたもの。
// パスワードの記載（credential-reference の clear-text）は、実物にもある。読まないことを確かめるために入れている。
const elytronForm = `<?xml version="1.0" encoding="UTF-8"?>
<server xmlns="urn:jboss:domain:community:20.0">
    <management>
        <management-interfaces>
            <http-interface http-authentication-factory="management-http-authentication">
                <socket-binding http="management-http"/>
            </http-interface>
        </management-interfaces>
    </management>
    <profile>
        <subsystem xmlns="urn:wildfly:elytron:community:19.0" final-providers="combined-providers">
            <tls>
                <key-stores>
                    <key-store name="applicationKS">
                        <credential-reference clear-text="SECRET-PASSWORD"/>
                        <implementation type="PKCS12"/>
                        <file path="application.keystore" relative-to="jboss.server.config.dir"/>
                    </key-store>
                </key-stores>
                <key-managers>
                    <key-manager name="applicationKM" key-store="applicationKS" generate-self-signed-certificate-host="localhost">
                        <credential-reference clear-text="SECRET-PASSWORD"/>
                    </key-manager>
                </key-managers>
                <server-ssl-contexts>
                    <server-ssl-context name="applicationSSC" cipher-suite-filter="ECDHE+AESGCM" cipher-suite-names="TLS_AES_128_GCM_SHA256"
                        protocols="TLSv1.2 TLSv1.3" key-manager="applicationKM"/>
                    <server-ssl-context name="otherSSC" key-manager="applicationKM" providers="openssl" use-cipher-suites-order="false"/>
                </server-ssl-contexts>
                <server-ssl-sni-contexts>
                    <server-ssl-sni-context name="sni" default-ssl-context="applicationSSC"/>
                </server-ssl-sni-contexts>
            </tls>
        </subsystem>
        <subsystem xmlns="urn:jboss:domain:undertow:15.0" default-server="default-server">
            <server name="default-server">
                <http-listener name="default" socket-binding="http" redirect-socket="https"/>
                <https-listener name="https" socket-binding="https" ssl-context="applicationSSC" enable-http2="true"/>
            </server>
        </subsystem>
        <subsystem xmlns="urn:example:other:1.0">
            <server name="not-undertow">
                <https-listener name="fake" socket-binding="https" ssl-context="x"/>
            </server>
        </subsystem>
    </profile>
    <socket-binding-group name="standard-sockets" default-interface="public" port-offset="${jboss.socket.binding.port-offset:0}">
        <socket-binding name="http" port="${jboss.http.port:8080}"/>
        <socket-binding name="https" port="${jboss.https.port:8443}"/>
    </socket-binding-group>
</server>
`

func TestParseElytronForm(t *testing.T) {
	f, err := Parse([]byte(elytronForm))
	if err != nil || len(f.Problems) != 0 {
		t.Fatalf("err=%v problems=%v", err, f.Problems)
	}
	if len(f.Listeners) != 1 {
		t.Fatalf("listeners = %+v (only the https-listener of the undertow subsystem is taken)", f.Listeners)
	}
	l := f.Listeners[0]
	if l.Server != "default-server" || l.Attr["name"].Value != "https" || l.Attr["ssl-context"].Value != "applicationSSC" || l.Attr["socket-binding"].Value != "https" || l.Line != 38 {
		t.Errorf("listener = %+v", l)
	}
	if _, ok := l.Attr["enable-http2"]; ok {
		t.Error("an attribute that is not in the list is taken")
	}
	if len(f.SSLContexts) != 2 {
		t.Fatalf("ssl contexts = %+v", f.SSLContexts)
	}
	c := f.SSLContexts[0].Attr
	if c["name"].Value != "applicationSSC" || c["cipher-suite-filter"].Value != "ECDHE+AESGCM" || c["cipher-suite-names"].Value != "TLS_AES_128_GCM_SHA256" ||
		c["protocols"].Value != "TLSv1.2 TLSv1.3" || c["key-manager"].Value != "applicationKM" || c["cipher-suite-filter"].Line != 26 {
		t.Errorf("ssl context = %+v", c)
	}
	if o := f.SSLContexts[1].Attr; o["providers"].Value != "openssl" || o["use-cipher-suites-order"].Value != "false" {
		t.Errorf("ssl context 2 = %+v", o)
	}
	if len(f.SNIContexts) != 1 || f.SNIContexts[0] != "sni" {
		t.Errorf("sni contexts = %v", f.SNIContexts)
	}
	if len(f.KeyManagers) != 1 || f.KeyManagers[0].Attr["key-store"].Value != "applicationKS" {
		t.Errorf("key managers = %+v", f.KeyManagers)
	}
	if len(f.KeyStores) != 1 {
		t.Fatalf("key stores = %+v", f.KeyStores)
	}
	if k := f.KeyStores[0]; k.Name != "applicationKS" || k.Type != "PKCS12" || k.Path.Value != "application.keystore" || k.RelativeTo != "jboss.server.config.dir" || k.Path.Line != 17 {
		t.Errorf("key store = %+v", k)
	}
	if len(f.SocketBindings) != 2 || f.SocketBindings[1].Name != "https" || f.SocketBindings[1].Port != "${jboss.https.port:8443}" {
		t.Errorf("socket bindings = %+v", f.SocketBindings)
	}
	// パスワードは、どこにも残らない
	if strings.Contains(fmt.Sprintf("%+v", f), "SECRET") {
		t.Error("a password is kept")
	}
}

// WildFly 24 までの古い形式（security-realm）。keystore 要素には、パスワードが属性として書かれている。
const legacyForm = `<?xml version='1.0' encoding='UTF-8'?>
<server xmlns="urn:jboss:domain:17.0">
    <management>
        <security-realms>
            <security-realm name="ApplicationRealm">
                <server-identities>
                    <ssl protocol="TLSv1.2">
                        <engine enabled-cipher-suites="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" enabled-protocols="TLSv1.2 TLSv1.3"/>
                        <keystore path="application.keystore" relative-to="jboss.server.config.dir" keystore-password="SECRET-PASSWORD" alias="server" key-password="SECRET-PASSWORD" generate-self-signed-certificate-host="localhost"/>
                    </ssl>
                </server-identities>
            </security-realm>
            <security-realm name="ManagementRealm">
                <authentication><local default-user="$local"/></authentication>
            </security-realm>
        </security-realms>
    </management>
    <profile>
        <subsystem xmlns="urn:jboss:domain:undertow:12.0">
            <server name="default-server">
                <https-listener name="https" socket-binding="https" security-realm="ApplicationRealm" enabled-protocols="TLSv1.3" enabled-cipher-suites="TLS_AES_128_GCM_SHA256" enable-http2="true"/>
            </server>
        </subsystem>
    </profile>
    <socket-binding-group name="standard-sockets" default-interface="public">
        <socket-binding name="https" port="8443"/>
    </socket-binding-group>
</server>
`

func TestParseLegacyForm(t *testing.T) {
	f, err := Parse([]byte(legacyForm))
	if err != nil || len(f.Problems) != 0 {
		t.Fatalf("err=%v problems=%v", err, f.Problems)
	}
	if len(f.Realms) != 2 {
		t.Fatalf("realms = %+v", f.Realms)
	}
	r := f.Realms[0]
	if r.Name != "ApplicationRealm" || !r.HasSSL || r.SSL["protocol"].Value != "TLSv1.2" || !r.HasEngine ||
		r.Engine["enabled-protocols"].Value != "TLSv1.2 TLSv1.3" || !strings.HasPrefix(r.Engine["enabled-cipher-suites"].Value, "TLS_ECDHE_RSA") ||
		r.Keystore["path"].Value != "application.keystore" || r.Keystore["relative-to"].Value != "jboss.server.config.dir" || r.Keystore["path"].Line != 9 {
		t.Errorf("realm = %+v", r)
	}
	if f.Realms[1].HasSSL {
		t.Error("a realm without ssl is marked as having it")
	}
	if l := f.Listeners[0].Attr; l["security-realm"].Value != "ApplicationRealm" || l["enabled-protocols"].Value != "TLSv1.3" || l["enabled-cipher-suites"].Value != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("listener = %+v", l)
	}
	if strings.Contains(fmt.Sprintf("%+v", f), "SECRET") {
		t.Error("a password is kept")
	}
}

// 管理用の待ち受け（management-interfaces）。検証ラボで、WildFly 42.0.0.Final と 24.0.1.Final に、管理用のコマンドで TLS を設定したときの形
// （lab/out/tlsapp/wildfly-mgmt）を、関わる部分だけに縮めたもの。native-interface と、古い書き方の socket 要素は、スキーマにある形。
const managementForm = `<?xml version="1.0" encoding="UTF-8"?>
<server xmlns="urn:jboss:domain:community:20.0">
    <management>
        <management-interfaces>
            <http-interface http-authentication-factory="management-http-authentication" ssl-context="labSSC" security-realm="ManagementRealm" console-enabled="true">
                <http-upgrade enabled="true" sasl-authentication-factory="management-sasl-authentication"/>
                <socket-binding http="management-http" https="management-https"/>
            </http-interface>
            <native-interface ssl-context="nativeSSC">
                <socket-binding native="management-native"/>
            </native-interface>
        </management-interfaces>
    </management>
    <profile>
        <subsystem xmlns="urn:example:other:1.0">
            <management-interfaces>
                <http-interface ssl-context="fake"><socket-binding https="fake"/></http-interface>
            </management-interfaces>
        </subsystem>
    </profile>
    <socket-binding-group name="standard-sockets" default-interface="public">
        <socket-binding name="management-http" interface="management" port="${jboss.management.http.port:9990}"/>
        <socket-binding name="management-https" interface="management" port="${jboss.management.https.port:9993}"/>
    </socket-binding-group>
</server>
`

func TestParseManagementInterfaces(t *testing.T) {
	f, err := Parse([]byte(managementForm))
	if err != nil || len(f.Problems) != 0 {
		t.Fatalf("err=%v problems=%v", err, f.Problems)
	}
	if len(f.Management) != 2 {
		t.Fatalf("management interfaces = %+v (only those under server/management are taken)", f.Management)
	}
	h := f.Management[0]
	if h.Kind != "http-interface" || h.Line != 5 || h.Attr["ssl-context"].Value != "labSSC" || h.Attr["ssl-context"].Line != 5 || h.Attr["security-realm"].Value != "ManagementRealm" ||
		h.Binding["http"].Value != "management-http" || h.Binding["https"].Value != "management-https" || h.Binding["https"].Line != 7 || h.Socket {
		t.Errorf("http-interface = %+v", h)
	}
	for _, name := range []string{"console-enabled", "http-authentication-factory"} {
		if _, ok := h.Attr[name]; ok {
			t.Errorf("an attribute that is not in the list is taken: %s", name)
		}
	}
	n := f.Management[1]
	if n.Kind != "native-interface" || n.Attr["ssl-context"].Value != "nativeSSC" || n.Binding["native"].Value != "management-native" || n.Line != 9 {
		t.Errorf("native-interface = %+v", n)
	}
	if len(f.SocketBindings) != 2 || f.SocketBindings[1].Name != "management-https" || f.SocketBindings[1].Port != "${jboss.management.https.port:9993}" {
		t.Errorf("socket bindings = %+v", f.SocketBindings)
	}

	// 配布物のままの形（TLS の設定も、TLS 用のソケットもない）
	f, err = Parse([]byte(elytronForm))
	if err != nil || len(f.Management) != 1 {
		t.Fatalf("err=%v management=%+v", err, f.Management)
	}
	if d := f.Management[0]; d.Kind != "http-interface" || len(d.Attr) != 0 || d.Binding["http"].Value != "management-http" || d.Binding["https"].Value != "" {
		t.Errorf("default http-interface = %+v", d)
	}

	// 古い書き方（socket 要素に、interface と port を直接書く）は、あることだけを残す
	f, err = Parse([]byte(`<server xmlns="urn:jboss:domain:17.0"><management><management-interfaces>
<http-interface security-realm="ManagementRealm"><socket interface="management" port="9990" secure-port="9993"/></http-interface>
</management-interfaces></management></server>`))
	if err != nil || len(f.Management) != 1 || !f.Management[0].Socket || len(f.Management[0].Binding) != 0 {
		t.Errorf("socket form: err=%v management=%+v", err, f.Management)
	}
}

func TestParseRejectsAndProblems(t *testing.T) {
	for name, text := range map[string]string{
		"not xml":    "this is not xml <",
		"other root": `<Server><Service/></Server>`,
		"domain":     `<domain xmlns="urn:jboss:domain:20.0"/>`,
		"encoding":   `<?xml version="1.0" encoding="Shift_JIS"?><server/>`,
		"empty":      "",
	} {
		if f, err := Parse([]byte(text)); err == nil {
			t.Errorf("%s: must be an error, got %+v", name, f)
		}
	}
	// DOCTYPE（実体の定義）があるファイルは、WildFly が読む内容と食い違いうるので、問題として返す。外部のものは読みに行かない
	f, err := Parse([]byte(`<!DOCTYPE server [<!ENTITY x SYSTEM "file:///etc/passwd">]><server xmlns="urn:jboss:domain:20.0"><profile/></server>`))
	if err != nil || len(f.Problems) == 0 {
		t.Errorf("DOCTYPE: err=%v problems=%v", err, f.Problems)
	}
	// 長すぎる値は読まない（その属性はなかったことにせず、問題として返す）
	long := `<server xmlns="urn:jboss:domain:20.0"><profile><subsystem xmlns="urn:wildfly:elytron:18.0"><tls><server-ssl-contexts><server-ssl-context name="a" cipher-suite-filter="` +
		strings.Repeat("HIGH:", 2000) + `"/></server-ssl-contexts></tls></subsystem></profile></server>`
	f, err = Parse([]byte(long))
	if err != nil || len(f.Problems) == 0 {
		t.Errorf("long value: err=%v problems=%v", err, f.Problems)
	}
	// 要素が多すぎる場合
	var b strings.Builder
	b.WriteString(`<server xmlns="urn:jboss:domain:20.0"><socket-binding-group name="s">`)
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&b, `<socket-binding name="b%d" port="%d"/>`, i, 1000+i)
	}
	b.WriteString(`</socket-binding-group></server>`)
	f, err = Parse([]byte(b.String()))
	if err != nil || len(f.Problems) == 0 || len(f.SocketBindings) > 1024 {
		t.Errorf("many elements: err=%v problems=%v n=%d", err, f.Problems, len(f.SocketBindings))
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(elytronForm))
	f.Add([]byte(legacyForm))
	f.Add([]byte(managementForm))
	f.Add([]byte(`<server><profile><subsystem xmlns="urn:wildfly:elytron:1.0"><tls><key-stores><key-store><file/></key-store></key-stores></tls></subsystem></profile></server>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		file, err := Parse(data)
		if err != nil {
			return
		}
		if len(file.Listeners) > 1024 || len(file.SSLContexts) > 1024 || len(file.KeyStores) > 1024 || len(file.Realms) > 1024 || len(file.SocketBindings) > 1024 || len(file.Management) > 1024 {
			t.Fatal("too many elements are kept")
		}
	})
}
