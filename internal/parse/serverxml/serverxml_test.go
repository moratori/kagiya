package serverxml

import (
	"strings"
	"testing"
)

const sample = `<?xml version="1.0" encoding="UTF-8"?>
<!-- comment <Connector port="1" SSLEnabled="true"/> -->
<Server port="-1" shutdown="SHUTDOWN">
  <Listener className="org.apache.catalina.startup.VersionLoggerListener" />
  <Listener className="org.apache.catalina.core.AprLifecycleListener" SSLEngine="on" />
  <Service name="Catalina">
    <Connector port="8080" protocol="HTTP/1.1" redirectPort="8443" />
    <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol" SSLEnabled="true"
               sslImplementationName="org.apache.tomcat.util.net.jsse.JSSEImplementation" address="127.0.0.1">
      <SSLHostConfig protocols="TLSv1.2+TLSv1.3" ciphers="HIGH:!aNULL" honorCipherOrder="true" cipherSuites="TLS_AES_128_GCM_SHA256" groups="x25519">
        <Certificate certificateKeyFile="conf/rsa.key" certificateFile="conf/rsa.crt" type="RSA" certificateKeyPassword="s3cret-A"/>
        <Certificate certificateKeystoreFile="/etc/lab/ec.p12" certificateKeystorePassword="s3cret-B" certificateKeystoreType="PKCS12" type="EC"/>
      </SSLHostConfig>
      <SSLHostConfig hostName="other.test">
        <Certificate certificateKeystoreFile="conf/other.jks"/>
      </SSLHostConfig>
    </Connector>
    <Connector port="9443" SSLEnabled="true" keystoreFile="/etc/lab/rsa.p12" keystorePass="s3cret-C" keystoreType="PKCS12"
               sslEnabledProtocols="TLSv1.2" ciphers="TLS_RSA_WITH_AES_128_GCM_SHA256" sslProtocol="TLS"/>
    <Engine name="Catalina" defaultHost="localhost"><Host name="localhost"/></Engine>
  </Service>
</Server>
`

// 決まった要素の、決まった属性だけを取り出す。パスワードの属性は読まない。
func TestParse(t *testing.T) {
	f, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Problems) != 0 {
		t.Errorf("problems = %v", f.Problems)
	}
	if len(f.Listeners) != 2 || f.Listeners[1].ClassName != "org.apache.catalina.core.AprLifecycleListener" || f.Listeners[1].Attr["SSLEngine"].Value != "on" || f.Listeners[1].Line != 5 {
		t.Errorf("listeners = %+v", f.Listeners)
	}
	if len(f.Connectors) != 3 {
		t.Fatalf("connectors = %d", len(f.Connectors))
	}
	c := f.Connectors[1]
	if c.Attr["port"].Value != "8443" || c.Attr["SSLEnabled"].Value != "true" || !strings.HasSuffix(c.Attr["sslImplementationName"].Value, "JSSEImplementation") || c.Line != 8 {
		t.Errorf("connector = %+v", c)
	}
	if _, ok := c.Attr["address"]; ok {
		t.Error("attributes outside the allowed set must not be kept")
	}
	if len(c.Hosts) != 2 {
		t.Fatalf("hosts = %d", len(c.Hosts))
	}
	h := c.Hosts[0]
	if h.Attr["protocols"].Value != "TLSv1.2+TLSv1.3" || h.Attr["ciphers"].Value != "HIGH:!aNULL" || h.Attr["cipherSuites"].Value != "TLS_AES_128_GCM_SHA256" ||
		h.Attr["groups"].Value != "x25519" || h.Attr["honorCipherOrder"].Value != "true" || h.Line != 10 || h.Attr["ciphers"].Line != 10 {
		t.Errorf("host = %+v", h)
	}
	if len(h.Certificates) != 2 || h.Certificates[0].Attr["certificateFile"].Value != "conf/rsa.crt" || h.Certificates[0].Attr["type"].Value != "RSA" ||
		h.Certificates[1].Attr["certificateKeystoreFile"].Value != "/etc/lab/ec.p12" || h.Certificates[1].Attr["certificateKeystoreType"].Value != "PKCS12" || h.Certificates[1].Line != 12 {
		t.Errorf("certificates = %+v", h.Certificates)
	}
	if c.Hosts[1].Attr["hostName"].Value != "other.test" || len(c.Hosts[1].Certificates) != 1 {
		t.Errorf("second host = %+v", c.Hosts[1])
	}
	old := f.Connectors[2]
	if old.Attr["keystoreFile"].Value != "/etc/lab/rsa.p12" || old.Attr["sslEnabledProtocols"].Value != "TLSv1.2" || old.Attr["ciphers"].Value != "TLS_RSA_WITH_AES_128_GCM_SHA256" || len(old.Hosts) != 0 {
		t.Errorf("legacy connector = %+v", old)
	}
	// パスワードは、どこにも残らない
	for _, c := range f.Connectors {
		all := []map[string]Attr{c.Attr}
		for _, h := range c.Hosts {
			all = append(all, h.Attr)
			for _, x := range h.Certificates {
				all = append(all, x.Attr)
			}
		}
		for _, m := range all {
			for k, v := range m {
				if strings.Contains(strings.ToLower(k), "pass") || strings.Contains(v.Value, "s3cret") {
					t.Errorf("a password was kept: %s", k)
				}
			}
		}
	}
}

// 属性の名前は、先頭の 1 文字だけ大文字小文字を区別しない（Tomcat と同じ）。それ以外の違いは別の名前として扱い、読まない。
func TestAttributeNames(t *testing.T) {
	f, err := Parse([]byte(`<Server><Service><Connector Port="8443" SSLEnabled="true"><SSLHostConfig Ciphers="HIGH" ciphersuites="X" PROTOCOLS="TLSv1.2"/></Connector></Service></Server>`))
	if err != nil {
		t.Fatal(err)
	}
	h := f.Connectors[0].Hosts[0]
	if f.Connectors[0].Attr["port"].Value != "8443" || h.Attr["ciphers"].Value != "HIGH" {
		t.Errorf("first letter must be case-insensitive: %+v %+v", f.Connectors[0].Attr, h.Attr)
	}
	if _, ok := h.Attr["cipherSuites"]; ok {
		t.Error("ciphersuites is not cipherSuites")
	}
	if _, ok := h.Attr["protocols"]; ok {
		t.Error("PROTOCOLS is not protocols")
	}
}

// 解釈しないもの: DOCTYPE（実体の定義。外部参照を含みうる）、壊れた XML、多すぎる要素。外部のものは読みに行かない。
func TestProblems(t *testing.T) {
	doctype := `<?xml version="1.0"?><!DOCTYPE Server [<!ENTITY x SYSTEM "file:///etc/hostname">]><Server><Service><Connector port="8443" SSLEnabled="true" ciphers="&x;"/></Service></Server>`
	if f, err := Parse([]byte(doctype)); err == nil && len(f.Problems) == 0 {
		t.Error("a DOCTYPE must be reported")
	}
	if _, err := Parse([]byte(`<Server><Service><Connector port="8443"`)); err == nil {
		t.Error("broken XML must be an error")
	}
	if _, err := Parse([]byte(`<Other/>`)); err == nil {
		t.Error("the root element must be Server")
	}
	many := "<Server><Service>" + strings.Repeat(`<Connector port="1"/>`, 300) + "</Service></Server>"
	if f, err := Parse([]byte(many)); err == nil && len(f.Problems) == 0 {
		t.Error("too many connectors must be reported")
	}
	deep := "<Server>" + strings.Repeat("<a>", 200) + strings.Repeat("</a>", 200) + "</Server>"
	if f, err := Parse([]byte(deep)); err == nil && len(f.Problems) == 0 {
		t.Error("too deep nesting must be reported")
	}
	// 設定の置き換え（${...}）は、値をそのまま返す（解釈するかどうかは使う側が決める）
	f, err := Parse([]byte(`<Server><Service><Connector port="${port.https}" SSLEnabled="true"/></Service></Server>`))
	if err != nil || f.Connectors[0].Attr["port"].Value != "${port.https}" {
		t.Errorf("placeholder: %v %+v", err, f)
	}
}

// 位置が入れ子の決まりに合わない要素（Service の外の Connector など）は読まない。
func TestStructure(t *testing.T) {
	f, err := Parse([]byte(`<Server><Connector port="1" SSLEnabled="true"/><Service><Engine><Connector port="2"/></Engine><Connector port="3"><Certificate type="RSA"/></Connector></Service></Server>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Connectors) != 1 || f.Connectors[0].Attr["port"].Value != "3" || len(f.Connectors[0].Hosts) != 0 {
		t.Errorf("connectors = %+v", f.Connectors)
	}
}
