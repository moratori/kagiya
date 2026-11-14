// Package serverxml は、Tomcat の server.xml から、TLS に関わる記載を取り出す。
//
// 取り出すのは、決まった要素（Listener、Connector、SSLHostConfig、Certificate）の、決まった属性だけ。
// パスワードの属性（certificateKeystorePassword、keystorePass など）は、名前の一覧にないので読まない。
//
// 外部のものは読みに行かない。Go の encoding/xml は実体の定義（DOCTYPE）を解釈しないが、
// DOCTYPE があるファイルは Tomcat が読む内容と食い違いうるので、問題として返す（使う側は値を求めない）。
package serverxml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strings"
)

const (
	maxDepth      = 64   // 要素の入れ子の上限
	maxElements   = 256  // 取り出す要素（種類ごと）の数の上限
	maxValue      = 4096 // 属性の値の長さの上限（超えるものは読まない）
	maxTokenCount = 200000
)

// Attr は、属性の値と、その要素のある行。
type Attr struct {
	Value string
	Line  int
}

// Listener は、Server の直下の Listener 要素。
type Listener struct {
	ClassName string
	Attr      map[string]Attr
	Line      int
}

// Certificate は、SSLHostConfig の中の Certificate 要素。
type Certificate struct {
	Attr map[string]Attr
	Line int
}

// Host は、Connector の中の SSLHostConfig 要素。
type Host struct {
	Attr         map[string]Attr
	Certificates []Certificate
	Line         int
}

// Connector は、Service の直下の Connector 要素。
type Connector struct {
	Attr  map[string]Attr
	Hosts []Host
	Line  int
}

// File は、server.xml から取り出した内容。
type File struct {
	Listeners  []Listener
	Connectors []Connector
	// 空でなければ、内容をそのまま信用できない（理由）
	Problems []string
}

// 取り出す属性の名前（要素ごと）。ここにない属性は読まない。
var (
	listenerAttrs  = []string{"className", "SSLEngine", "useOpenSSL", "useAprConnector", "FIPSMode", "SSLRandomSeed"}
	connectorAttrs = []string{"port", "protocol", "SSLEnabled", "secure", "scheme", "sslImplementationName", "defaultSSLHostConfigName",
		// 古い書き方（Connector に直接書く）
		"ciphers", "sslEnabledProtocols", "sslProtocol", "honorCipherOrder", "useServerCipherSuitesOrder",
		"keystoreFile", "keystoreType", "truststoreFile", "truststoreType", "clientAuth",
		"SSLCertificateFile", "SSLCertificateKeyFile", "SSLCertificateChainFile", "SSLCACertificateFile", "SSLCipherSuite", "SSLProtocol", "SSLHonorCipherOrder"}
	hostAttrs = []string{"hostName", "protocols", "ciphers", "cipherSuites", "groups", "honorCipherOrder", "sslProtocol",
		"certificateVerification", "truststoreFile", "truststoreType", "caCertificateFile", "caCertificatePath", "disableSessionTickets", "insecureRenegotiation"}
	certificateAttrs = []string{"type", "certificateFile", "certificateKeyFile", "certificateChainFile",
		"certificateKeystoreFile", "certificateKeystoreType", "certificateKeystoreProvider", "certificateKeyAlias"}
)

// pick は、決まった名前の属性だけを取り出す。名前は、先頭の 1 文字だけ大文字小文字を区別しない
// （Tomcat は「set + 先頭を大文字にした名前」のメソッドを探すので、port と Port は同じで、ciphersuites と cipherSuites は別）。
func pick(el xml.StartElement, names []string, line int) map[string]Attr {
	out := map[string]Attr{}
	for _, a := range el.Attr {
		if a.Name.Space != "" || a.Name.Local == "" || len(a.Value) > maxValue {
			continue
		}
		for _, n := range names {
			if a.Name.Local[1:] == n[1:] && strings.EqualFold(a.Name.Local[:1], n[:1]) {
				out[n] = Attr{Value: a.Value, Line: line}
				break
			}
		}
	}
	return out
}

// Parse は、server.xml を読む。XML として壊れている場合と、最上位が Server でない場合はエラーを返す。
func Parse(data []byte) (*File, error) {
	f := &File{}
	problem := func(p string) {
		for _, x := range f.Problems {
			if x == p {
				return
			}
		}
		f.Problems = append(f.Problems, p)
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = true
	d.Entity = nil
	// 文字コードの変換はしない（UTF-8 と、その部分集合として読めるものだけ）
	d.CharsetReader = func(label string, r io.Reader) (io.Reader, error) {
		switch strings.ToLower(label) {
		case "utf-8", "us-ascii", "ascii":
			return r, nil
		}
		return nil, errors.New("unsupported encoding: " + label)
	}
	var stack []string
	var conn *Connector
	var host *Host
	sawRoot := false
	for n := 0; ; n++ {
		if n > maxTokenCount {
			problem("the file has too many elements")
			break
		}
		off := d.InputOffset()
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.Directive:
			if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(string(t))), "DOCTYPE") {
				problem("the file has a DOCTYPE (entity definitions are not interpreted)")
			}
		case xml.StartElement:
			// 要素の開始位置の行（トークンの前の空白を飛ばす）
			start := int(off)
			for start < len(data) && data[start] != '<' {
				start++
			}
			line := 1 + bytes.Count(data[:start], []byte("\n"))
			name := t.Name.Local
			if len(stack) == 0 {
				if name != "Server" || sawRoot {
					return nil, errors.New("the root element is not Server")
				}
				sawRoot = true
			}
			if len(stack) >= maxDepth {
				problem("the elements are nested too deeply")
				if err := d.Skip(); err != nil {
					return nil, err
				}
				continue
			}
			path := strings.Join(stack, "/")
			switch {
			case path == "Server" && name == "Listener":
				if len(f.Listeners) >= maxElements {
					problem("too many Listener elements")
					break
				}
				a := pick(t, listenerAttrs, line)
				f.Listeners = append(f.Listeners, Listener{ClassName: a["className"].Value, Attr: a, Line: line})
			case path == "Server/Service" && name == "Connector":
				if len(f.Connectors) >= maxElements {
					problem("too many Connector elements")
					break
				}
				f.Connectors = append(f.Connectors, Connector{Attr: pick(t, connectorAttrs, line), Line: line})
				conn = &f.Connectors[len(f.Connectors)-1]
			case path == "Server/Service/Connector" && name == "SSLHostConfig" && conn != nil:
				if len(conn.Hosts) >= maxElements {
					problem("too many SSLHostConfig elements")
					break
				}
				conn.Hosts = append(conn.Hosts, Host{Attr: pick(t, hostAttrs, line), Line: line})
				host = &conn.Hosts[len(conn.Hosts)-1]
			case path == "Server/Service/Connector/SSLHostConfig" && name == "Certificate" && host != nil:
				if len(host.Certificates) >= maxElements {
					problem("too many Certificate elements")
					break
				}
				host.Certificates = append(host.Certificates, Certificate{Attr: pick(t, certificateAttrs, line), Line: line})
			}
			stack = append(stack, name)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, errors.New("unbalanced element")
			}
			switch strings.Join(stack, "/") {
			case "Server/Service/Connector":
				conn, host = nil, nil
			case "Server/Service/Connector/SSLHostConfig":
				host = nil
			}
			stack = stack[:len(stack)-1]
		}
	}
	if !sawRoot {
		return nil, errors.New("the root element is not Server")
	}
	return f, nil
}
