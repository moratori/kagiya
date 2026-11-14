// Package standalonexml は、WildFly の standalone.xml から、TLS に関わる記載を取り出す。
//
// 取り出すのは、決まった要素の、決まった属性だけ:
//
//   - Undertow の https-listener（どの設定で TLS を待ち受けるか）
//   - Elytron の server-ssl-context、key-manager、key-store（いまの形式）
//   - security-realm の ssl、engine、keystore（WildFly 24 までの古い形式）
//   - socket-binding（ポート）
//
// パスワードの記載（credential-reference の clear-text、keystore の keystore-password / key-password など）は、
// 名前の一覧にないので読まない。
//
// 外部のものは読みに行かない。Go の encoding/xml は実体の定義（DOCTYPE）を解釈しないが、
// DOCTYPE があるファイルは WildFly が読む内容と食い違いうるので、問題として返す（使う側は値を求めない）。
package standalonexml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strings"
)

const (
	maxDepth      = 64   // 要素の入れ子の上限
	maxElements   = 1024 // 取り出す要素（種類ごと）の数の上限
	maxValue      = 4096 // 属性の値の長さの上限（超えるものは読まない）
	maxTokenCount = 400000
)

// Attr は、属性の値と、その要素のある行。
type Attr struct {
	Value string
	Line  int
}

// Listener は、Undertow の https-listener。
type Listener struct {
	Server string // 属する server 要素の名前
	Attr   map[string]Attr
	Line   int
}

// Element は、名前の付いた要素 1 つ（決まった属性だけ）。
type Element struct {
	Attr map[string]Attr
	Line int
}

// KeyStore は、Elytron の key-store。
type KeyStore struct {
	Name       string
	Type       string // implementation の type
	Path       Attr   // file の path
	RelativeTo string // file の relative-to
	Line       int
}

// Realm は、古い形式の security-realm。
type Realm struct {
	Name      string
	HasSSL    bool // server-identities に ssl がある
	HasEngine bool // ssl に engine がある
	SSL       map[string]Attr
	Engine    map[string]Attr
	Keystore  map[string]Attr
	Line      int
}

// SocketBinding は、ポートの定義。Port は、書かれたままの値（「${jboss.https.port:8443}」のような式のことがある）。
type SocketBinding struct {
	Name string
	Port string
}

// File は、standalone.xml から取り出した内容。
type File struct {
	Listeners      []Listener
	SSLContexts    []Element
	SNIContexts    []string // server-ssl-sni-context の名前
	KeyManagers    []Element
	KeyStores      []KeyStore
	Realms         []Realm
	SocketBindings []SocketBinding
	// 空でなければ、内容をそのまま信用できない（理由）
	Problems []string
}

// 取り出す属性の名前（要素ごと）。ここにない属性は読まない。
var (
	listenerAttrs   = []string{"name", "socket-binding", "ssl-context", "security-realm", "enabled-protocols", "enabled-cipher-suites", "enabled", "verify-client"}
	sslContextAttrs = []string{"name", "cipher-suite-filter", "cipher-suite-names", "protocols", "key-manager", "trust-manager", "providers", "provider-name",
		"use-cipher-suites-order", "need-client-auth", "want-client-auth"}
	keyManagerAttrs = []string{"name", "key-store", "algorithm", "providers", "provider-name"}
	realmSSLAttrs   = []string{"protocol"}
	engineAttrs     = []string{"enabled-protocols", "enabled-cipher-suites"}
	keystoreAttrs   = []string{"path", "relative-to", "provider"}
)

const (
	elytronSpace  = "urn:wildfly:elytron:"
	undertowSpace = "urn:jboss:domain:undertow:"
)

type parser struct {
	f    *File
	data []byte
}

func (p *parser) problem(text string) {
	for _, x := range p.f.Problems {
		if x == text {
			return
		}
	}
	p.f.Problems = append(p.f.Problems, text)
}

// pick は、決まった名前の属性だけを取り出す。長すぎる値は読まず、問題として残す。
func (p *parser) pick(el xml.StartElement, names []string, line int) map[string]Attr {
	out := map[string]Attr{}
	for _, a := range el.Attr {
		if a.Name.Space != "" {
			continue
		}
		for _, n := range names {
			if a.Name.Local != n {
				continue
			}
			if len(a.Value) > maxValue {
				p.problem("the value of " + n + " is too long")
				break
			}
			out[n] = Attr{Value: a.Value, Line: line}
			break
		}
	}
	return out
}

// Parse は、standalone.xml を読む。XML として壊れている場合と、最上位が server でない場合はエラーを返す。
func Parse(data []byte) (*File, error) {
	f := &File{}
	p := &parser{f: f, data: data}
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
	subsystem := "" // いま中にいる subsystem の種類（elytron / undertow / それ以外は空）
	server := ""    // いま中にいる Undertow の server の名前
	var realm *Realm
	var store *KeyStore
	sawRoot := false
	for n := 0; ; n++ {
		if n > maxTokenCount {
			p.problem("the file has too many elements")
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
				p.problem("the file has a DOCTYPE (entity definitions are not interpreted)")
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
				if name != "server" || sawRoot {
					return nil, errors.New("the root element is not server")
				}
				sawRoot = true
			}
			if len(stack) >= maxDepth {
				p.problem("the elements are nested too deeply")
				if err := d.Skip(); err != nil {
					return nil, err
				}
				continue
			}
			path := strings.Join(stack, "/")
			full := func(n int) bool {
				if n >= maxElements {
					p.problem("too many " + name + " elements")
					return true
				}
				return false
			}
			switch {
			case path == "server/profile" && name == "subsystem":
				switch {
				case strings.HasPrefix(t.Name.Space, elytronSpace):
					subsystem = "elytron"
				case strings.HasPrefix(t.Name.Space, undertowSpace):
					subsystem = "undertow"
				default:
					subsystem = ""
				}
			case path == "server/management/security-realms" && name == "security-realm":
				if full(len(f.Realms)) {
					break
				}
				f.Realms = append(f.Realms, Realm{Name: p.pick(t, []string{"name"}, line)["name"].Value, Line: line})
				realm = &f.Realms[len(f.Realms)-1]
			case path == "server/management/security-realms/security-realm/server-identities" && name == "ssl" && realm != nil:
				realm.HasSSL, realm.SSL = true, p.pick(t, realmSSLAttrs, line)
			case path == "server/management/security-realms/security-realm/server-identities/ssl" && realm != nil && realm.HasSSL:
				switch name {
				case "engine":
					realm.HasEngine, realm.Engine = true, p.pick(t, engineAttrs, line)
				case "keystore":
					realm.Keystore = p.pick(t, keystoreAttrs, line)
				}
			case subsystem == "elytron" && path == "server/profile/subsystem/tls/key-stores" && name == "key-store":
				if full(len(f.KeyStores)) {
					break
				}
				f.KeyStores = append(f.KeyStores, KeyStore{Name: p.pick(t, []string{"name"}, line)["name"].Value, Line: line})
				store = &f.KeyStores[len(f.KeyStores)-1]
			case subsystem == "elytron" && path == "server/profile/subsystem/tls/key-stores/key-store" && store != nil:
				switch name {
				case "implementation":
					store.Type = p.pick(t, []string{"type"}, line)["type"].Value
				case "file":
					a := p.pick(t, []string{"path", "relative-to"}, line)
					store.Path, store.RelativeTo = a["path"], a["relative-to"].Value
				}
			case subsystem == "elytron" && path == "server/profile/subsystem/tls/key-managers" && name == "key-manager":
				if !full(len(f.KeyManagers)) {
					f.KeyManagers = append(f.KeyManagers, Element{Attr: p.pick(t, keyManagerAttrs, line), Line: line})
				}
			case subsystem == "elytron" && path == "server/profile/subsystem/tls/server-ssl-contexts" && name == "server-ssl-context":
				if !full(len(f.SSLContexts)) {
					f.SSLContexts = append(f.SSLContexts, Element{Attr: p.pick(t, sslContextAttrs, line), Line: line})
				}
			case subsystem == "elytron" && path == "server/profile/subsystem/tls/server-ssl-sni-contexts" && name == "server-ssl-sni-context":
				if !full(len(f.SNIContexts)) {
					f.SNIContexts = append(f.SNIContexts, p.pick(t, []string{"name"}, line)["name"].Value)
				}
			case subsystem == "undertow" && path == "server/profile/subsystem" && name == "server":
				server = p.pick(t, []string{"name"}, line)["name"].Value
			case subsystem == "undertow" && path == "server/profile/subsystem/server" && name == "https-listener":
				if !full(len(f.Listeners)) {
					f.Listeners = append(f.Listeners, Listener{Server: server, Attr: p.pick(t, listenerAttrs, line), Line: line})
				}
			case path == "server/socket-binding-group" && name == "socket-binding":
				if !full(len(f.SocketBindings)) {
					a := p.pick(t, []string{"name", "port"}, line)
					f.SocketBindings = append(f.SocketBindings, SocketBinding{Name: a["name"].Value, Port: a["port"].Value})
				}
			}
			stack = append(stack, name)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, errors.New("unbalanced element")
			}
			switch strings.Join(stack, "/") {
			case "server/profile/subsystem":
				subsystem, server = "", ""
			case "server/profile/subsystem/server":
				server = ""
			case "server/management/security-realms/security-realm":
				realm = nil
			case "server/profile/subsystem/tls/key-stores/key-store":
				store = nil
			}
			stack = stack[:len(stack)-1]
		}
	}
	if !sawRoot {
		return nil, errors.New("no root element")
	}
	return f, nil
}
