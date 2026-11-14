// Package standalonexml は、WildFly の standalone.xml から、TLS に関わる記載を取り出す。
package standalonexml

import "errors"

// Attr は、属性の値と、その要素のある行。
type Attr struct {
	Value string
	Line  int
}

// Listener は、Undertow の https-listener。
type Listener struct {
	Server string
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
	Type       string
	Path       Attr
	RelativeTo string
	Line       int
}

// Realm は、古い形式の security-realm。
type Realm struct {
	Name      string
	HasSSL    bool
	HasEngine bool
	SSL       map[string]Attr
	Engine    map[string]Attr
	Keystore  map[string]Attr
	Line      int
}

// SocketBinding は、ポートの定義。
type SocketBinding struct {
	Name string
	Port string
}

// File は、standalone.xml から取り出した内容。
type File struct {
	Listeners      []Listener
	SSLContexts    []Element
	SNIContexts    []string
	KeyManagers    []Element
	KeyStores      []KeyStore
	Realms         []Realm
	SocketBindings []SocketBinding
	Problems       []string
}

// Parse は、standalone.xml を読む。
func Parse(data []byte) (*File, error) {
	return nil, errors.New("not implemented")
}
