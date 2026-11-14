package springconf

import (
	"strings"
	"testing"
)

func load(files map[string]string) *Config {
	return Load(func(name string) ([]byte, bool) {
		s, ok := files[name]
		return []byte(s), ok
	})
}

func get(t *testing.T, c *Config, key string) string {
	t.Helper()
	v, _ := c.Get(key)
	return v.Value
}

// properties の書き方: 区切り（= : 空白）、コメント、行の継続、前後の空白。
func TestProperties(t *testing.T) {
	c := load(map[string]string{"application.properties": "# comment\n! comment\nserver.port=8443\nserver.ssl.enabled : true\n" +
		"server.ssl.key-store   /etc/app/ks.p12\nserver.ssl.ciphers=TLS_AES_128_GCM_SHA256,\\\n    TLS_AES_256_GCM_SHA384\n\nserver.ssl.protocol = TLS  \n"})
	if len(c.Problems) != 0 {
		t.Errorf("problems = %v", c.Problems)
	}
	if get(t, c, "server.port") != "8443" || get(t, c, "server.ssl.enabled") != "true" || get(t, c, "server.ssl.key-store") != "/etc/app/ks.p12" || get(t, c, "server.ssl.protocol") != "TLS" {
		t.Errorf("values = %+v", c)
	}
	if got, _ := c.List("server.ssl.ciphers"); strings.Join(got, "|") != "TLS_AES_128_GCM_SHA256|TLS_AES_256_GCM_SHA384" {
		t.Errorf("ciphers = %v", got)
	}
	v, ok := c.Get("server.ssl.key-store")
	if !ok || v.File != "application.properties" || v.Line != 5 {
		t.Errorf("location = %+v", v)
	}
	// 添字つきの並び
	c = load(map[string]string{"application.properties": "server.ssl.ciphers[1]=B\nserver.ssl.ciphers[0]=A\n"})
	if got, at := c.List("server.ssl.ciphers"); strings.Join(got, "|") != "A|B" || at.Line != 2 {
		t.Errorf("indexed list = %v %+v", got, at)
	}
}

// YAML の書き方: 入れ子、並び（- と [ ]）、コンマ区切りの文字列。
func TestYAML(t *testing.T) {
	c := load(map[string]string{"application.yml": "server:\n  port: 8443\n  ssl:\n    key-store: /etc/app/ks.p12\n    enabled-protocols: [TLSv1.2, TLSv1.3]\n    ciphers:\n      - A\n      - B\n" +
		"spring:\n  ssl:\n    bundle:\n      jks:\n        web:\n          keystore:\n            location: /etc/app/b.p12\n          options:\n            ciphers: X,Y\n"})
	if len(c.Problems) != 0 {
		t.Errorf("problems = %v", c.Problems)
	}
	if get(t, c, "server.port") != "8443" || get(t, c, "server.ssl.key-store") != "/etc/app/ks.p12" || get(t, c, "spring.ssl.bundle.jks.web.keystore.location") != "/etc/app/b.p12" {
		t.Errorf("values = %+v", c)
	}
	if got, _ := c.List("server.ssl.enabled-protocols"); strings.Join(got, "|") != "TLSv1.2|TLSv1.3" {
		t.Errorf("protocols = %v", got)
	}
	if got, at := c.List("server.ssl.ciphers"); strings.Join(got, "|") != "A|B" || at.File != "application.yml" || at.Line != 7 {
		t.Errorf("ciphers = %v %+v", got, at)
	}
	if got, _ := c.List("spring.ssl.bundle.jks.web.options.ciphers"); strings.Join(got, "|") != "X|Y" {
		t.Errorf("bundle ciphers = %v", got)
	}
	// 拡張子は .yaml でもよい
	c = load(map[string]string{"application.yaml": "server:\n  ssl:\n    protocol: TLSv1.3\n"})
	if get(t, c, "server.ssl.protocol") != "TLSv1.3" {
		t.Error("application.yaml must be read")
	}
}

// 優先順（実測）: 同じ場所では properties が yml に勝つ。有効にしたプロファイルの設定が上書きする。有効にしていないプロファイルは読まない。
func TestPrecedence(t *testing.T) {
	c := load(map[string]string{
		"application.properties": "server.ssl.enabled-protocols=TLSv1.3\n",
		"application.yml":        "server:\n  ssl:\n    enabled-protocols: TLSv1.2\n    protocol: TLS\n"})
	if get(t, c, "server.ssl.enabled-protocols") != "TLSv1.3" || get(t, c, "server.ssl.protocol") != "TLS" {
		t.Errorf("properties must win: %+v", c)
	}
	files := map[string]string{
		"application.properties":      "server.ssl.key-store=/a.p12\n",
		"application-prod.properties": "server.ssl.enabled-protocols=TLSv1.2\n",
		"application-dev.yml":         "server:\n  ssl:\n    enabled-protocols: TLSv1.1\n"}
	c = load(files)
	if _, ok := c.Get("server.ssl.enabled-protocols"); ok {
		t.Error("an inactive profile must not be read")
	}
	files["application.properties"] += "spring.profiles.active=prod\n"
	c = load(files)
	if get(t, c, "server.ssl.enabled-protocols") != "TLSv1.2" || strings.Join(c.Profiles, ",") != "prod" {
		t.Errorf("active profile: %+v", c)
	}
	// 1 つのファイルに複数の文書がある YAML: プロファイルの条件つきの文書は、そのプロファイルが有効なときだけ
	multi := "server:\n  ssl:\n    key-store: /a.p12\nspring:\n  profiles:\n    active: prod\n---\nspring:\n  config:\n    activate:\n      on-profile: prod\nserver:\n  ssl:\n    enabled-protocols: TLSv1.2\n" +
		"---\nspring:\n  config:\n    activate:\n      on-profile: dev\nserver:\n  ssl:\n    enabled-protocols: TLSv1.1\n"
	c = load(map[string]string{"application.yml": multi})
	if get(t, c, "server.ssl.enabled-protocols") != "TLSv1.2" {
		t.Errorf("multi-document yaml: %+v", c)
	}
}

// 取り出すのは、許可した項目だけ。パスワードの項目と、設定に直接書かれた鍵の中身は、読んでも持たない。
func TestAllowList(t *testing.T) {
	pem := "-----BEGIN PRIVATE KEY-----\\nMIIEvs3cretKEY\\n-----END PRIVATE KEY-----"
	c := load(map[string]string{"application.properties": "server.ssl.key-store-password=s3cret-A\nserver.ssl.key-password=s3cret-B\nspring.datasource.password=s3cret-C\n" +
		"spring.ssl.bundle.jks.web.keystore.password=s3cret-D\nspring.ssl.bundle.pem.web.keystore.private-key-password=s3cret-E\n" +
		"spring.ssl.bundle.pem.web.keystore.private-key=" + pem + "\nserver.ssl.certificate-private-key=/etc/app/key.pem\n" +
		"my.app.secret=s3cret-F\nserver.ssl.key-store=/etc/app/ks.p12\nserver.ssl.trust-store-password=s3cret-G\n"})
	for _, k := range c.Keys() {
		v, _ := c.Get(k)
		if strings.Contains(strings.ToLower(k), "password") || strings.Contains(v.Value, "s3cret") || strings.Contains(v.Value, "BEGIN") {
			t.Errorf("a secret was kept: %s", k)
		}
	}
	if get(t, c, "server.ssl.key-store") != "/etc/app/ks.p12" || get(t, c, "server.ssl.certificate-private-key") != "/etc/app/key.pem" {
		t.Errorf("allowed items must be kept: %v", c.Keys())
	}
	if len(c.Keys()) != 2 {
		t.Errorf("keys = %v", c.Keys())
	}
	// 鍵の中身が直接書かれていたことは、値を持たずに記録する
	if !c.Inline["spring.ssl.bundle.pem.web.keystore.private-key"] {
		t.Errorf("inline key material must be noted without its value: %v", c.Inline)
	}
}

// 名前のゆるい対応（Spring は keyStore、key_store、KEY-STORE を同じ項目として扱う）と、解釈しない値（${...}）。
func TestBindingAndPlaceholders(t *testing.T) {
	c := load(map[string]string{"application.properties": "server.ssl.keyStore=/a.p12\nserver.ssl.ENABLED_PROTOCOLS=TLSv1.3\nSERVER.SSL.Key-Store-Type=PKCS12\n"})
	if get(t, c, "server.ssl.key-store") != "/a.p12" || get(t, c, "server.ssl.enabled-protocols") != "TLSv1.3" || get(t, c, "server.ssl.key-store-type") != "PKCS12" {
		t.Errorf("relaxed binding: %v", c.Keys())
	}
	c = load(map[string]string{"application.properties": "server.ssl.ciphers=${TLS_CIPHERS}\nserver.ssl.key-store=${app.home}/ks.p12\nserver.ssl.enabled-protocols=TLSv1.3\n"})
	if _, ok := c.Get("server.ssl.ciphers"); ok {
		t.Error("a placeholder must not be kept as a value")
	}
	if !c.Unresolved["server.ssl.ciphers"] || !c.Unresolved["server.ssl.key-store"] || c.Unresolved["server.ssl.enabled-protocols"] {
		t.Errorf("unresolved = %v", c.Unresolved)
	}
}

// 壊れた YAML、別名（アンカー）を使った YAML、大きすぎる・深すぎる内容でも止まらない。問題として記録する。
func TestProblems(t *testing.T) {
	for name, y := range map[string]string{
		"broken": "server:\n  ssl: [unclosed\n",
		"alias":  "base: &b\n  ssl:\n    protocol: TLS\nserver: *b\n",
		"deep": func() string {
			s := ""
			for i := 0; i < 200; i++ {
				s += strings.Repeat(" ", i) + "k:\n"
			}
			return s + strings.Repeat(" ", 200) + "v: 1\n"
		}(),
	} {
		c := load(map[string]string{"application.yml": y})
		if len(c.Problems) == 0 {
			t.Errorf("%s: expected a problem", name)
		}
	}
	// 項目が多すぎる properties
	var b strings.Builder
	for i := 0; i < 20000; i++ {
		b.WriteString("server.ssl.ciphers[")
		b.WriteString(strings.Repeat("9", 1+i%5))
		b.WriteString("]=X\n")
	}
	if c := load(map[string]string{"application.properties": b.String()}); len(c.Keys()) > 1024 {
		t.Errorf("too many keys kept: %d", len(c.Keys()))
	}
	// 設定ファイルがなければ、空
	if c := load(nil); len(c.Keys()) != 0 || len(c.Problems) != 0 {
		t.Errorf("empty = %+v", c)
	}
}
