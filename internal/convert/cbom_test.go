package convert

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"kagiya/internal/model"
)

const fp1 = "001686cd181f83a1b1217d305b365c41e3470a78a1d37b134a98cd547b92dab3"
const fp2 = "32d180ed31c935589ec9dbbb722123b883b5fc2dc10f9fca3a95d77e1bfcb534"

// cbomSample は、証明書・鍵・サービスの設定を含む結果。
func cbomSample() *model.Inventory {
	yes := true
	inv := &model.Inventory{
		Schema: model.Schema,
		Meta: model.Meta{ScanID: "d381586eb279993c2d9ba4527aa4f3a3", StartedAt: "2026-11-12T13:37:00Z", FinishedAt: "2026-11-12T13:37:02Z", Completed: true,
			Tool: model.Tool{Version: "0.1.0"}, Rules: model.Rules{Source: "builtin", Version: "2026.11.0"},
			Host:   model.Host{Hostname: "web01", OS: "linux", Arch: "amd64", Distribution: &model.Distribution{ID: "rhel", VersionID: "9.9", Name: "Red Hat Enterprise Linux 9.9 (Plow)"}},
			Labels: map[string]string{"system": "portal"}},
		Assets: []model.Asset{
			{ID: "alg:rsa-2048", Type: "algorithm", Algorithm: &model.Algorithm{Family: "RSA", Primitive: "public-key", KeyBits: 2048, RawName: "1.2.840.113549.1.1.1", Scheme: "oid", Known: true}},
			{ID: "alg:sha256-with-rsa", Type: "algorithm", Algorithm: &model.Algorithm{Family: "RSA", Primitive: "signature", RawName: "1.2.840.113549.1.1.11", Scheme: "oid", Known: true}},
			{ID: "alg:aes-256-cbc", Type: "algorithm", Algorithm: &model.Algorithm{Family: "AES", Primitive: "block-cipher", KeyBits: 256, Known: true}},
			{ID: "alg:mystery", Type: "algorithm", Algorithm: &model.Algorithm{RawName: "1.2.3.4", Scheme: "oid"}},
			{ID: "cert:sha256:" + fp1, Type: "certificate", Certificate: &model.Certificate{
				Subject: "CN=www.example.jp, O=例", Issuer: "CN=ca", Serial: "1ca0", NotBefore: "2025-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z",
				SignatureAlgorithm: "alg:sha256-with-rsa", PublicKey: model.PublicKey{Algorithm: "alg:rsa-2048", FingerprintSHA256: fp2}, FingerprintSHA256: fp1}},
			{ID: "key:private:spki-sha256:" + fp2, Type: "private-key", Key: &model.Key{Algorithm: "alg:rsa-2048", PublicFingerprintSHA256: fp2}},
			{ID: "keystore:loc:cc", Type: "keystore", Keystore: &model.Keystore{Format: "pkcs12", Unreadable: true, Entries: map[string]int{"private_keys": 1}}},
		},
		Occurrences: []model.Occurrence{
			{ID: "occ:1", Asset: "cert:sha256:" + fp1, Collector: "fscrawl", State: "present", Location: model.Location{Kind: "file", Path: "/etc/pki/tls/certs/www.crt"}},
			{ID: "occ:2", Asset: "cert:sha256:" + fp1, Collector: "fscrawl", State: "present", Location: model.Location{Kind: "file", Path: "/opt/app/store.jks", Container: "jks", Index: 2}},
			{ID: "occ:3", Asset: "key:private:spki-sha256:" + fp2, Collector: "fscrawl", State: "present", Location: model.Location{Kind: "file", Path: "/etc/pki/tls/private/www.key"},
				Detail: &model.Detail{Format: "pkcs8-encrypted", Encrypted: &yes, Protection: &model.Protection{Cipher: "alg:aes-256-cbc", Iterations: 4096}}},
			{ID: "occ:4", Asset: "keystore:loc:cc", Collector: "fscrawl", State: "present", Location: model.Location{Kind: "file", Path: "/opt/app/a.p12"}, Detail: &model.Detail{Format: "pkcs12"}},
		},
		Packages: []model.Package{{Manager: "rpm", Name: "openssl-libs", Version: "3.5.9", Release: "1.el9_9", Role: "crypto-library"}},
		Components: []model.Component{
			{ID: "app:nginx:/usr/sbin/nginx", Kind: "application", Name: "nginx", Path: "/usr/sbin/nginx", Version: &model.ComponentVersion{Value: "1.20.1", Source: "binary-string"},
				Links: []model.Link{{SOName: "libssl.so.3", Via: "needed", Component: "lib:openssl:/usr/lib64/libssl.so.3.5.9"}, {SOName: "libz.so.1", Via: "needed"}}},
			{ID: "lib:openssl:/usr/lib64/libssl.so.3.5.9", Kind: "library", Name: "openssl", Path: "/usr/lib64/libssl.so.3.5.9", Version: &model.ComponentVersion{Value: "3.5.9"}},
		},
		Services: []model.Service{
			{ID: "svc:nginx", App: "nginx", Component: "app:nginx:/usr/sbin/nginx", Activity: model.Activity{Level: "enabled"}},
			{ID: "svc:openssh", App: "openssh", Activity: model.Activity{Level: "enabled"}},
		},
		EffectiveValues: []model.EffectiveValue{
			{ID: "eff:1", Service: "svc:nginx", Parameter: "tls.ciphers", Direction: "inbound", Scope: "server www.example.jp", Status: "resolved", Confidence: "high",
				Values: []string{"ECDHE-RSA-AES256-GCM-SHA384", "AES256-SHA"}},
			{ID: "eff:2", Service: "svc:nginx", Parameter: "tls.ciphersuites-tls13", Direction: "inbound", Scope: "server www.example.jp", Status: "resolved", Confidence: "high",
				Values: []string{"TLS_AES_256_GCM_SHA384"}},
			{ID: "eff:3", Service: "svc:nginx", Parameter: "tls.groups", Direction: "inbound", Scope: "server www.example.jp", Status: "resolved", Confidence: "high",
				Values: []string{"X25519MLKEM768", "X25519", "MLKEM768"}},
			{ID: "eff:4", Service: "svc:nginx", Parameter: "tls.ciphers", Direction: "inbound", Scope: "server api.example.jp", Status: "unresolved",
				Reason: "no cipher table is recorded for openssl-libs 9.9"},
			{ID: "eff:5", Service: "svc:openssh", Parameter: "ssh.kex-algorithms", Direction: "inbound", Status: "resolved", Confidence: "high",
				Values: []string{"mlkem768x25519-sha256", "curve25519-sha256"}},
			{ID: "eff:6", Service: "svc:openssh", Parameter: "ssh.ciphers", Direction: "inbound", Status: "resolved", Confidence: "high", Values: []string{"aes256-gcm@openssh.com"}},
			{ID: "eff:7", Service: "svc:openssh", Parameter: "ssh.macs", Direction: "inbound", Status: "resolved", Confidence: "high", Values: []string{"hmac-sha2-512"}},
			{ID: "eff:8", Service: "svc:openssh", Parameter: "ssh.host-key-algorithms", Direction: "inbound", Status: "resolved", Confidence: "high", Values: []string{"ssh-ed25519"}},
		},
		Assessment: &model.Assessment{Policy: "default", PolicyVersion: "2026.11.0",
			Assets: map[string]model.Verdict{"alg:rsa-2048": {Quantum: "vulnerable", Classical: "legacy"}, "cert:sha256:" + fp1: {Quantum: "vulnerable", Classical: "legacy"}},
			Values: map[string]model.Verdict{
				"tls-group:X25519MLKEM768": {Quantum: "hybrid", Classical: "ok"}, "tls-group:X25519": {Quantum: "vulnerable", Classical: "ok"}, "tls-group:MLKEM768": {Quantum: "resistant", Classical: "ok"},
				"ssh-kex:mlkem768x25519-sha256": {Quantum: "hybrid", Classical: "ok"}, "ssh-kex:curve25519-sha256": {Quantum: "vulnerable", Classical: "ok"},
				"tls-suite:AES256-SHA": {Quantum: "vulnerable", Classical: "legacy"},
			}},
	}
	return inv
}

type cbomDoc struct {
	BomFormat    string `json:"bomFormat"`
	SpecVersion  string `json:"specVersion"`
	SerialNumber string `json:"serialNumber"`
	Version      int    `json:"version"`
	Metadata     struct {
		Timestamp string `json:"timestamp"`
		Tools     struct {
			Components []cbomComponent `json:"components"`
		} `json:"tools"`
		Component  cbomComponent `json:"component"`
		Properties []cbomProp    `json:"properties"`
	} `json:"metadata"`
	Components   []cbomComponent `json:"components"`
	Dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	} `json:"dependencies"`
}

type cbomProp struct{ Name, Value string }

type cbomComponent struct {
	Type       string     `json:"type"`
	BomRef     string     `json:"bom-ref"`
	Name       string     `json:"name"`
	Version    string     `json:"version"`
	Properties []cbomProp `json:"properties"`
	Hashes     []struct{ Alg, Content string }
	Evidence   struct {
		Occurrences []struct{ Location string }
	}
	Crypto *struct {
		AssetType string `json:"assetType"`
		OID       string `json:"oid"`
		Algorithm *struct {
			Primitive              string `json:"primitive"`
			ParameterSetIdentifier string `json:"parameterSetIdentifier"`
			NistQuantumLevel       *int   `json:"nistQuantumSecurityLevel"`
		} `json:"algorithmProperties"`
		Certificate *struct {
			SubjectName, IssuerName, NotValidBefore, NotValidAfter string
			SignatureAlgorithmRef, SubjectPublicKeyRef             string
			CertificateFormat                                      string
		} `json:"certificateProperties"`
		Material *struct {
			Type, ID, AlgorithmRef, Format string
			Size                           int
			Value                          *string
			SecuredBy                      *struct{ Mechanism, AlgorithmRef string }
		} `json:"relatedCryptoMaterialProperties"`
		Protocol *struct {
			Type         string
			CipherSuites []struct{ Name string }
			CryptoRefs   []string `json:"cryptoRefArray"`
		} `json:"protocolProperties"`
	} `json:"cryptoProperties"`
}

func (c cbomComponent) prop(name string) string {
	for _, p := range c.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

func cbom(t *testing.T, inv *model.Inventory) (cbomDoc, map[string]cbomComponent, string) {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteCBOM(inv, &buf); err != nil {
		t.Fatal(err)
	}
	var d cbomDoc
	if err := json.Unmarshal(buf.Bytes(), &d); err != nil {
		t.Fatalf("the CBOM is not valid JSON: %v", err)
	}
	by := map[string]cbomComponent{}
	for _, c := range d.Components {
		if c.BomRef == "" {
			t.Errorf("component %q has no bom-ref", c.Name)
		}
		if _, dup := by[c.BomRef]; dup {
			t.Errorf("duplicate bom-ref %q", c.BomRef)
		}
		by[c.BomRef] = c
	}
	return d, by, buf.String()
}

// 文書の枠: CycloneDX 1.6、スキャンごとに決まる通し番号、作成したツール、対象のホスト。
func TestCBOMDocument(t *testing.T) {
	d, _, _ := cbom(t, cbomSample())
	if d.BomFormat != "CycloneDX" || d.SpecVersion != "1.6" || d.Version != 1 {
		t.Errorf("header = %s %s %d", d.BomFormat, d.SpecVersion, d.Version)
	}
	if !regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(d.SerialNumber) {
		t.Errorf("serialNumber = %q", d.SerialNumber)
	}
	if d.Metadata.Timestamp != "2026-11-12T13:37:02Z" {
		t.Errorf("timestamp = %q (the time of the scan, not of the conversion)", d.Metadata.Timestamp)
	}
	if tc := d.Metadata.Tools.Components; len(tc) != 1 || tc[0].Name != "kagiya" || tc[0].Version != "0.1.0" || tc[0].Type != "application" {
		t.Errorf("tools = %+v", tc)
	}
	host := d.Metadata.Component
	if host.Name != "web01" || host.Type != "device" || host.BomRef == "" || host.prop("kagiya:os") != "Red Hat Enterprise Linux 9.9 (Plow)" || host.prop("kagiya:label:system") != "portal" {
		t.Errorf("subject = %+v", host)
	}
	props := map[string]string{}
	for _, p := range d.Metadata.Properties {
		props[p.Name] = p.Value
	}
	if props["kagiya:scan-id"] != "d381586eb279993c2d9ba4527aa4f3a3" || props["kagiya:scan-completed"] != "true" || props["kagiya:policy"] != "default 2026.11.0" || props["kagiya:rules-version"] != "2026.11.0" {
		t.Errorf("metadata properties = %v", props)
	}
	// 同じ結果からは、同じ文書ができる（変換した時刻や乱数を含まない）
	_, _, a := cbom(t, cbomSample())
	_, _, b := cbom(t, cbomSample())
	if a != b {
		t.Error("the conversion must be deterministic")
	}
	// 別のスキャンには、別の通し番号
	other := cbomSample()
	other.Meta.ScanID = "ffffffffffffffffffffffffffffffff"
	if d2, _, _ := cbom(t, other); d2.SerialNumber == d.SerialNumber {
		t.Error("another scan must have another serial number")
	}
}

// アルゴリズム、証明書、鍵。秘密の値は含めない。
func TestCBOMAssets(t *testing.T) {
	_, by, text := cbom(t, cbomSample())
	rsa := by["alg:rsa-2048"]
	if rsa.Type != "cryptographic-asset" || rsa.Crypto == nil || rsa.Crypto.AssetType != "algorithm" || rsa.Crypto.Algorithm.Primitive != "pke" ||
		rsa.Crypto.Algorithm.ParameterSetIdentifier != "2048" || rsa.Crypto.OID != "1.2.840.113549.1.1.1" || rsa.Name != "rsa-2048" {
		t.Errorf("rsa = %+v %+v", rsa, rsa.Crypto)
	}
	// 量子計算機に弱い方式は、耐量子の安全性の水準が 0
	if l := rsa.Crypto.Algorithm.NistQuantumLevel; l == nil || *l != 0 || rsa.prop("kagiya:quantum") != "vulnerable" || rsa.prop("kagiya:classical") != "legacy" {
		t.Errorf("rsa verdict = %+v %v", rsa.Properties, l)
	}
	if c := by["alg:sha256-with-rsa"].Crypto; c == nil || c.Algorithm.Primitive != "signature" {
		t.Errorf("signature algorithm = %+v", c)
	}
	if c := by["alg:aes-256-cbc"].Crypto; c == nil || c.Algorithm.Primitive != "block-cipher" || c.Algorithm.NistQuantumLevel != nil {
		t.Errorf("block cipher = %+v", c)
	}
	// カタログにないアルゴリズムは、種別を unknown とする
	if c := by["alg:mystery"].Crypto; c == nil || c.Algorithm.Primitive != "unknown" || c.OID != "1.2.3.4" {
		t.Errorf("unknown algorithm = %+v", c)
	}

	cert := by["cert:sha256:"+fp1]
	cp := cert.Crypto.Certificate
	if cert.Crypto.AssetType != "certificate" || cert.Name != "CN=www.example.jp, O=例" || cp.SubjectName != "CN=www.example.jp, O=例" || cp.IssuerName != "CN=ca" ||
		cp.NotValidBefore != "2025-01-01T00:00:00Z" || cp.NotValidAfter != "2027-01-01T00:00:00Z" || cp.SignatureAlgorithmRef != "alg:sha256-with-rsa" || cp.CertificateFormat != "X.509" {
		t.Errorf("certificate = %+v %+v", cert, cp)
	}
	if len(cert.Hashes) != 1 || cert.Hashes[0].Alg != "SHA-256" || cert.Hashes[0].Content != fp1 {
		t.Errorf("certificate hashes = %+v", cert.Hashes)
	}
	var where []string
	for _, o := range cert.Evidence.Occurrences {
		where = append(where, o.Location)
	}
	if strings.Join(where, " ") != "/etc/pki/tls/certs/www.crt /opt/app/store.jks" {
		t.Errorf("certificate occurrences = %v", where)
	}
	// 証明書の公開鍵は、公開鍵の資産として参照できる
	pub := by[cp.SubjectPublicKeyRef]
	if pub.Crypto == nil || pub.Crypto.Material == nil || pub.Crypto.Material.Type != "public-key" || pub.Crypto.Material.AlgorithmRef != "alg:rsa-2048" || pub.Crypto.Material.ID != fp2 {
		t.Errorf("subject public key = %+v", pub)
	}

	key := by["key:private:spki-sha256:"+fp2]
	m := key.Crypto.Material
	if key.Crypto.AssetType != "related-crypto-material" || m.Type != "private-key" || m.AlgorithmRef != "alg:rsa-2048" || m.Size != 2048 || m.ID != fp2 || m.Value != nil {
		t.Errorf("private key = %+v", m)
	}
	if m.SecuredBy == nil || m.SecuredBy.Mechanism != "Software" || m.SecuredBy.AlgorithmRef != "alg:aes-256-cbc" || m.Format != "pkcs8-encrypted" {
		t.Errorf("private key protection = %+v format=%q", m.SecuredBy, m.Format)
	}
	if len(key.Evidence.Occurrences) != 1 || key.Evidence.Occurrences[0].Location != "/etc/pki/tls/private/www.key" {
		t.Errorf("private key occurrences = %+v", key.Evidence.Occurrences)
	}
	// 値そのものを入れる欄（value）は、どこにも出さない
	if strings.Contains(text, `"value": ""`) || regexp.MustCompile(`"relatedCryptoMaterialProperties":\s*\{[^}]*"value"`).MatchString(text) {
		t.Error("the CBOM must not carry key material values")
	}

	ks := by["keystore:loc:cc"]
	if ks.Type != "file" || ks.Name != "/opt/app/a.p12" || ks.prop("kagiya:keystore-format") != "pkcs12" || ks.prop("kagiya:contents-unreadable") != "true" {
		t.Errorf("keystore = %+v", ks)
	}
}

// サービスが受け入れる方式は、プロトコルの資産として出す。
func TestCBOMProtocols(t *testing.T) {
	d, by, _ := cbom(t, cbomSample())
	find := func(name string) cbomComponent {
		for _, c := range d.Components {
			if c.Name == name {
				return c
			}
		}
		t.Fatalf("no component named %q", name)
		return cbomComponent{}
	}
	web := find("nginx: server www.example.jp")
	p := web.Crypto.Protocol
	if web.Crypto.AssetType != "protocol" || p.Type != "tls" {
		t.Fatalf("tls protocol = %+v", web.Crypto)
	}
	var suites []string
	for _, s := range p.CipherSuites {
		suites = append(suites, s.Name)
	}
	if strings.Join(suites, " ") != "ECDHE-RSA-AES256-GCM-SHA384 AES256-SHA TLS_AES_256_GCM_SHA384" {
		t.Errorf("cipher suites = %v", suites)
	}
	// 鍵交換のグループは、アルゴリズムの資産への参照。ハイブリッドかどうかが分かる
	prim := map[string]string{}
	for _, ref := range p.CryptoRefs {
		c, ok := by[ref]
		if !ok || c.Crypto == nil || c.Crypto.Algorithm == nil {
			t.Fatalf("group reference %q does not resolve to an algorithm", ref)
		}
		prim[c.Name] = c.Crypto.Algorithm.Primitive + "/" + c.prop("kagiya:quantum")
	}
	if prim["X25519MLKEM768"] != "combiner/hybrid" || prim["X25519"] != "key-agree/vulnerable" || prim["MLKEM768"] != "kem/resistant" || len(prim) != 3 {
		t.Errorf("groups = %v", prim)
	}
	// 特定できなかった項目は、理由を残す（空の一覧を「何も受け入れない」と読ませない）
	api := find("nginx: server api.example.jp")
	if got := api.prop("kagiya:unresolved:tls.ciphers"); !strings.Contains(got, "no cipher table") || len(api.Crypto.Protocol.CipherSuites) != 0 {
		t.Errorf("unresolved scope = %+v", api)
	}

	ssh := find("openssh")
	if ssh.Crypto.AssetType != "protocol" || ssh.Crypto.Protocol.Type != "ssh" || len(ssh.Crypto.Protocol.CryptoRefs) != 5 {
		t.Fatalf("ssh protocol = %+v", ssh.Crypto.Protocol)
	}
	kinds := map[string]string{}
	for _, ref := range ssh.Crypto.Protocol.CryptoRefs {
		c := by[ref]
		kinds[c.Name] = c.Crypto.Algorithm.Primitive
	}
	if kinds["mlkem768x25519-sha256"] != "combiner" || kinds["curve25519-sha256"] != "key-agree" || kinds["aes256-gcm@openssh.com"] != "ae" ||
		kinds["hmac-sha2-512"] != "mac" || kinds["ssh-ed25519"] != "signature" {
		t.Errorf("ssh algorithms = %v", kinds)
	}
}

// サービス、プログラム、ライブラリと、その関係。参照は、必ず文書の中の資産を指す。
func TestCBOMServicesAndReferences(t *testing.T) {
	d, by, _ := cbom(t, cbomSample())
	app := by["svc:nginx"]
	if app.Type != "application" || app.Name != "nginx" || app.Version != "1.20.1" || app.prop("kagiya:activity") != "enabled" {
		t.Errorf("service = %+v", app)
	}
	lib := by["lib:openssl:/usr/lib64/libssl.so.3.5.9"]
	if lib.Type != "library" || lib.Name != "openssl" || lib.Version != "3.5.9" {
		t.Errorf("library = %+v", lib)
	}
	deps := map[string][]string{}
	refs := map[string]bool{d.Metadata.Component.BomRef: true}
	for r := range by {
		refs[r] = true
	}
	for _, dep := range d.Dependencies {
		if _, dup := deps[dep.Ref]; dup {
			t.Errorf("duplicate dependency entry for %q", dep.Ref)
		}
		deps[dep.Ref] = dep.DependsOn
		for _, r := range append([]string{dep.Ref}, dep.DependsOn...) {
			if !refs[r] {
				t.Errorf("dependency reference %q does not resolve", r)
			}
		}
	}
	// nginx は、リンクしている暗号ライブラリと、範囲ごとのプロトコルに依存する
	got := strings.Join(deps["svc:nginx"], " ")
	if !strings.Contains(got, "lib:openssl:/usr/lib64/libssl.so.3.5.9") || strings.Count(got, "protocol:svc:nginx") != 2 {
		t.Errorf("nginx dependsOn = %v", deps["svc:nginx"])
	}
	// 対象のホストは、見つかったサービスに依存する
	if h := strings.Join(deps[d.Metadata.Component.BomRef], " "); !strings.Contains(h, "svc:nginx") || !strings.Contains(h, "svc:openssh") {
		t.Errorf("host dependsOn = %v", deps[d.Metadata.Component.BomRef])
	}
	// 資産の中の参照
	for ref, c := range by {
		if c.Crypto == nil {
			continue
		}
		var rs []string
		if cp := c.Crypto.Certificate; cp != nil {
			rs = append(rs, cp.SignatureAlgorithmRef, cp.SubjectPublicKeyRef)
		}
		if m := c.Crypto.Material; m != nil {
			rs = append(rs, m.AlgorithmRef)
			if m.SecuredBy != nil {
				rs = append(rs, m.SecuredBy.AlgorithmRef)
			}
		}
		if p := c.Crypto.Protocol; p != nil {
			rs = append(rs, p.CryptoRefs...)
		}
		for _, r := range rs {
			if r != "" && !refs[r] {
				t.Errorf("%s: reference %q does not resolve", ref, r)
			}
		}
	}
}

// 参照先が結果にない場合は、参照を出さない（宙に浮いた参照を作らない）。空の結果でも変換できる。
func TestCBOMMissingReferencesAndEmpty(t *testing.T) {
	inv := cbomSample()
	inv.Assets = inv.Assets[4:] // アルゴリズムの資産を落とす
	inv.Assessment = nil
	_, by, _ := cbom(t, inv)
	cp := by["cert:sha256:"+fp1].Crypto.Certificate
	if cp.SignatureAlgorithmRef != "" {
		t.Errorf("dangling signatureAlgorithmRef %q", cp.SignatureAlgorithmRef)
	}
	if m := by["key:private:spki-sha256:"+fp2].Crypto.Material; m.AlgorithmRef != "" || (m.SecuredBy != nil && m.SecuredBy.AlgorithmRef != "") {
		t.Errorf("dangling references in %+v", m)
	}
	empty := &model.Inventory{Schema: model.Schema}
	d, by, _ := cbom(t, empty)
	if d.SpecVersion != "1.6" || len(by) != 0 || d.Metadata.Timestamp != "" {
		t.Errorf("empty = %+v", d)
	}
}
