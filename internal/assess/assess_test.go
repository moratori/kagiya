package assess

import (
	"strings"
	"testing"

	"kagiya/internal/model"
	"kagiya/internal/ruleset"
)

func evaluator(t *testing.T) *Evaluator {
	t.Helper()
	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(rs, "default")
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func alg(family, primitive string, bits int) *model.Algorithm {
	return &model.Algorithm{Family: family, Primitive: primitive, KeyBits: bits, Known: true}
}

func has(v model.Verdict, rule string) bool {
	for _, r := range v.Rules {
		if r == rule {
			return true
		}
	}
	return false
}

func TestUnknownPolicy(t *testing.T) {
	rs, _ := ruleset.Builtin()
	if _, err := New(rs, "nosuch"); err == nil {
		t.Error("an unknown policy must be an error")
	}
}

// 証明書・鍵で見つかるアルゴリズムの判定。
func TestAlgorithms(t *testing.T) {
	e := evaluator(t)
	for _, c := range []struct {
		id        string
		a         *model.Algorithm
		quantum   string
		classical string
		rule      string
	}{
		{"alg:rsa-1024", alg("RSA", "public-key", 1024), "vulnerable", "weak", "rsa-dsa-below-2048"},
		{"alg:rsa-2048", alg("RSA", "public-key", 2048), "vulnerable", "legacy", "rsa-dsa-112bit"},
		{"alg:rsa-3072", alg("RSA", "public-key", 3072), "vulnerable", "ok", "pk-key-quantum"},
		{"alg:rsa-4096", alg("RSA", "public-key", 4096), "vulnerable", "ok", "rsa-dsa-128bit"},
		{"alg:rsa", alg("RSA", "public-key", 0), "vulnerable", "unknown", "pk-key-quantum"}, // 鍵長が分からない
		{"alg:ec-p224", alg("EC", "curve", 224), "vulnerable", "legacy", "ec-p224"},
		{"alg:ec-p256", alg("EC", "curve", 256), "vulnerable", "ok", "ec-128bit"},
		{"alg:ed25519", alg("EdDSA", "signature", 0), "vulnerable", "ok", "pk-signature-quantum"},
		{"alg:sha1-with-rsa", alg("RSA", "signature", 0), "vulnerable", "weak", "signature-sha1"},
		{"alg:md5-with-rsa", alg("RSA", "signature", 0), "vulnerable", "weak", "signature-md5"},
		{"alg:sha256-with-rsa", alg("RSA", "signature", 0), "vulnerable", "ok", "signature-sha2"},
		{"alg:ecdsa-with-sha224", alg("ECDSA", "signature", 0), "vulnerable", "legacy", "signature-sha224"},
		{"alg:ecdsa-with-sha384", alg("ECDSA", "signature", 0), "vulnerable", "ok", "pk-signature-quantum"},
		{"alg:ml-kem-768", alg("ML-KEM", "kem", 0), "resistant", "ok", "pqc-kem"},
		{"alg:ml-dsa-65", alg("ML-DSA", "signature", 0), "resistant", "ok", "pqc-signature"},
		{"alg:sha256", alg("SHA-2", "hash", 0), "reduced", "ok", "hash-sha256"}, // CRYPTREC の耐量子リストは SHA-384 以上
		{"alg:sha512", alg("SHA-2", "hash", 0), "resistant", "ok", "hash-sha384"},
		{"alg:hmac-sha256", alg("HMAC", "mac", 0), "not-targeted", "ok", "hmac-sha2"},
		{"alg:sha1", alg("SHA-1", "hash", 0), "not-targeted", "legacy", "hash-sha1"},
		{"alg:md5", alg("MD5", "hash", 0), "not-targeted", "weak", "hash-md5"},
		{"alg:aes-128-cbc", alg("AES", "block-cipher", 128), "reduced", "ok", "cipher-aes-128"}, // CRYPTREC の耐量子リストは AES-192 / 256
		{"alg:aes-192-ctr", alg("AES", "block-cipher", 192), "resistant", "ok", "cipher-aes-192"},
		{"alg:aes-256-cbc", alg("AES", "block-cipher", 256), "resistant", "ok", "cipher-aes-192"},
		{"alg:des-ede3-cbc", alg("3DES", "block-cipher", 168), "not-targeted", "legacy", "cipher-3des"},
		{"alg:pkcs12-pbe-sha1-rc2-40", alg("PKCS12-PBE", "other", 0), "not-targeted", "weak", "cipher-rc2-40"},
		// 規則のないもの、カタログにないものは、判定できない
		{"alg:bcrypt-pbkdf", alg("bcrypt", "kdf", 0), "unknown", "unknown", ""},
		{"alg:unknown:oid:1.2.3.4", &model.Algorithm{Scheme: "oid", RawName: "1.2.3.4"}, "unknown", "unknown", ""},
	} {
		v := e.Algorithm(c.id, c.a)
		if v.Quantum != c.quantum || v.Classical != c.classical || (c.rule != "" && !has(v, c.rule)) || (c.rule == "" && len(v.Rules) != 0) {
			t.Errorf("%s: got %+v, want %s / %s (rule %s)", c.id, v, c.quantum, c.classical, c.rule)
		}
	}
}

// TLS の暗号スイートは、鍵交換・認証・暗号化・MAC のそれぞれを判定し、軸ごとに最も厳しいものを採る。
func TestSuites(t *testing.T) {
	e := evaluator(t)
	for _, c := range []struct{ name, quantum, classical, rule string }{
		{"ECDHE-RSA-AES256-GCM-SHA384", "vulnerable", "ok", "tls-kx-ephemeral"},
		{"ECDHE-ECDSA-CHACHA20-POLY1305", "vulnerable", "ok", "tls-au-signature"},
		{"DHE-RSA-AES128-SHA", "vulnerable", "legacy", "tls-mac-sha1"},
		{"AES256-GCM-SHA384", "vulnerable", "legacy", "tls-kx-rsa"}, // RSA による鍵輸送（前方秘匿性なし）
		{"DES-CBC3-SHA", "vulnerable", "legacy", "tls-enc-3des"},
		{"RC4-SHA", "vulnerable", "weak", "tls-enc-broken"},
		{"NULL-SHA256", "vulnerable", "weak", "tls-enc-broken"},
		{"ADH-AES256-GCM-SHA384", "vulnerable", "weak", "tls-au-none"}, // サーバーを認証しない
		{"ECDHE-ARIA256-GCM-SHA384", "vulnerable", "unknown", "tls-enc-unlisted"},
		{"TLS_AES_256_GCM_SHA384", "unknown", "ok", "tls-kx-tls13"}, // 鍵共有はグループの設定で決まる
	} {
		v, ok := e.Suite(c.name)
		if !ok || v.Quantum != c.quantum || v.Classical != c.classical || !has(v, c.rule) {
			t.Errorf("%s: got %+v ok=%v, want %s / %s (rule %s)", c.name, v, ok, c.quantum, c.classical, c.rule)
		}
	}
	// 暗号化の部分だけを見た判定は、規則として残る（AES-128 は「強度が下がる」、AES-256 は「耐量子」）
	if v, _ := e.Suite("ECDHE-RSA-AES128-GCM-SHA256"); !has(v, "tls-enc-aes-128") {
		t.Errorf("AES-128 suite: %+v", v)
	}
	if v, _ := e.Suite("ECDHE-RSA-AES256-GCM-SHA384"); !has(v, "tls-enc-aes-256") {
		t.Errorf("AES-256 suite: %+v", v)
	}
	if _, ok := e.Suite("NO-SUCH-SUITE"); ok {
		t.Error("an unknown suite must not be assessed")
	}
}

// SSH の方式名と、TLS のプロトコルの版。
func TestNames(t *testing.T) {
	e := evaluator(t)
	for _, c := range []struct{ scheme, name, quantum, classical, rule string }{
		{"ssh-kex", "curve25519-sha256", "vulnerable", "ok", "ssh-kex-classical"},
		{"ssh-kex", "ecdh-sha2-nistp384", "vulnerable", "ok", "ssh-kex-classical"},
		{"ssh-kex", "diffie-hellman-group14-sha1", "vulnerable", "legacy", "ssh-kex-sha1"},
		{"ssh-kex", "diffie-hellman-group1-sha1", "vulnerable", "weak", "ssh-kex-group1"},
		{"ssh-kex", "mlkem768x25519-sha256", "hybrid", "ok", "ssh-kex-hybrid-mlkem"},
		{"ssh-kex", "sntrup761x25519-sha512@openssh.com", "hybrid", "ok", "ssh-kex-hybrid-sntrup"},
		{"ssh-key", "ssh-rsa", "vulnerable", "weak", "ssh-key-rsa-sha1"},
		{"ssh-key", "ssh-rsa-cert-v01@openssh.com", "vulnerable", "weak", "ssh-key-rsa-sha1"},
		{"ssh-key", "rsa-sha2-512", "vulnerable", "ok", "ssh-key-signature"},
		{"ssh-key", "ssh-ed25519-cert-v01@openssh.com", "vulnerable", "ok", "ssh-key-signature"},
		{"ssh-key", "sk-ecdsa-sha2-nistp256@openssh.com", "vulnerable", "ok", "ssh-key-signature"},
		{"ssh-cipher", "aes256-gcm@openssh.com", "resistant", "ok", "ssh-cipher-aes-192"},
		{"ssh-cipher", "aes128-ctr", "reduced", "ok", "ssh-cipher-aes-128"},
		{"ssh-cipher", "chacha20-poly1305@openssh.com", "not-targeted", "ok", "ssh-cipher-chacha20"},
		{"ssh-cipher", "3des-cbc", "not-targeted", "legacy", "ssh-cipher-3des"},
		{"ssh-cipher", "arcfour128", "not-targeted", "weak", "ssh-cipher-rc4"},
		{"ssh-mac", "hmac-sha2-512-etm@openssh.com", "not-targeted", "ok", "ssh-mac-sha2"},
		{"ssh-mac", "hmac-sha1", "not-targeted", "legacy", "ssh-mac-sha1"},
		{"tls-protocol", "TLSv1", "unknown", "weak", "tls-protocol-deprecated"},
		{"tls-protocol", "TLSv1.3", "unknown", "ok", "tls-protocol-current"},
	} {
		v, ok := e.Name(c.scheme, c.name)
		if !ok || v.Quantum != c.quantum || v.Classical != c.classical || !has(v, c.rule) {
			t.Errorf("%s %s: got %+v ok=%v, want %s / %s (rule %s)", c.scheme, c.name, v, ok, c.quantum, c.classical, c.rule)
		}
	}
	for _, c := range [][2]string{{"ssh-kex", "no-such-kex"}, {"ssh-mac", "umac-64@openssh.com"}, {"tls-protocol", "all"}, {"nosuch", "x"}} {
		if v, ok := e.Name(c[0], c[1]); ok {
			t.Errorf("%s %s: no rule should match, got %+v", c[0], c[1], v)
		}
	}
}

// 結果全体の評価: 資産（アルゴリズム・証明書・鍵）と、設定から求めた値（暗号スイート、SSH の方式）。
func TestAssessInventory(t *testing.T) {
	e := evaluator(t)
	inv := &model.Inventory{
		Assets: []model.Asset{
			{ID: "alg:rsa-2048", Type: "algorithm", Algorithm: alg("RSA", "public-key", 2048)},
			{ID: "alg:sha256-with-rsa", Type: "algorithm", Algorithm: alg("RSA", "signature", 0)},
			{ID: "alg:sha1-with-rsa", Type: "algorithm", Algorithm: alg("RSA", "signature", 0)},
			{ID: "alg:ec-p256", Type: "algorithm", Algorithm: alg("EC", "curve", 256)},
			{ID: "cert:a", Type: "certificate", Certificate: &model.Certificate{SignatureAlgorithm: "alg:sha256-with-rsa", PublicKey: model.PublicKey{Algorithm: "alg:rsa-2048"}}},
			{ID: "cert:b", Type: "certificate", Certificate: &model.Certificate{SignatureAlgorithm: "alg:sha1-with-rsa", PublicKey: model.PublicKey{Algorithm: "alg:ec-p256"}}},
			{ID: "cert:c", Type: "certificate", Certificate: &model.Certificate{SignatureAlgorithm: "alg:missing", PublicKey: model.PublicKey{Algorithm: "alg:ec-p256"}}},
			{ID: "key:k", Type: "private-key", Key: &model.Key{Algorithm: "alg:ec-p256"}},
			{ID: "key:n", Type: "private-key", Key: &model.Key{}},
		},
		EffectiveValues: []model.EffectiveValue{
			{Service: "svc:nginx", Parameter: "tls.ciphers", Status: "resolved", Values: []string{"ECDHE-RSA-AES256-GCM-SHA384", "AES128-SHA"}},
			{Service: "svc:nginx", Parameter: "tls.ciphersuites-tls13", Status: "resolved", Values: []string{"TLS_AES_256_GCM_SHA384"}},
			{Service: "svc:openssh", Parameter: "ssh.kex-algorithms", Status: "resolved", Values: []string{"mlkem768x25519-sha256", "curve25519-sha256", "no-such-kex"}},
			{Service: "svc:openssh", Parameter: "ssh.host-key-algorithms", Status: "resolved", Values: []string{"ssh-ed25519"}},
			{Service: "svc:openssh", Parameter: "ssh.ciphers", Status: "resolved", Values: []string{"aes256-ctr"}},
			{Service: "svc:openssh", Parameter: "ssh.macs", Status: "resolved", Values: []string{"hmac-sha1"}},
			{Service: "svc:openssh", Parameter: "ssh.required-rsa-size", Status: "resolved", Values: []string{"1024"}},
			{Service: "svc:openssh", Parameter: "ssh.pubkey-accepted-algorithms", Status: "unresolved", Values: nil},
		},
		Settings: []model.Setting{
			{Service: "svc:nginx", Parameter: "tls.protocols", Values: []string{"TLSv1", "TLSv1.2"}},
			{Service: "svc:httpd", Parameter: "tls.protocols", Values: []string{"all", "-SSLv3"}},
		},
	}
	a := e.Assess(inv)
	if a.Policy != "default" || a.PolicyVersion == "" {
		t.Errorf("policy = %q %q", a.Policy, a.PolicyVersion)
	}
	for id, want := range map[string][2]string{
		"alg:rsa-2048": {"vulnerable", "legacy"},
		"cert:a":       {"vulnerable", "legacy"}, // 鍵（RSA 2048）と署名（SHA-256 with RSA）のうち厳しいほう
		"cert:b":       {"vulnerable", "weak"},   // SHA-1 による署名
		"cert:c":       {"vulnerable", "unknown"},
		"key:k":        {"vulnerable", "ok"},
		"key:n":        {"unknown", "unknown"}, // アルゴリズムが分からない鍵
	} {
		if v, ok := a.Assets[id]; !ok || v.Quantum != want[0] || v.Classical != want[1] {
			t.Errorf("asset %s: got %+v ok=%v, want %v", id, v, ok, want)
		}
	}
	for key, want := range map[string][2]string{
		"tls-suite:ECDHE-RSA-AES256-GCM-SHA384": {"vulnerable", "ok"},
		"tls-suite:AES128-SHA":                  {"vulnerable", "legacy"},
		"tls-suite:TLS_AES_256_GCM_SHA384":      {"unknown", "ok"},
		"ssh-kex:mlkem768x25519-sha256":         {"hybrid", "ok"},
		"ssh-kex:curve25519-sha256":             {"vulnerable", "ok"},
		"ssh-kex:no-such-kex":                   {"unknown", "unknown"}, // 規則のない名前は「判定できない」として残す
		"ssh-key:ssh-ed25519":                   {"vulnerable", "ok"},
		"ssh-cipher:aes256-ctr":                 {"resistant", "ok"},
		"ssh-mac:hmac-sha1":                     {"not-targeted", "legacy"},
		"tls-protocol:TLSv1":                    {"unknown", "weak"},
		"tls-protocol:TLSv1.2":                  {"unknown", "ok"},
	} {
		if v, ok := a.Values[key]; !ok || v.Quantum != want[0] || v.Classical != want[1] {
			t.Errorf("value %s: got %+v ok=%v, want %v", key, v, ok, want)
		}
	}
	// 一覧ではない項目（数値）や、プロトコル名でない語（Apache の「all」「-SSLv3」）は評価の対象にしない
	for key := range a.Values {
		if strings.Contains(key, "1024") || strings.HasSuffix(key, ":all") || strings.Contains(key, "-SSLv3") {
			t.Errorf("unexpected value %s", key)
		}
	}
	// 判定の根拠として挙げた規則は、すべてポリシーにある
	known := map[string]bool{}
	for _, r := range e.Policy().Rules {
		known[r.ID] = true
	}
	for _, m := range []map[string]model.Verdict{a.Assets, a.Values} {
		for k, v := range m {
			for _, r := range v.Rules {
				if !known[r] {
					t.Errorf("%s: unknown rule %s", k, r)
				}
			}
		}
	}
}
