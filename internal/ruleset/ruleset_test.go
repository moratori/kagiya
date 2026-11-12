package ruleset

import (
	"strings"
	"testing"
	"testing/fstest"
)

const okManifest = "format: kagiya-rules/v0\nversion: \"2026.11.0\"\n"
const okCatalog = `algorithms:
  - id: rsa
    family: RSA
    primitive: public-key
    aliases:
      oid: ["1.2.840.113549.1.1.1"]
      jca: ["RSA"]
  - id: sha256-with-rsa
    family: RSA
    primitive: signature
    aliases:
      oid: ["1.2.840.113549.1.1.11"]
`

func mapFS(files map[string]string) fstest.MapFS {
	m := fstest.MapFS{}
	for k, v := range files {
		m[k] = &fstest.MapFile{Data: []byte(v)}
	}
	return m
}

func TestBuiltinRulesLoad(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatalf("builtin rules are invalid: %v", err)
	}
	if rs.Version == "" || len(rs.SHA256) != 64 {
		t.Errorf("version=%q sha256=%q", rs.Version, rs.SHA256)
	}
	for oid, want := range map[string]string{
		"1.2.840.113549.1.1.1":    "rsa",
		"1.2.840.113549.1.1.11":   "sha256-with-rsa",
		"1.2.840.10045.4.3.2":     "ecdsa-with-sha256",
		"1.2.840.10045.3.1.7":     "ec-p256",
		"1.3.101.112":             "ed25519",
		"2.16.840.1.101.3.4.3.18": "ml-dsa-65",
		"2.16.840.1.101.3.4.4.2":  "ml-kem-768",
	} {
		a, ok := rs.LookupAlias("oid", oid)
		if !ok || a.ID != want {
			t.Errorf("LookupAlias(oid, %s) = %q, %v; want %q", oid, a.ID, ok, want)
		}
	}
	if _, ok := rs.LookupAlias("oid", "9.9.9"); ok {
		t.Error("unknown OID must not be found")
	}
}

func TestLoadValid(t *testing.T) {
	rs, err := Load(mapFS(map[string]string{"manifest.yaml": okManifest, "catalog/algorithms.yaml": okCatalog}))
	if err != nil {
		t.Fatal(err)
	}
	if rs.Version != "2026.11.0" || len(rs.Algorithms) != 2 {
		t.Errorf("rs = %+v", rs)
	}
	if a, ok := rs.LookupAlias("jca", "RSA"); !ok || a.ID != "rsa" || a.Family != "RSA" {
		t.Errorf("LookupAlias(jca, RSA) = %+v, %v", a, ok)
	}
}

// 引用符なしの 1.20 が数値 1.2 に化けない。
func TestScalarsStayStrings(t *testing.T) {
	rs, err := Load(mapFS(map[string]string{
		"manifest.yaml":           "format: kagiya-rules/v0\nversion: 1.20\n",
		"catalog/algorithms.yaml": okCatalog,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if rs.Version != "1.20" {
		t.Errorf("version = %q, want \"1.20\"", rs.Version)
	}
}

func TestLoadRejects(t *testing.T) {
	bomb := "a: &a [x, x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\nalgorithms: []\n"
	deep := "algorithms:\n" + strings.Repeat("  - [", 0) + "  - id: x\n    family: X\n    primitive: hash\n    aliases:\n      oid: " +
		strings.Repeat("[", 40) + "\"1.2\"" + strings.Repeat("]", 40) + "\n"
	cases := map[string]map[string]string{
		"missing manifest":  {"catalog/algorithms.yaml": okCatalog},
		"wrong format":      {"manifest.yaml": "format: other/v9\nversion: \"1\"\n", "catalog/algorithms.yaml": okCatalog},
		"missing version":   {"manifest.yaml": "format: kagiya-rules/v0\n", "catalog/algorithms.yaml": okCatalog},
		"unknown key":       {"manifest.yaml": okManifest, "catalog/algorithms.yaml": okCatalog + "    exec: rm -rf /\n"},
		"unknown top key":   {"manifest.yaml": okManifest + "extra: 1\n", "catalog/algorithms.yaml": okCatalog},
		"alias and anchor":  {"manifest.yaml": okManifest, "catalog/algorithms.yaml": bomb},
		"anchor only":       {"manifest.yaml": okManifest, "catalog/algorithms.yaml": "algorithms: &x []\n"},
		"too deep":          {"manifest.yaml": okManifest, "catalog/algorithms.yaml": deep},
		"too large":         {"manifest.yaml": okManifest, "catalog/algorithms.yaml": okCatalog + "# " + strings.Repeat("x", 2<<20) + "\n"},
		"duplicate id":      {"manifest.yaml": okManifest, "catalog/algorithms.yaml": okCatalog + "  - id: rsa\n    family: RSA\n    primitive: public-key\n"},
		"duplicate alias":   {"manifest.yaml": okManifest, "catalog/algorithms.yaml": okCatalog + "  - id: rsa2\n    family: RSA\n    primitive: public-key\n    aliases:\n      oid: [\"1.2.840.113549.1.1.1\"]\n"},
		"bad id characters": {"manifest.yaml": okManifest, "catalog/algorithms.yaml": "algorithms:\n  - id: \"RSA key\"\n    family: RSA\n    primitive: public-key\n"},
		"missing family":    {"manifest.yaml": okManifest, "catalog/algorithms.yaml": "algorithms:\n  - id: x\n    primitive: hash\n"},
		"unknown primitive": {"manifest.yaml": okManifest, "catalog/algorithms.yaml": "algorithms:\n  - id: x\n    family: X\n    primitive: magic\n"},
		"unknown file":      {"manifest.yaml": okManifest, "catalog/algorithms.yaml": okCatalog, "plugins/run.yaml": "a: 1\n"},
		"multi document":    {"manifest.yaml": okManifest + "---\nformat: x\n", "catalog/algorithms.yaml": okCatalog},
		"no algorithms":     {"manifest.yaml": okManifest},
	}
	for name, files := range cases {
		if _, err := Load(mapFS(files)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// 書き出したルールを読み込み直すと、内包ルールと同一（同じハッシュ）になる。
func TestExportRoundTrip(t *testing.T) {
	builtin, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	files, err := BuiltinFiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 2 {
		t.Fatalf("exported %d files", len(files))
	}
	m := fstest.MapFS{}
	for _, f := range files {
		if strings.HasPrefix(f.Path, "/") || strings.Contains(f.Path, "..") {
			t.Errorf("unsafe export path %q", f.Path)
		}
		m[f.Path] = &fstest.MapFile{Data: f.Data}
	}
	rs, err := Load(m)
	if err != nil {
		t.Fatal(err)
	}
	if rs.SHA256 != builtin.SHA256 {
		t.Error("exported rules differ from builtin rules")
	}
}

func TestHashChangesWithContent(t *testing.T) {
	a, _ := Load(mapFS(map[string]string{"manifest.yaml": okManifest, "catalog/algorithms.yaml": okCatalog}))
	b, _ := Load(mapFS(map[string]string{"manifest.yaml": okManifest, "catalog/algorithms.yaml": okCatalog + "# comment\n"}))
	if a == nil || b == nil || a.SHA256 == b.SHA256 {
		t.Error("hash must reflect file contents")
	}
}

const okStores = `stores:
  - id: system-trust
    paths: ["/etc/ssl/certs", "/etc/pki/ca-trust/extracted"]
    sources:
      - image: "ubuntu@sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6"
        os: "Ubuntu 16.04.7 LTS"
`

func TestBuiltinStores(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	// 実物で確認した場所（出典はルールファイルに記載）
	for path, want := range map[string]string{
		"/etc/ssl/certs/ca-certificates.crt":                      "system-trust",
		"/usr/share/ca-certificates/mozilla/X.crt":                "system-trust",
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem":       "system-trust",
		"/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt": "system-trust",
		"/etc/pki/ca-trust/extracted/java/cacerts":                "system-trust-java",
		"/usr/local/share/ca-certificates/corp.crt":               "local-trust-anchors",
		"/etc/pki/ca-trust/source/anchors/corp.pem":               "local-trust-anchors",
		"/etc/ssl/private/server.key":                             "",
		"/etc/ssl/certsX/a.pem":                                   "",
		"/opt/app/cert.pem":                                       "",
	} {
		if got := rs.StoreFor(path); got != want {
			t.Errorf("StoreFor(%q) = %q, want %q", path, got, want)
		}
	}
	if len(rs.StorePaths()) < 5 {
		t.Errorf("StorePaths() = %v", rs.StorePaths())
	}
	// 出典のないストア定義は内包ルールに存在しない
	for _, s := range rs.Stores {
		if len(s.Sources) == 0 {
			t.Errorf("store %s has no source", s.ID)
		}
	}
}

func TestLoadStores(t *testing.T) {
	base := map[string]string{"manifest.yaml": okManifest, "catalog/algorithms.yaml": okCatalog}
	with := func(stores string) map[string]string {
		m := map[string]string{"os/stores.yaml": stores}
		for k, v := range base {
			m[k] = v
		}
		return m
	}
	rs, err := Load(mapFS(with(okStores)))
	if err != nil {
		t.Fatal(err)
	}
	// より深い場所の定義が優先される
	if rs.StoreFor("/etc/ssl/certs/a.pem") != "system-trust" || rs.StoreFor("/etc/ssl") != "" {
		t.Error("StoreFor on loaded rules is wrong")
	}
	bad := map[string]string{
		"no sources":       "stores:\n  - id: s\n    paths: [\"/etc/ssl/certs\"]\n",
		"source w/o image": "stores:\n  - id: s\n    paths: [\"/a\"]\n    sources:\n      - os: \"X\"\n",
		"image w/o digest": "stores:\n  - id: s\n    paths: [\"/a\"]\n    sources:\n      - image: \"ubuntu:16.04\"\n        os: \"X\"\n",
		"relative path":    "stores:\n  - id: s\n    paths: [\"etc/ssl\"]\n    sources:\n      - image: \"u@sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6\"\n        os: \"X\"\n",
		"unclean path":     "stores:\n  - id: s\n    paths: [\"/etc/../x\"]\n    sources:\n      - image: \"u@sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6\"\n        os: \"X\"\n",
		"no paths":         "stores:\n  - id: s\n    sources:\n      - image: \"u@sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6\"\n        os: \"X\"\n",
		"duplicate id":     okStores + "  - id: system-trust\n    paths: [\"/b\"]\n    sources:\n      - image: \"u@sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6\"\n        os: \"X\"\n",
		"same path twice":  okStores + "  - id: other\n    paths: [\"/etc/ssl/certs\"]\n    sources:\n      - image: \"u@sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6\"\n        os: \"X\"\n",
	}
	for name, y := range bad {
		if _, err := Load(mapFS(with(y))); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
