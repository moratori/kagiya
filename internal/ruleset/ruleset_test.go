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
