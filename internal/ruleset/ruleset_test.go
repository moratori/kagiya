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

func TestBuiltinPackageRoles(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"openssl": "crypto-library", "openssl-libs": "crypto-library", "libssl3t64": "crypto-library", "libssl1.0.0": "crypto-library",
		"libgnutls30": "crypto-library", "gnutls": "crypto-library", "libgcrypt20": "crypto-library",
		"openssh-server": "ssh", "openssh-clients": "ssh", "openssh-client": "ssh",
		"nginx": "web-server", "nginx-core": "web-server", "httpd": "web-server", "mod_ssl": "web-server", "apache2-bin": "web-server",
		"crypto-policies": "crypto-policy", "ca-certificates": "trust-store",
		"libc6": "", "bash": "", "opensslx": "", "nginx-filesystem": "",
	} {
		if got := rs.PackageRole(name); got != want {
			t.Errorf("PackageRole(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestLoadPackageRolesRequireSources(t *testing.T) {
	base := map[string]string{"manifest.yaml": okManifest, "catalog/algorithms.yaml": okCatalog}
	with := func(y string) map[string]string {
		m := map[string]string{"os/packages.yaml": y}
		for k, v := range base {
			m[k] = v
		}
		return m
	}
	src := "    sources:\n      - image: \"u@sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6\"\n        os: \"X\"\n"
	ok := "packages:\n  - role: ssh\n    names: [\"openssh-server\", \"libssh*\"]\n" + src
	rs, err := Load(mapFS(with(ok)))
	if err != nil {
		t.Fatal(err)
	}
	if rs.PackageRole("openssh-server") != "ssh" || rs.PackageRole("libssh-4") != "ssh" || rs.PackageRole("openssh") != "" {
		t.Error("package role lookup is wrong")
	}
	for name, y := range map[string]string{
		"no sources":     "packages:\n  - role: ssh\n    names: [\"openssh-server\"]\n",
		"no names":       "packages:\n  - role: ssh\n" + src,
		"bad name":       "packages:\n  - role: ssh\n    names: [\"open ssh\"]\n" + src,
		"star in middle": "packages:\n  - role: ssh\n    names: [\"open*ssh\"]\n" + src,
		"bare star":      "packages:\n  - role: ssh\n    names: [\"*\"]\n" + src,
		"duplicate name": ok + "  - role: other\n    names: [\"openssh-server\"]\n" + src,
		"bad role":       "packages:\n  - role: \"SSH role\"\n    names: [\"a\"]\n" + src,
	} {
		if _, err := Load(mapFS(with(y))); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestBuiltinAppsAndLibraries(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	apps := map[string]AppRule{}
	for _, a := range rs.Apps {
		apps[a.ID] = a
		if len(a.Sources) == 0 || len(a.Binaries) == 0 {
			t.Errorf("app %s lacks sources or binaries", a.ID)
		}
	}
	for _, id := range []string{"openssh", "nginx", "httpd"} {
		if _, ok := apps[id]; !ok {
			t.Errorf("app %s missing", id)
		}
	}
	// 版文字列のパターン: 実物のバイナリに埋め込まれていた文字列で確認
	for id, c := range map[string][2]string{
		"openssh": {"OpenSSH_8.0p1", "8.0p1"},
		"nginx":   {"nginx/1.14.1", "1.14.1"},
		"httpd":   {"Apache/2.4.37 (Red Hat Enterprise Linux)", "2.4.37"},
	} {
		if got := apps[id].MatchVersion([]byte("xx\x00" + c[0] + "\x00yy")); len(got) != 1 || got[0] != c[1] {
			t.Errorf("%s: MatchVersion(%q) = %v, want %q", id, c[0], got, c[1])
		}
	}
	if got := apps["openssh"].MatchVersion([]byte("OpenSSH_2\x00OpenSSH_3.0\x00OpenSSH_2.5.0p1*\x00")); len(got) != 0 {
		t.Errorf("compatibility strings must not match: %v", got)
	}
	lib, ok := rs.LibraryForSOName("libcrypto.so.1.1")
	if !ok || lib.ID != "openssl" {
		t.Fatalf("LibraryForSOName(libcrypto.so.1.1) = %+v, %v", lib, ok)
	}
	if _, ok := rs.LibraryForSOName("libc.so.6"); ok {
		t.Error("libc must not match a crypto library rule")
	}
	for in, want := range map[string]string{
		"OpenSSL 1.1.1k  FIPS 25 Mar 2021": "1.1.1k",
		"OpenSSL 3.5.9 29 Sep 2026":        "3.5.9",
		"OpenSSL 1.0.2g  1 Mar 2016":       "1.0.2g",
		"OpenSSL 3.0.13 30 Jan 2024":       "3.0.13",
	} {
		if got := lib.MatchVersion([]byte(in)); len(got) != 1 || got[0] != want {
			t.Errorf("openssl MatchVersion(%q) = %v, want %q", in, got, want)
		}
	}
}

func TestLoadAppRules(t *testing.T) {
	base := map[string]string{"manifest.yaml": okManifest, "catalog/algorithms.yaml": okCatalog}
	with := func(path, y string) map[string]string {
		m := map[string]string{path: y}
		for k, v := range base {
			m[k] = v
		}
		return m
	}
	src := "  sources:\n    - image: \"u@sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6\"\n      os: \"X\"\n"
	ok := "app:\n  id: myapp\n  binaries: [\"/opt/myapp/bin/myapp\"]\n  version_pattern: 'myapp/(\\d+\\.\\d+)'\n  packages: [\"myapp\"]\n" + src
	rs, err := Load(mapFS(with("apps/myapp.yaml", ok)))
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Apps) != 1 || rs.Apps[0].ID != "myapp" {
		t.Fatalf("apps = %+v", rs.Apps)
	}
	if got := rs.Apps[0].MatchVersion([]byte("myapp/1.2 myapp/1.2 myapp/3.4")); len(got) != 2 {
		t.Errorf("distinct versions = %v", got)
	}
	for name, y := range map[string]string{
		"no sources":         "app:\n  id: a\n  binaries: [\"/a\"]\n",
		"no binaries":        "app:\n  id: a\n" + src,
		"relative binary":    "app:\n  id: a\n  binaries: [\"bin/a\"]\n" + src,
		"bad pattern":        "app:\n  id: a\n  binaries: [\"/a\"]\n  version_pattern: '(('\n" + src,
		"no capture group":   "app:\n  id: a\n  binaries: [\"/a\"]\n  version_pattern: 'a/\\d+'\n" + src,
		"two capture groups": "app:\n  id: a\n  binaries: [\"/a\"]\n  version_pattern: '(a)/(\\d+)'\n" + src,
		"unknown key":        "app:\n  id: a\n  binaries: [\"/a\"]\n  command: \"a -V\"\n" + src,
	} {
		if _, err := Load(mapFS(with("apps/a.yaml", y))); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	libOK := "library:\n  id: mylib\n  sonames: [\"libmy.so*\"]\n  version_pattern: 'MyLib (\\d+)'\n" + src
	rs, err = Load(mapFS(with("libraries/mylib.yaml", libOK)))
	if err != nil {
		t.Fatal(err)
	}
	if l, ok := rs.LibraryForSOName("libmy.so.2"); !ok || l.ID != "mylib" {
		t.Error("library rule lookup failed")
	}
	if _, err := Load(mapFS(with("libraries/x.yaml", "library:\n  id: x\n  sonames: [\"libx.so\"]\n"))); err == nil {
		t.Error("library without sources must be rejected")
	}
}

func TestBuiltinAppDefaults(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	// 実物で採取した値（出典はルールファイルに記載）
	v, src, ok := rs.AppDefaults("openssh", "openssh-server", "9.9p1-16.el9_9")
	if !ok || !strings.HasPrefix(src.Image, "redhat/ubi9@sha256:") || src.OS != "Red Hat Enterprise Linux 9.9 (Plow)" {
		t.Fatalf("RHEL 9.9 defaults: ok=%v src=%+v", ok, src)
	}
	if kex := v["ssh.kex-algorithms"]; len(kex) < 5 || kex[0] != "sntrup761x25519-sha512" {
		t.Errorf("kex = %v", kex)
	}
	if v["ssh.required-rsa-size"][0] != "1024" {
		t.Errorf("required-rsa-size = %v", v["ssh.required-rsa-size"])
	}
	// 同じ上流の版（9.9p1）でも、RHEL 10.3 のパッケージは既定値が違う
	v10, _, ok := rs.AppDefaults("openssh", "openssh-server", "9.9p1-33.el10_3")
	if !ok || strings.Join(v10["ssh.kex-algorithms"], ",") == strings.Join(v["ssh.kex-algorithms"], ",") {
		t.Errorf("RHEL 10.3 defaults must differ from RHEL 9.9: %v", v10["ssh.kex-algorithms"])
	}
	if _, _, ok := rs.AppDefaults("openssh", "openssh-server", "9.9p1-1.unknown"); ok {
		t.Error("unknown package version must not match")
	}
}

func TestLoadAppDefaults(t *testing.T) {
	base := map[string]string{"manifest.yaml": okManifest, "catalog/algorithms.yaml": okCatalog}
	with := func(y string) map[string]string {
		m := map[string]string{"defaults/x.yaml": y}
		for k, v := range base {
			m[k] = v
		}
		return m
	}
	src := "    source:\n      image: \"u@sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6\"\n      os: \"X\"\n"
	ok := "defaults:\n  - app: myapp\n    package: myapp\n    version: \"1.2-3\"\n" + src + "    values:\n      tls.ciphers: \"a,b\"\n"
	rs, err := Load(mapFS(with(ok)))
	if err != nil {
		t.Fatal(err)
	}
	if v, _, found := rs.AppDefaults("myapp", "myapp", "1.2-3"); !found || strings.Join(v["tls.ciphers"], "|") != "a|b" {
		t.Errorf("defaults = %v %v", v, found)
	}
	for name, y := range map[string]string{
		"no source":     "defaults:\n  - app: a\n    package: a\n    version: \"1\"\n    values:\n      p: \"x\"\n",
		"no values":     "defaults:\n  - app: a\n    package: a\n    version: \"1\"\n" + src,
		"bad value":     "defaults:\n  - app: a\n    package: a\n    version: \"1\"\n" + src + "    values:\n      p: \"x y;z\"\n",
		"no version":    "defaults:\n  - app: a\n    package: a\n" + src + "    values:\n      p: \"x\"\n",
		"duplicate key": ok + "  - app: myapp\n    package: myapp\n    version: \"1.2-3\"\n" + src + "    values:\n      tls.ciphers: \"c\"\n",
	} {
		if _, err := Load(mapFS(with(y))); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// 内包している OpenSSL の暗号スイートの対応表が読め、パッケージ版から引ける。
func TestBuiltinCipherTables(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	// 実測した版そのもの
	tb, b, exact, ok := rs.CipherTableFor("openssl", "openssl-libs", "3.5.9-1.el9_9")
	if !ok || !exact {
		t.Fatalf("exact lookup: ok=%v exact=%v", ok, exact)
	}
	if b.Package != "openssl-libs" || b.Version != "3.5.9-1.el9_9" || !strings.Contains(b.Source.Image, "@sha256:") {
		t.Errorf("build = %+v", b)
	}
	if tb.Upstream != "3.5.9" || !tb.StandardNames || !tb.SecurityLevels || tb.DefaultLevel == nil ||
		tb.ProfileSystem != "/etc/crypto-policies/back-ends/opensslcnf.config" {
		t.Errorf("table header = %+v", tb)
	}
	if len(tb.Suites) < 100 || len(tb.TLS13) < 3 { // TLS 1.3 は、既定に入っていないものも含めて載せている
		t.Fatalf("suites=%d tls13=%d", len(tb.Suites), len(tb.TLS13))
	}
	s := tb.Suites[0]
	if s.Name != "ECDHE-ECDSA-AES256-GCM-SHA384" || s.Standard != "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" || s.Protocol != "TLSv1.2" ||
		s.Kx != "ECDH" || s.Au != "ECDSA" || s.Enc != "AESGCM(256)" || s.Mac != "AEAD" || s.Strength != 256 ||
		s.Level == nil || *s.Level != 5 || !s.Default || !strings.Contains(" "+s.Keywords+" ", " HIGH ") {
		t.Errorf("first suite = %+v", s)
	}
	// RHEL 8 は PROFILE=SYSTEM で別のファイルを読む
	if tb8, _, exact, ok := rs.CipherTableFor("openssl", "openssl-libs", "1.1.1k-18.el8_6"); !ok || !exact ||
		tb8.ProfileSystem != "/etc/crypto-policies/back-ends/openssl.config" || tb8.StandardNames {
		t.Errorf("RHEL 8 table: ok=%v exact=%v", ok, exact)
	}
	// セキュリティレベルのない古い版
	if old, _, _, ok := rs.CipherTableFor("openssl", "libssl1.0.0", "1.0.2g-1ubuntu4.20"); !ok || old.SecurityLevels || old.DefaultLevel != nil || len(old.TLS13) != 0 {
		t.Errorf("1.0.2 table: ok=%v", ok)
	}

	// 補間: 同じパッケージ名・同じ上流版・同じディストリ系列で、リリースだけが違う版は、実測した表で代用する（完全一致ではないと分かる形で返す）。
	tb2, b2, exact, ok := rs.CipherTableFor("openssl", "openssl-libs", "3.5.9-2.el9_9")
	if !ok || exact || tb2 != tb || b2.Version != "3.5.9-1.el9_9" {
		t.Errorf("interpolated lookup: ok=%v exact=%v build=%+v", ok, exact, b2)
	}
	if _, b3, exact, ok := rs.CipherTableFor("openssl", "openssl-libs", "1:3.5.9-7.el10_4"); !ok || exact || b3.Version != "3.5.9-1.el10_3" {
		t.Errorf("interpolated lookup (el10): ok=%v exact=%v build=%+v", ok, exact, b3)
	}
	if _, b4, exact, ok := rs.CipherTableFor("openssl", "libssl3t64", "3.0.13-0ubuntu3.99"); !ok || exact || b4.Version != "3.0.13-0ubuntu3.16" {
		t.Errorf("interpolated lookup (ubuntu): ok=%v exact=%v build=%+v", ok, exact, b4)
	}
	// 代用しない: 上流版が違う、ディストリ系列が違う、パッケージ名が違う、ライブラリが違う
	for _, c := range [][3]string{
		{"openssl", "openssl-libs", "3.5.10-1.el9_9"},
		{"openssl", "openssl-libs", "3.5.9-1.el11"},
		{"openssl", "openssl-libs", "3.5.9-1.fc43"},
		{"openssl", "libssl3t64", "3.5.9-1.el9_9"},
		{"openssl", "libssl3t64", "3.0.13-1~deb13u1"},
		{"gnutls", "openssl-libs", "3.5.9-1.el9_9"},
		{"openssl", "openssl-libs", ""},
	} {
		if _, _, _, ok := rs.CipherTableFor(c[0], c[1], c[2]); ok {
			t.Errorf("%v must not match any table", c)
		}
	}
}

// 対応表にも出典が必須。壊れた表は読み込み時に拒否する。
func TestLoadCipherTables(t *testing.T) {
	base := map[string]string{"manifest.yaml": okManifest, "catalog/algorithms.yaml": okCatalog}
	with := func(y string) map[string]string {
		m := map[string]string{"ciphers/x.yaml": y}
		for k, v := range base {
			m[k] = v
		}
		return m
	}
	head := "cipher_tables:\n  - library: mylib\n    upstream: \"1.2\"\n"
	build := "    builds:\n      - package: mylib\n        version: \"1.2-3.el9\"\n        source:\n          image: \"u@sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6\"\n          os: \"X\"\n"
	flags := "    standard_names: false\n    security_levels: true\n    default_level: 1\n"
	suites := "    suites:\n" +
		"      - {name: A-B, id: \"0x00,0x01\", protocol: TLSv1.2, kx: RSA, au: RSA, enc: \"AES(128)\", mac: SHA1, strength: 128, level: 3, default: true, keywords: \"ALL HIGH kRSA\"}\n" +
		"      - {name: C-D, id: \"0x00,0x02\", protocol: SSLv3, kx: RSA, au: RSA, enc: \"None\", mac: SHA1, strength: 0, keywords: \"eNULL\"}\n"
	ok := head + build + flags + suites
	rs, err := Load(mapFS(with(ok)))
	if err != nil {
		t.Fatal(err)
	}
	if tb, _, exact, found := rs.CipherTableFor("mylib", "mylib", "1.2-3.el9"); !found || !exact || len(tb.Suites) != 2 || tb.Suites[1].Level != nil {
		t.Errorf("table = %+v found=%v exact=%v", tb, found, exact)
	}
	noSource := "    builds:\n      - package: mylib\n        version: \"1.2-3.el9\"\n"
	for name, y := range map[string]string{
		"no builds":             head + flags + suites,
		"no source":             head + noSource + flags + suites,
		"no suites":             head + build + flags,
		"no upstream":           "cipher_tables:\n  - library: mylib\n" + build + flags + suites,
		"duplicate build":       ok + "  - library: mylib\n    upstream: \"1.2\"\n" + build + flags + suites,
		"duplicate suite":       ok + "      - {name: A-B, id: \"0x00,0x03\", protocol: TLSv1.2, kx: RSA, au: RSA, enc: \"AES(128)\", mac: SHA1, strength: 128, keywords: \"ALL\"}\n",
		"bad suite name":        head + build + flags + "    suites:\n      - {name: \"A B\", id: \"0x00,0x01\", protocol: TLSv1.2, kx: RSA, au: RSA, enc: \"AES(128)\", mac: SHA1, strength: 128, keywords: \"ALL\"}\n",
		"bad keyword":           head + build + flags + "    suites:\n      - {name: A-B, id: \"0x00,0x01\", protocol: TLSv1.2, kx: RSA, au: RSA, enc: \"AES(128)\", mac: SHA1, strength: 128, keywords: \"ALL !x\"}\n",
		"bad level":             head + build + flags + "    suites:\n      - {name: A-B, id: \"0x00,0x01\", protocol: TLSv1.2, kx: RSA, au: RSA, enc: \"AES(128)\", mac: SHA1, strength: 128, level: 9, keywords: \"ALL\"}\n",
		"level without flag":    head + build + "    standard_names: false\n    security_levels: false\n    default_level: 1\n" + suites,
		"relative profile":      head + build + flags + "    profile_system: \"etc/x\"\n" + suites,
		"unknown key":           head + build + flags + "    surprise: 1\n" + suites,
		"keyword same as suite": head + build + flags + "    suites:\n      - {name: A-B, id: \"0x00,0x01\", protocol: TLSv1.2, kx: RSA, au: RSA, enc: \"AES(128)\", mac: SHA1, strength: 128, keywords: \"ALL A-B\"}\n",
	} {
		if _, err := Load(mapFS(with(y))); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// 対応表には、TLS 1.3 のスイートの全体（既定に入っていないものも含む）が入っている。
func TestBuiltinCipherTableTLS13(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	tb, _, _, ok := rs.CipherTableFor("openssl", "openssl-libs", "3.5.9-1.el9_9")
	if !ok {
		t.Fatal("no table")
	}
	names := map[string]CipherSuite{}
	for _, s := range tb.TLS13 {
		names[s.Name] = s
	}
	if c, ok := names["TLS_AES_128_CCM_SHA256"]; !ok || c.Default || c.Level == nil || *c.Level != 3 {
		t.Errorf("TLS_AES_128_CCM_SHA256 = %+v %v", c, ok)
	}
	if c := names["TLS_AES_256_GCM_SHA384"]; !c.Default || c.Level == nil || *c.Level != 5 {
		t.Errorf("TLS_AES_256_GCM_SHA384 = %+v", c)
	}
}

// nginx と Apache httpd の既定（暗号文字列と、DH パラメータなしで DHE を使えるか）が、パッケージ版から引ける。
func TestBuiltinWebServerDefaults(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	v, src, ok := rs.AppDefaults("nginx", "nginx-core", "1.20.1-32.el9_9.1")
	if !ok || strings.Join(v["tls.ciphers"], "|") != "HIGH:!aNULL:!MD5" || strings.Join(v["tls.dhe-without-params"], "|") != "disabled" || !strings.HasPrefix(src.Image, "redhat/ubi9@sha256:") {
		t.Errorf("nginx on RHEL 9 = %v %v", v, ok)
	}
	// 古い nginx は、組み込みの DH パラメータを持っていた
	if v, _, ok := rs.AppDefaults("nginx", "nginx-core", "1.10.3-0ubuntu0.16.04.5"); !ok || strings.Join(v["tls.dhe-without-params"], "|") != "builtin" {
		t.Errorf("nginx on Ubuntu 16.04 = %v %v", v, ok)
	}
	if v, _, ok := rs.AppDefaults("httpd", "httpd-core", "2.4.62-13.el9_8.9"); !ok || strings.Join(v["tls.ciphers"], "|") != "DEFAULT" || strings.Join(v["tls.dhe-without-params"], "|") != "builtin" {
		t.Errorf("httpd on RHEL 9 = %v %v", v, ok)
	}
	// Debian 系の Apache は、組み込みの既定の暗号文字列を実測できていない（設定ファイルが必ず書いているため）
	if v, _, ok := rs.AppDefaults("httpd", "apache2-bin", "2.4.58-1ubuntu8.18"); !ok || v["tls.ciphers"] != nil || strings.Join(v["tls.dhe-without-params"], "|") != "builtin" {
		t.Errorf("apache2 on Ubuntu 24.04 = %v %v", v, ok)
	}
}

// アプリの既定値表の補間: パッケージ名・上流の版・ディストリの系列が同じで、リリースだけが違う版は、実測した版の表で代用する。
func TestAppDefaultsInterpolation(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	// 実測した版そのもの
	v, measured, src, exact, ok := rs.AppDefaultsFor("openssh", "openssh-server", "1:9.6p1-3ubuntu13.20")
	if !ok || !exact || measured != "1:9.6p1-3ubuntu13.20" || len(v["ssh.kex-algorithms"]) == 0 || !strings.Contains(src.Image, "@sha256:") {
		t.Errorf("exact: ok=%v exact=%v measured=%s", ok, exact, measured)
	}
	for _, c := range []struct{ app, pkg, version, want string }{
		{"openssh", "openssh-server", "1:9.6p1-3ubuntu13.21", "1:9.6p1-3ubuntu13.20"},
		{"openssh", "openssh-server", "9.9p1-17.el9_9", "9.9p1-16.el9_9"}, // 同じ上流版でも、RHEL 10 の表ではなく RHEL 9 の表
		{"openssh", "openssh-server", "9.9p1-40.el10_4", "9.9p1-33.el10_3"},
		{"openssh", "openssh-server", "1:10.0p1-7+deb13u5", "1:10.0p1-7+deb13u4"},
		{"nginx", "nginx-core", "1.20.1-33.el9_9.1", "1.20.1-32.el9_9.1"},
	} {
		v, measured, _, exact, ok := rs.AppDefaultsFor(c.app, c.pkg, c.version)
		if !ok || exact || measured != c.want || len(v) == 0 {
			t.Errorf("%s %s: ok=%v exact=%v measured=%s, want %s", c.pkg, c.version, ok, exact, measured, c.want)
		}
	}
	// 代用しない: 上流の版が違う、ディストリの系列が違う・分からない、パッケージ名やアプリが違う
	for _, c := range [][3]string{
		{"openssh", "openssh-server", "9.8p1-16.el9_9"},
		{"openssh", "openssh-server", "9.9p1-1.el11"},
		{"openssh", "openssh-server", "9.9p1-1.fc42"},
		{"openssh", "openssh-server", "1:9.6p1-1~deb13u1"},
		{"openssh", "openssh-server", "1:99.9p9-1custom"},
		{"openssh", "openssh", "9.9p1-17.el9_9"},
		{"nginx", "openssh-server", "9.9p1-17.el9_9"},
		{"openssh", "openssh-server", ""},
	} {
		if _, _, _, _, ok := rs.AppDefaultsFor(c[0], c[1], c[2]); ok {
			t.Errorf("%v must not match", c)
		}
	}
	// AppDefaults は、従来どおり完全に一致する版だけを返す
	if _, _, ok := rs.AppDefaults("openssh", "openssh-server", "1:9.6p1-3ubuntu13.21"); ok {
		t.Error("AppDefaults must stay exact")
	}
}

// 内包している評価ポリシーが読め、すべての規則が出典を持つ。
func TestBuiltinPolicy(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	p, ok := rs.Policy("default")
	if !ok || p.Version == "" || len(p.Rules) < 30 {
		t.Fatalf("default policy: ok=%v %+v", ok, p)
	}
	refs := map[string]PolicyRef{}
	for _, r := range p.References {
		refs[r.ID] = r
	}
	if r := refs["nist-ir-8547"]; r.URL != "https://doi.org/10.6028/NIST.IR.8547" || !strings.Contains(r.Title, "8547") {
		t.Errorf("nist-ir-8547 = %+v", r)
	}
	if r := refs["cryptrec-ls-0001"]; !strings.HasPrefix(r.URL, "https://www.cryptrec.go.jp/") {
		t.Errorf("cryptrec-ls-0001 = %+v", r)
	}
	for _, r := range p.Rules {
		if len(r.Refs) == 0 || r.Summary == "" || (r.Quantum == "" && r.Classical == "") {
			t.Errorf("rule %s is incomplete: %+v", r.ID, r)
		}
		for _, id := range r.Refs {
			if _, ok := refs[id]; !ok {
				t.Errorf("rule %s refers to an unknown reference %q", r.ID, id)
			}
		}
	}
	if _, ok := rs.Policy("nosuch"); ok {
		t.Error("unknown policy must not be found")
	}
	// 暗号スイートの属性は、名前から引ける（どの版の対応表でも同じ）
	if s, ok := rs.SuiteAttributes("ECDHE-RSA-AES256-GCM-SHA384"); !ok || s.Kx != "ECDH" || s.Au != "RSA" || s.Enc != "AESGCM(256)" || s.Mac != "AEAD" {
		t.Errorf("suite attributes = %+v %v", s, ok)
	}
	if s, ok := rs.SuiteAttributes("TLS_AES_128_GCM_SHA256"); !ok || s.Kx != "any" || s.Protocol != "TLSv1.3" {
		t.Errorf("TLS 1.3 suite attributes = %+v %v", s, ok)
	}
	if _, ok := rs.SuiteAttributes("NO-SUCH-SUITE"); ok {
		t.Error("unknown suite must not be found")
	}
}

// 同じ名前の暗号スイートは、どの版の対応表でも同じ属性を持つ（名前から属性を引いてよいことの確認）。
func TestSuiteAttributesAreConsistentAcrossTables(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, tb := range rs.CipherTables {
		for _, list := range [][]CipherSuite{tb.Suites, tb.TLS13} {
			for _, s := range list {
				a := s.Kx + "|" + s.Au + "|" + s.Enc + "|" + s.Mac
				if old, ok := seen[s.Name]; ok && old != a {
					t.Errorf("%s: %s in one table, %s in another", s.Name, old, a)
				}
				seen[s.Name] = a
			}
		}
	}
}

// 評価ポリシーにも出典が必須。壊れたポリシーは読み込み時に拒否する。
func TestLoadPolicy(t *testing.T) {
	base := map[string]string{"manifest.yaml": okManifest, "catalog/algorithms.yaml": okCatalog}
	with := func(y string) map[string]string {
		m := map[string]string{"policies/p.yaml": y}
		for k, v := range base {
			m[k] = v
		}
		return m
	}
	head := "policy:\n  id: mine\n  title: \"My policy\"\n  version: \"1\"\n"
	refs := "  references:\n    - id: doc-a\n      title: \"Document A\"\n      url: \"https://example.org/a\"\n"
	rule := func(body string) string { return "  rules:\n    - id: r1\n" + body }
	good := "      scheme: tls-kx\n      match: { names: [RSA, \"EC*\"] }\n      role: key-establishment\n      quantum: vulnerable\n      classical: legacy\n      tags: [no-forward-secrecy]\n      summary: \"text\"\n      refs: [doc-a]\n"
	rs, err := Load(mapFS(with(head + refs + rule(good))))
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := rs.Policy("mine"); !ok || len(p.Rules) != 1 || p.Rules[0].Quantum != "vulnerable" || p.Rules[0].Match.Names[1] != "EC*" {
		t.Errorf("policy = %+v %v", p, ok)
	}
	for name, y := range map[string]string{
		"no references":          head + rule(good),
		"rule without refs":      head + refs + rule("      scheme: tls-kx\n      match: { names: [RSA] }\n      quantum: vulnerable\n      summary: \"text\"\n"),
		"unknown reference":      head + refs + rule(strings.Replace(good, "[doc-a]", "[doc-b]", 1)),
		"reference not https":    head + strings.Replace(refs, "https://", "http://", 1) + rule(good),
		"no verdict":             head + refs + rule("      scheme: tls-kx\n      match: { names: [RSA] }\n      summary: \"text\"\n      refs: [doc-a]\n"),
		"bad quantum value":      head + refs + rule(strings.Replace(good, "quantum: vulnerable", "quantum: broken", 1)),
		"bad classical value":    head + refs + rule(strings.Replace(good, "classical: legacy", "classical: bad", 1)),
		"bad scheme":             head + refs + rule(strings.Replace(good, "scheme: tls-kx", "scheme: nosuch", 1)),
		"bad role":               head + refs + rule(strings.Replace(good, "role: key-establishment", "role: nosuch", 1)),
		"no summary":             head + refs + rule(strings.Replace(good, "      summary: \"text\"\n", "", 1)),
		"empty match":            head + refs + rule(strings.Replace(good, "match: { names: [RSA, \"EC*\"] }", "match: {}", 1)),
		"bad pattern":            head + refs + rule(strings.Replace(good, "\"EC*\"", "\"EC[\"", 1)),
		"family outside catalog": head + refs + rule(strings.Replace(good, "match: { names: [RSA, \"EC*\"] }", "match: { family: [RSA] }", 1)),
		"duplicate rule":         head + refs + rule(good) + "    - id: r1\n" + good,
		"duplicate policy":       head + refs + rule(good) + "---\n",
		"unknown key":            head + refs + rule(good) + "      surprise: 1\n",
	} {
		if _, err := Load(mapFS(with(y))); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// HAProxy のルールと既定の表。
func TestBuiltinHAProxy(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	var app *AppRule
	for i := range rs.Apps {
		if rs.Apps[i].ID == "haproxy" {
			app = &rs.Apps[i]
		}
	}
	if app == nil || app.Grammar != "haproxy" || len(app.Sources) == 0 || app.Direction != "inbound" {
		t.Fatalf("haproxy app rule = %+v", app)
	}
	if d, ok := app.Directive("ssl-default-bind-ciphers"); !ok || d.Parameter != "tls.ciphers" || d.Type != "cipher-string" {
		t.Errorf("ssl-default-bind-ciphers = %+v %v", d, ok)
	}
	if d, ok := app.Directive("tune.ssl.default-dh-param"); !ok || d.Type != "int" {
		t.Errorf("tune.ssl.default-dh-param = %+v %v", d, ok)
	}
	v, _, ok := rs.AppDefaults("haproxy", "haproxy", "2.8.14-3.el9_8.2")
	if !ok || strings.Join(v["tls.ciphers"], "|") != "@system" || strings.Join(v["tls.dhe-without-params"], "|") != "disabled" || strings.Join(v["tls.certificate-selection"], "|") != "all" {
		t.Errorf("haproxy on RHEL 9 = %v %v", v, ok)
	}
	if v, _, ok := rs.AppDefaults("haproxy", "haproxy", "1.6.3-1ubuntu0.3"); !ok || strings.Join(v["tls.certificate-selection"], "|") != "first" || strings.Join(v["tls.dhe-without-params"], "|") != "builtin" {
		t.Errorf("haproxy on Ubuntu 16.04 = %v %v", v, ok)
	}
}
