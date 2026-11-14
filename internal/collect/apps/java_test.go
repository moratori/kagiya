//go:build unix

package apps

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kagiya/internal/inventory"
	"kagiya/internal/model"
)

// 以下の期待値（プロトコル、スイートの数と要約値、グループ）は、検証ラボで各ディストリの OpenJDK を導入し、JDK 自身の報告
// （サーバーで有効なプロトコルとスイート）と、同じコンテナ内で起動した Java の TLS サーバーへのハンドシェイクで数え上げた結果
// （AlmaLinux 9.8 の java-21-openjdk-headless 21.0.13.0.9-1.2.el9.alma.1 と java-1.8.0-openjdk-headless 1.8.0.504.b01-1.2.el9.alma.1、
// AlmaLinux 10.2 の java-25-openjdk-headless 25.0.5.0.8-1.0.el10.alma.1、Debian 13 の openjdk-25-jre-headless 25.0.5+8-1~deb13u1）。
// java.security は、関係する行だけを書いたもの（実物の既定と同じ値）。

const (
	// 上流の既定（JDK 11 以降の最近の版。Debian / Ubuntu はこのまま配る）
	jdkUpstreamDisabled = "jdk.tls.disabledAlgorithms=SSLv3, TLSv1, TLSv1.1, DTLSv1.0, RC4, DES, \\\n" +
		"    MD5withRSA, DH keySize < 1024, EC keySize < 224, 3DES_EDE_CBC, anon, NULL, \\\n" +
		"    ECDH, TLS_RSA_*, rsa_pkcs1_sha1 usage HandshakeSignature, \\\n" +
		"    ecdsa_sha1 usage HandshakeSignature, dsa_sha1 usage HandshakeSignature\n"
	// Java 8（RHEL 系）の既定
	jdk8Disabled = "jdk.disabled.namedCurves = secp112r1, secp256k1, \\\n    brainpoolP256r1\n" +
		"jdk.tls.disabledAlgorithms=SSLv3, TLSv1, TLSv1.1, RC4, DES, MD5withRSA, \\\n" +
		"    DH keySize < 1024, EC keySize < 224, 3DES_EDE_CBC, anon, NULL, \\\n    ECDH, \\\n    include jdk.disabled.namedCurves\n"

	jdkDeb25Home  = "/usr/lib/jvm/java-25-openjdk-arm64"
	jdkEL9Home21  = "/usr/lib/jvm/java-21-openjdk-21.0.13.0.9-1.2.el9.alma.1.aarch64"
	jdkEL9Home8   = "/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.504.b01-1.2.el9.alma.1.aarch64"
	jdkEL10Home25 = "/usr/lib/jvm/java-25-openjdk"
	jdkPolicyFile = "/etc/crypto-policies/back-ends/java.config"

	jdkDefault12     = "698878ff8c0df26c" // 上流の既定での TLS 1.2 以下のスイート（27）
	jdkTLS13         = "0298a462f55e65f8" // TLS 1.3 のスイート（3）
	jdkGroups        = "P-256,P-384,P-521,X25519,X448,ffdhe2048,ffdhe3072,ffdhe4096,ffdhe6144,ffdhe8192"
	jdkGroupsHybrid  = "P-256,P-384,P-521,X25519,X25519MLKEM768,X448,ffdhe2048,ffdhe3072,ffdhe4096,ffdhe6144,ffdhe8192"
	jdkGroupsJava8   = "P-256,P-384,P-521,ffdhe2048,ffdhe3072,ffdhe4096,ffdhe6144,ffdhe8192"
	jdkParamDisabled = "tls.disabled-algorithms"
)

func jdkPolicy(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "java", name+"-java.config"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// jdkHost は、ファイルとパッケージを置いた状態を作る。
func jdkHost(t *testing.T, files map[string]string, pkgs ...model.Package) func(p string, b *inventory.Builder) {
	return func(p string, b *inventory.Builder) {
		for name, content := range files {
			if err := os.MkdirAll(filepath.Dir(p+name), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p+name, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		for _, pkg := range pkgs {
			b.AddPackage(pkg)
		}
	}
}

var (
	pkgDeb25  = model.Package{Manager: "dpkg", Name: "openjdk-25-jre-headless", Version: "25.0.5+8-1~deb13u1"}
	pkgEL9J21 = model.Package{Manager: "rpm", Name: "java-21-openjdk-headless", Version: "21.0.13.0.9", Release: "1.2.el9.alma.1"}
	pkgEL9J8  = model.Package{Manager: "rpm", Name: "java-1.8.0-openjdk-headless", Version: "1.8.0.504.b01", Release: "1.2.el9.alma.1"}
	pkgEL10   = model.Package{Manager: "rpm", Name: "java-25-openjdk-headless", Version: "25.0.5.0.8", Release: "1.0.el10.alma.1"}
)

func jdkEff(t *testing.T, inv *model.Inventory, param, home string) model.EffectiveValue {
	t.Helper()
	return eff(t, inv, "svc:openjdk", param, home)
}

// Debian 13 の JDK 25: java.security の既定のままで、TLS 1.3 と 1.2、耐量子のハイブリッド（X25519MLKEM768）を受け入れる。
func TestJDKDefaultsDebian13(t *testing.T) {
	sec := jdkDeb25Home + "/conf/security/java.security"
	prefix, inv := collect(t, "", jdkHost(t, map[string]string{sec: "security.provider.1=SUN\n" + jdkUpstreamDisabled}, pkgDeb25))
	svc := service(t, inv, "openjdk")
	if svc.ID != "svc:openjdk" || len(svc.ConfigFiles) != 1 || svc.ConfigFiles[0] != prefix+sec {
		t.Errorf("service = %+v", svc)
	}
	p := jdkEff(t, inv, "tls.protocols", jdkDeb25Home)
	if p.Status != "resolved" || strings.Join(p.Values, ",") != "TLSv1.3,TLSv1.2" || p.Confidence != "high" || p.Direction != "inbound" {
		t.Errorf("protocols = %+v", p)
	}
	e := jdkEff(t, inv, "tls.ciphers", jdkDeb25Home)
	checkSuites(t, e, 27, jdkDefault12, "high")
	if contains(e.Values, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV") {
		t.Error("the renegotiation marker is not a cipher suite and must not be listed")
	}
	if l := layers(e); l != "library/default app-config/remove" {
		t.Errorf("steps = %s", l)
	}
	if s := e.Steps[0].Source; s == nil || s.Package != "openjdk-25-jre-headless" || s.Version != "25.0.5+8-1~deb13u1" || !strings.HasPrefix(s.Image, "debian@sha256:") {
		t.Errorf("source = %+v", e.Steps[0].Source)
	}
	checkSuites(t, jdkEff(t, inv, "tls.ciphersuites-tls13", jdkDeb25Home), 3, jdkTLS13, "high")
	g := jdkEff(t, inv, "tls.groups", jdkDeb25Home)
	if g.Status != "resolved" || sortedJoin(g.Values) != jdkGroupsHybrid || g.Confidence != "high" {
		t.Errorf("groups = %+v", g)
	}
	// 根拠になった記載を、場所とともに記録する
	set := find(inv, jdkParamDisabled)
	if len(set) != 1 || set[0].Location.Path != prefix+sec || set[0].Location.Line != 2 || set[0].Scope != jdkDeb25Home ||
		set[0].Layer != "app-config" || !contains(set[0].Values, "TLS_RSA_*") || !contains(set[0].Values, "DH keySize < 1024") {
		t.Errorf("setting = %+v", set)
	}
	if e.Steps[1].Setting != set[0].ID {
		t.Errorf("the step must point at the setting: %+v", e.Steps[1])
	}
	// どれも「アプリが指定しない場合」の値であることを添える
	if !strings.Contains(strings.Join(e.Notes, " "), "unless the application") {
		t.Errorf("notes = %v", e.Notes)
	}
}

// RHEL 系の JDK 21: java.security の security.useSystemPropertiesFile=true により、暗号ポリシーのファイルの値が上書きする。
func TestJDKCryptoPolicyRHEL9(t *testing.T) {
	sec := jdkEL9Home21 + "/conf/security/java.security"
	files := map[string]string{
		sec:           "security.useSystemPropertiesFile=true\n" + jdkUpstreamDisabled,
		jdkPolicyFile: jdkPolicy(t, "alma9"),
	}
	prefix, inv := collect(t, "", jdkHost(t, files, pkgEL9J21))
	e := jdkEff(t, inv, "tls.ciphers", jdkEL9Home21)
	checkSuites(t, e, 27, "955590d039a4c6df", "high")
	if l := layers(e); l != "library/default os-policy/remove" {
		t.Errorf("steps = %s", l)
	}
	if p := jdkEff(t, inv, "tls.protocols", jdkEL9Home21); strings.Join(p.Values, ",") != "TLSv1.3,TLSv1.2" {
		t.Errorf("protocols = %v", p.Values)
	}
	if g := jdkEff(t, inv, "tls.groups", jdkEL9Home21); sortedJoin(g.Values) != jdkGroups {
		t.Errorf("groups = %+v", g)
	}
	set := find(inv, jdkParamDisabled)
	if len(set) != 1 || set[0].Location.Path != prefix+jdkPolicyFile || set[0].Layer != "os-policy" {
		t.Errorf("setting = %+v", set)
	}
	// 連動を切ってある場合（false）は、java.security の値のまま
	files[sec] = "security.useSystemPropertiesFile=false\n" + jdkUpstreamDisabled
	_, inv = collect(t, "", jdkHost(t, files, pkgEL9J21))
	e = jdkEff(t, inv, "tls.ciphers", jdkEL9Home21)
	checkSuites(t, e, 27, jdkDefault12, "high")
	if l := layers(e); l != "library/default app-config/remove" {
		t.Errorf("steps = %s", l)
	}
}

// RHEL 系の JDK 25: java.security の include から、暗号ポリシーのファイルを取り込む。
func TestJDKCryptoPolicyIncludeRHEL10(t *testing.T) {
	dir := jdkEL10Home25 + "/conf/security"
	files := map[string]string{
		dir + "/java.security":                          jdkUpstreamDisabled + "include redhat/${redhat.crypto-policies}/crypto-policies.properties\n",
		dir + "/redhat/crypto-policies.properties":      "include true/crypto-policies.properties\n",
		dir + "/redhat/true/crypto-policies.properties": "include " + jdkPolicyFile + "\ninclude ../${__redhat_fips__}/fips.properties\n",
		dir + "/redhat/false/fips.properties":           "",
		dir + "/redhat/true/fips.properties":            "__redhat_fips_filter__=true\n",
		jdkPolicyFile:                                   jdkPolicy(t, "alma10"),
		"/proc/sys/crypto/fips_enabled":                 "0\n",
	}
	prefix, inv := collect(t, "", jdkHost(t, files, pkgEL10))
	e := jdkEff(t, inv, "tls.ciphers", jdkEL10Home25)
	checkSuites(t, e, 21, "ac7fad05bc5bcf16", "high")
	if l := layers(e); l != "library/default os-policy/remove" {
		t.Errorf("steps = %s", l)
	}
	if g := jdkEff(t, inv, "tls.groups", jdkEL10Home25); sortedJoin(g.Values) != jdkGroupsHybrid {
		t.Errorf("groups = %+v", g)
	}
	if set := find(inv, jdkParamDisabled); len(set) != 1 || set[0].Location.Path != prefix+jdkPolicyFile {
		t.Errorf("setting = %+v", set)
	}
}

// Java 8: 鍵交換のグループは P-256 / P-384 / P-521 と ffdhe だけ。DHE の既定の鍵長が 1024 ビットであることを添える。
func TestJDK8(t *testing.T) {
	sec := jdkEL9Home8 + "/jre/lib/security/java.security"
	// 配られた状態（暗号ポリシーとの連動あり）
	_, inv := collect(t, "", jdkHost(t, map[string]string{sec: "security.useSystemPropertiesFile=true\n" + jdk8Disabled, jdkPolicyFile: jdkPolicy(t, "alma9")}, pkgEL9J8))
	p := jdkEff(t, inv, "tls.protocols", jdkEL9Home8)
	if strings.Join(p.Values, ",") != "TLSv1.3,TLSv1.2,SSLv2Hello" {
		t.Errorf("protocols = %v", p.Values)
	}
	e := jdkEff(t, inv, "tls.ciphers", jdkEL9Home8)
	checkSuites(t, e, 24, "5320181f2611ce1a", "high")
	if !strings.Contains(strings.Join(e.Notes, " "), "1024-bit") {
		t.Errorf("the DHE default size must be noted: %v", e.Notes)
	}
	checkSuites(t, jdkEff(t, inv, "tls.ciphersuites-tls13", jdkEL9Home8), 2, "080c925e0b00a67d", "high")
	if g := jdkEff(t, inv, "tls.groups", jdkEL9Home8); sortedJoin(g.Values) != jdkGroupsJava8 {
		t.Errorf("groups = %+v", g)
	}
	// 連動を切った場合（java.security の値のまま）
	_, inv = collect(t, "", jdkHost(t, map[string]string{sec: jdk8Disabled}, pkgEL9J8))
	checkSuites(t, jdkEff(t, inv, "tls.ciphers", jdkEL9Home8), 30, "f3b54407c1bef775", "high")
	// 2048 ビットの版では、この注記は出ない
	_, inv = collect(t, "", jdkHost(t, map[string]string{jdkDeb25Home + "/conf/security/java.security": jdkUpstreamDisabled}, pkgDeb25))
	if e := jdkEff(t, inv, "tls.ciphers", jdkDeb25Home); strings.Contains(strings.Join(e.Notes, " "), "1024-bit") {
		t.Errorf("notes = %v", e.Notes)
	}
}

// 導入されている JDK ごとに、別々の範囲として求める。JDK がなければ、何も出さない。
func TestJDKMultipleAndNone(t *testing.T) {
	files := map[string]string{
		jdkEL9Home21 + "/conf/security/java.security":   jdkUpstreamDisabled,
		jdkEL9Home8 + "/jre/lib/security/java.security": jdk8Disabled,
	}
	_, inv := collect(t, "", jdkHost(t, files, pkgEL9J21, pkgEL9J8))
	if g := jdkEff(t, inv, "tls.groups", jdkEL9Home21); sortedJoin(g.Values) != jdkGroups {
		t.Errorf("JDK 21 groups = %+v", g)
	}
	if g := jdkEff(t, inv, "tls.groups", jdkEL9Home8); sortedJoin(g.Values) != jdkGroupsJava8 {
		t.Errorf("JDK 8 groups = %+v", g)
	}
	if n := len(find(inv, jdkParamDisabled)); n != 2 {
		t.Errorf("%d settings, want 2", n)
	}
	_, inv = collect(t, "", nil)
	for _, s := range inv.Services {
		if s.App == "openjdk" {
			t.Errorf("no JDK is installed, but a service was reported: %+v", s)
		}
	}
}

// 測定した版とリリースだけが違う場合は、測定した版の表で補い、確度を下げて注記する。
func TestJDKInterpolated(t *testing.T) {
	home := "/usr/lib/jvm/java-21-openjdk-21.0.13.0.9-5.el9.aarch64"
	pkg := model.Package{Manager: "rpm", Name: "java-21-openjdk-headless", Version: "21.0.13.0.9", Release: "5.el9"}
	_, inv := collect(t, "", jdkHost(t, map[string]string{home + "/conf/security/java.security": jdkUpstreamDisabled}, pkg))
	e := jdkEff(t, inv, "tls.ciphers", home)
	checkSuites(t, e, 27, jdkDefault12, "medium")
	if !strings.Contains(strings.Join(e.Notes, " "), "21.0.13.0.9-1.2.el9.alma.1") {
		t.Errorf("notes = %v", e.Notes)
	}
	if g := jdkEff(t, inv, "tls.groups", home); g.Confidence != "medium" || sortedJoin(g.Values) != jdkGroups {
		t.Errorf("groups = %+v", g)
	}
}

// 求められない場合は、推測で埋めずに、理由を残す。
func TestJDKUnresolved(t *testing.T) {
	debSec := jdkDeb25Home + "/conf/security/java.security"
	el9Sec := jdkEL9Home21 + "/conf/security/java.security"
	for name, c := range map[string]struct {
		files  map[string]string
		pkgs   []model.Package
		home   string
		reason string
	}{
		"a version that has not been measured": {
			map[string]string{debSec: jdkUpstreamDisabled},
			[]model.Package{{Manager: "dpkg", Name: "openjdk-25-jre-headless", Version: "25.0.9+3-1~deb13u1"}}, jdkDeb25Home, "no JDK table"},
		"no package information": {
			map[string]string{debSec: jdkUpstreamDisabled}, nil, jdkDeb25Home, "package"},
		"FIPS mode": {
			map[string]string{el9Sec: "security.useSystemPropertiesFile=true\n" + jdkUpstreamDisabled, jdkPolicyFile: jdkPolicy(t, "alma9"), "/proc/sys/crypto/fips_enabled": "1\n"},
			[]model.Package{pkgEL9J21}, jdkEL9Home21, "FIPS"},
		"an include on a build where it has not been measured": {
			map[string]string{debSec: jdkUpstreamDisabled + "include extra.security\n", jdkDeb25Home + "/conf/security/extra.security": "a=b\n"},
			[]model.Package{pkgDeb25}, jdkDeb25Home, "include"},
		"the policy switch on a build where it has not been measured": {
			map[string]string{debSec: "security.useSystemPropertiesFile=true\n" + jdkUpstreamDisabled},
			[]model.Package{pkgDeb25}, jdkDeb25Home, "security.useSystemPropertiesFile"},
		"the policy file cannot be read": {
			map[string]string{el9Sec: "security.useSystemPropertiesFile=true\n" + jdkUpstreamDisabled},
			[]model.Package{pkgEL9J21}, jdkEL9Home21, "java.config"},
		"an included file cannot be read": {
			map[string]string{jdkEL10Home25 + "/conf/security/java.security": jdkUpstreamDisabled + "include redhat/crypto-policies.properties\n"},
			[]model.Package{pkgEL10}, jdkEL10Home25, "cannot be read"},
		"no jdk.tls.disabledAlgorithms": {
			map[string]string{debSec: "security.provider.1=SUN\n"}, []model.Package{pkgDeb25}, jdkDeb25Home, "jdk.tls.disabledAlgorithms"},
		"a value that is not interpreted": {
			map[string]string{debSec: "jdk.tls.disabledAlgorithms=SSLv3, $(bad), TLSv1\n"}, []model.Package{pkgDeb25}, jdkDeb25Home, "not interpreted"},
	} {
		_, inv := collect(t, "", jdkHost(t, c.files, c.pkgs...))
		for _, param := range []string{"tls.protocols", "tls.ciphers", "tls.ciphersuites-tls13", "tls.groups"} {
			e := jdkEff(t, inv, param, c.home)
			if e.Status != "unresolved" || len(e.Values) != 0 || !strings.Contains(e.Reason, c.reason) {
				t.Errorf("%s: %s = %s %v reason=%q, want unresolved with %q", name, param, e.Status, e.Values, e.Reason, c.reason)
			}
		}
	}
	// グループだけが求められない場合（実測で確かめていない書き方）は、ほかの項目は求める
	_, inv := collect(t, "", jdkHost(t, map[string]string{debSec: "jdk.tls.disabledAlgorithms=SSLv3, TLSv1, TLSv1.1, EC keySize <= 384\n"}, pkgDeb25))
	if g := jdkEff(t, inv, "tls.groups", jdkDeb25Home); g.Status != "unresolved" || !strings.Contains(g.Reason, "not been measured") {
		t.Errorf("groups = %+v", g)
	}
	if e := jdkEff(t, inv, "tls.ciphers", jdkDeb25Home); e.Status != "resolved" || len(e.Values) == 0 {
		t.Errorf("ciphers = %+v", e)
	}
}

// 配布元の JDK（ディストリのパッケージではないもの）: JDK のディレクトリにある release ファイルの JAVA_VERSION が、
// 測定した表の開発元の版と同じなら、その表で補う（確度を下げ、注記を付ける）。何を無効にするかは、その JDK 自身の java.security から読む。
// 期待値は、検証ラボで Amazon Corretto 21（21.0.13）と 8（1.8.0_512）、Eclipse Temurin 25（25.0.5）の公式イメージの JDK を、
// ディストリの JDK と同じ方法で測った結果。
func TestJDKOtherDistributor(t *testing.T) {
	// Corretto 21（/usr/lib/jvm/java-21-amazon-corretto.aarch64。版の付かない名前は、そこへのリンク）
	home := "/usr/lib/jvm/java-21-amazon-corretto.aarch64"
	files := map[string]string{
		home + "/conf/security/java.security": jdkUpstreamDisabled,
		home + "/release":                     "IMPLEMENTOR=\"Amazon.com Inc.\"\nJAVA_VERSION=\"21.0.13\"\nJAVA_VERSION_DATE=\"2026-10-20\"\nOS_ARCH=\"aarch64\"\n",
	}
	_, inv := collect(t, "", func(p string, b *inventory.Builder) {
		jdkHost(t, files)(p, b)
		link(t, p, "java-21-amazon-corretto.aarch64", "/usr/lib/jvm/java-21-amazon-corretto")
	})
	e := jdkEff(t, inv, "tls.ciphers", home)
	checkSuites(t, e, 27, jdkDefault12, "medium")
	notes := strings.Join(e.Notes, " ")
	if !strings.Contains(notes, "21.0.13") || !strings.Contains(notes, "another distributor") {
		t.Errorf("notes = %v", e.Notes)
	}
	if s := e.Steps[0].Source; s == nil || s.Package == "" || !strings.Contains(s.Image, "@sha256:") {
		t.Errorf("source = %+v", e.Steps[0].Source)
	}
	if g := jdkEff(t, inv, "tls.groups", home); g.Confidence != "medium" || sortedJoin(g.Values) != jdkGroups {
		t.Errorf("groups = %+v", g)
	}
	n := 0
	for _, v := range inv.EffectiveValues {
		if v.Service == "svc:openjdk" && v.Parameter == "tls.ciphers" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("the JDK must be reported once (the unversioned name is a link to it): %d", n)
	}

	// Temurin 25 の公式イメージの配置（/opt/java/openjdk）。耐量子のハイブリッドを受け入れる
	tem := "/opt/java/openjdk"
	_, inv = collect(t, "", jdkHost(t, map[string]string{tem + "/conf/security/java.security": jdkUpstreamDisabled,
		tem + "/release": "IMPLEMENTOR=\"Eclipse Adoptium\"\nJAVA_VERSION=\"25.0.5\"\n"}))
	if g := jdkEff(t, inv, "tls.groups", tem); g.Confidence != "medium" || sortedJoin(g.Values) != jdkGroupsHybrid {
		t.Errorf("Temurin 25 groups = %+v", g)
	}

	// Corretto 8 は、java.security の既定が違い、TLS 1.0 と 1.1 を無効にしていない（実測）。配布元ごとの違いは、ファイルから読んだ値に現れる
	c8 := "/usr/lib/jvm/java-1.8.0-amazon-corretto.aarch64"
	_, inv = collect(t, "", jdkHost(t, map[string]string{
		c8 + "/jre/lib/security/java.security": "jdk.disabled.namedCurves = secp112r1, secp256k1\n" +
			"jdk.tls.disabledAlgorithms=SSLv3, RC4, DES, MD5withRSA, DH keySize < 1024, \\\n    EC keySize < 224, anon, NULL, ECDH, \\\n    include jdk.disabled.namedCurves\n",
		c8 + "/release": "JAVA_VERSION=\"1.8.0_512\"\nIMPLEMENTOR=\"Amazon.com Inc.\"\n"}))
	if p := jdkEff(t, inv, "tls.protocols", c8); strings.Join(p.Values, ",") != "TLSv1.3,TLSv1.2,TLSv1.1,TLSv1,SSLv2Hello" || p.Confidence != "medium" {
		t.Errorf("Corretto 8 protocols = %+v", p)
	}
	checkSuites(t, jdkEff(t, inv, "tls.ciphers", c8), 35, "12681ad093c3755c", "medium")

	// 補わない場合
	for name, c := range map[string]struct {
		sec, release, reason string
	}{
		"a Java version that has not been measured": {jdkUpstreamDisabled, "JAVA_VERSION=\"21.0.99\"\n", "21.0.99"},
		"no release file":                      {jdkUpstreamDisabled, "", "package"},
		"a release file without JAVA_VERSION":  {jdkUpstreamDisabled, "IMPLEMENTOR=\"X\"\n", "package"},
		"a JAVA_VERSION that is not a version": {jdkUpstreamDisabled, "JAVA_VERSION=\"21.0.13; rm\"\n", "package"},
		// 暗号ポリシーとのつなぎ方は、測ったディストリの JDK のもの。配布元の違う JDK には当てはめない
		"the policy switch of another distribution": {"security.useSystemPropertiesFile=true\n" + jdkUpstreamDisabled, "JAVA_VERSION=\"21.0.13\"\n", "security.useSystemPropertiesFile"},
		"an include": {jdkUpstreamDisabled + "include extra.security\n", "JAVA_VERSION=\"25.0.5\"\n", "include"},
	} {
		f := map[string]string{home + "/conf/security/java.security": c.sec, home + "/conf/security/extra.security": "a=b\n", jdkPolicyFile: jdkPolicy(t, "alma9")}
		if c.release != "" {
			f[home+"/release"] = c.release
		}
		_, inv := collect(t, "", jdkHost(t, f))
		if e := jdkEff(t, inv, "tls.ciphers", home); e.Status != "unresolved" || !strings.Contains(e.Reason, c.reason) {
			t.Errorf("%s: %s reason=%q, want unresolved with %q", name, e.Status, e.Reason, c.reason)
		}
	}

	// ディストリのパッケージの JDK で、その版の表がなくても、開発元の版が同じ表（別のディストリで測ったもの）があれば補う
	pkg := model.Package{Manager: "rpm", Name: "java-21-openjdk-headless", Version: "21.0.13.0.9", Release: "1.fc43"}
	fhome := "/usr/lib/jvm/java-21-openjdk"
	_, inv = collect(t, "", jdkHost(t, map[string]string{fhome + "/conf/security/java.security": jdkUpstreamDisabled, fhome + "/release": "JAVA_VERSION=\"21.0.13\"\n"}, pkg))
	checkSuites(t, jdkEff(t, inv, "tls.ciphers", fhome), 27, jdkDefault12, "medium")
}

// JDK に含まれないセキュリティプロバイダ（BouncyCastle など）が登録されていると、TLS をどの実装が担当するかが変わりうる。
// その場合は JDK の表を当てはめず、値を求めない。JDK に含まれるプロバイダ（検証ラボの 35 の JDK の既定に現れたもの）は妨げにならない。
func TestJDKForeignProvider(t *testing.T) {
	sec := jdkDeb25Home + "/conf/security/java.security"
	std := "security.provider.1=SUN\nsecurity.provider.2=SunRsaSign\nsecurity.provider.3=SunEC\nsecurity.provider.4=SunJSSE\nsecurity.provider.5=SunJCE\n" +
		"security.provider.6=SunJGSS\nsecurity.provider.7=SunSASL\nsecurity.provider.8=XMLDSig\nsecurity.provider.9=SunPCSC\nsecurity.provider.10=JdkLDAP\n" +
		"security.provider.11=JdkSASL\nsecurity.provider.12=SunPKCS11\nfips.provider.1=SunPKCS11 ${java.home}/conf/security/nss.fips.cfg\n"
	_, inv := collect(t, "", jdkHost(t, map[string]string{sec: std + jdkUpstreamDisabled}, pkgDeb25))
	checkSuites(t, jdkEff(t, inv, "tls.ciphers", jdkDeb25Home), 27, jdkDefault12, "high")

	java8 := "security.provider.1=sun.security.provider.Sun\nsecurity.provider.2=sun.security.rsa.SunRsaSign\nsecurity.provider.3=sun.security.ec.SunEC\n" +
		"security.provider.4=com.sun.net.ssl.internal.ssl.Provider\nsecurity.provider.5=com.sun.crypto.provider.SunJCE\nsecurity.provider.6=sun.security.jgss.SunProvider\n" +
		"security.provider.7=com.sun.security.sasl.Provider\nsecurity.provider.8=org.jcp.xml.dsig.internal.dom.XMLDSigRI\nsecurity.provider.9=sun.security.smartcardio.SunPCSC\n"
	_, inv = collect(t, "", jdkHost(t, map[string]string{sec: java8 + jdkUpstreamDisabled}, pkgDeb25))
	checkSuites(t, jdkEff(t, inv, "tls.ciphers", jdkDeb25Home), 27, jdkDefault12, "high")

	for name, c := range map[string][2]string{
		"bouncy castle":   {"security.provider.13=org.bouncycastle.jce.provider.BouncyCastleProvider\n", "org.bouncycastle.jce.provider.BouncyCastleProvider"},
		"bc jsse first":   {"security.provider.1=org.bouncycastle.jsse.provider.BouncyCastleJsseProvider\n", "BouncyCastleJsseProvider"},
		"conscrypt":       {"security.provider.13=org.conscrypt.OpenSSLProvider\n", "org.conscrypt.OpenSSLProvider"},
		"pkcs11 config":   {"security.provider.12=SunPKCS11 /etc/pkcs11.cfg\n", "SunPKCS11"},
		"socket factory":  {"ssl.ServerSocketFactory.provider=com.example.Factory\n", "ssl.ServerSocketFactory.provider"},
		"key manager":     {"ssl.KeyManagerFactory.algorithm=PKIX-custom\n", "ssl.KeyManagerFactory.algorithm"},
		"unreadable name": {"security.provider.13=bad name here\n", "security.provider.13"},
	} {
		_, inv := collect(t, "", jdkHost(t, map[string]string{sec: std + c[0] + jdkUpstreamDisabled}, pkgDeb25))
		for _, p := range []string{"tls.protocols", "tls.ciphers", "tls.ciphersuites-tls13", "tls.groups"} {
			e := jdkEff(t, inv, p, jdkDeb25Home)
			if e.Status != "unresolved" || !strings.Contains(e.Reason, c[1]) {
				t.Errorf("%s %s: status=%s reason=%q", name, p, e.Status, e.Reason)
			}
		}
	}
	// 既定の値（SunX509、PKIX）は妨げにならない
	ok := "ssl.KeyManagerFactory.algorithm=SunX509\nssl.TrustManagerFactory.algorithm=PKIX\n"
	_, inv = collect(t, "", jdkHost(t, map[string]string{sec: std + ok + jdkUpstreamDisabled}, pkgDeb25))
	checkSuites(t, jdkEff(t, inv, "tls.ciphers", jdkDeb25Home), 27, jdkDefault12, "high")
}

// Tomcat を動かす JDK に、JDK に含まれないプロバイダが登録されている場合も、値を求めない。
func TestTomcatForeignProvider(t *testing.T) {
	extra := map[string]string{tcDebJava + "/conf/security/java.security": "security.provider.1=SUN\nsecurity.provider.2=org.bouncycastle.jce.provider.BouncyCastleProvider\n" + jdkUpstreamDisabled}
	_, inv := collect(t, "", tcDebian(t, tcServer(tcAPR, tcNIO, "", tcCertRSA), extra, tcDebPackages...))
	tcUnresolved(t, inv, "BouncyCastleProvider")
}
