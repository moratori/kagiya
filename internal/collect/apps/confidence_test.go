//go:build unix

package apps

import (
	"os"
	"strings"
	"testing"

	"kagiya/internal/inventory"
	"kagiya/internal/model"
)

// 確度の決め方（docs/confidence.md の 6 章）を、代表的な場合で確かめる。
// 材料は 2 つだけ: ルールを完全一致で見つけたか・補ったか、開発者がそのルールを数え上げで裏付けたか（ルールの verified-by-handshake）。

func hasQualifier(e model.EffectiveValue, q string) bool {
	for _, x := range e.Qualifiers {
		if x == q {
			return true
		}
	}
	return false
}

// sshd の既定値のルールは、項目によって裏付けが違う。鍵交換・暗号・MAC は、SSH の接続での数え上げで裏付けてある。
// ホスト鍵のアルゴリズムは、sshd -T の出力だけで、裏付けていない（サーバーが持つ鍵の種類で決まり、報告の一覧とは一致しない）。
func TestConfidenceUnverifiedRule(t *testing.T) {
	_, inv := collect(t, "ubuntu2404", withPackage(ubuntu2404Version, func(p string, b *inventory.Builder) {
		os.WriteFile(p+"/etc/ssh/sshd_config", []byte("Ciphers aes256-ctr\n"), 0o644)
	}))
	// 完全一致で、裏付けがあるので高
	if e := effectiveValue(t, inv, "ssh.kex-algorithms"); e.Status != "resolved" || e.Confidence != "high" {
		t.Errorf("kex (exact, verified) = %s %s", e.Status, e.Confidence)
	}
	// 完全一致でも、裏付けがないので中
	if e := effectiveValue(t, inv, "ssh.host-key-algorithms"); e.Status != "resolved" || e.Confidence != "medium" {
		t.Errorf("host key algorithms (exact, not verified) = %s %s", e.Status, e.Confidence)
	}
	// 設定に一覧がそのまま書かれている項目は、ルールを使わないので高
	if e := effectiveValue(t, inv, "ssh.ciphers"); strings.Join(e.Values, ",") != "aes256-ctr" || e.Confidence != "high" {
		t.Errorf("ciphers (written in the configuration) = %v %s", e.Values, e.Confidence)
	}
	_, inv = collect(t, "ubuntu2404", withPackage("1:9.6p1-3ubuntu13.99", nil))
	// 近い版のルールで補ったが、裏付けはあるので中
	if e := effectiveValue(t, inv, "ssh.kex-algorithms"); e.Status != "resolved" || e.Confidence != "medium" {
		t.Errorf("kex (filled, verified) = %s %s", e.Status, e.Confidence)
	}
	// 近い版のルールで補い、かつ裏付けがないので低
	if e := effectiveValue(t, inv, "ssh.host-key-algorithms"); e.Status != "resolved" || e.Confidence != "low" {
		t.Errorf("host key algorithms (filled, not verified) = %s %s", e.Status, e.Confidence)
	}
}

// 証明書の種類を判定できない（キーストアの中は読まない）場合: RSA の証明書の場合と EC の証明書の場合を合わせた一覧を出し、確度は下げない。
// DSA の証明書でしか使えないスイートは、入れない（DSA の証明書では数え上げていない）。
func TestConfidenceUnknownCertificateKind(t *testing.T) {
	ks := `<Certificate certificateKeystoreFile="conf/server.p12" certificateKeystorePassword="s3cret-tomcat" certificateKeystoreType="PKCS12"/>`
	_, inv := collect(t, "", tcDebian(t, tcServer(tcAPR, tcNIO, "", ks), nil, tcDebPackages...))
	e := tcEff(t, inv, "tls.ciphers")
	// RSA と EC の証明書を両方持つ場合（tcBoth12）と同じ一覧になる
	checkSuites(t, e, 21, tcBoth12, "high")
	if !hasQualifier(e, model.QualifierAnyCertificateKind) {
		t.Errorf("qualifiers = %v", e.Qualifiers)
	}
	for _, s := range e.Values {
		if strings.Contains(s, "_DSS_") {
			t.Errorf("a suite for DSA certificates is listed: %s", s)
		}
	}
	// 証明書の種類が分かる場合は、説明を付けない
	_, inv = collect(t, "", tcDebian(t, tcServer(tcAPR, tcNIO, "", tcCertRSA), nil, tcDebPackages...))
	if e := tcEff(t, inv, "tls.ciphers"); hasQualifier(e, model.QualifierAnyCertificateKind) || e.Confidence != "high" {
		t.Errorf("known kind: %s %v", e.Confidence, e.Qualifiers)
	}
}

// 動かす JDK を 1 つに決められない場合: 見つけた JDK のどれでも同じ値なら、その値を出す。決められないこと自体では、確度を下げない。
func TestConfidenceJDKNotIdentified(t *testing.T) {
	_, inv := collect(t, "", wfHost(t, "42.0.0.Final", wfElytron("", `ssl-context="labSSC"`), nil))
	p := wfEff(t, inv, "tls.protocols")
	if p.Confidence != "high" || !hasQualifier(p, model.QualifierAnyJDKFound) || hasQualifier(p, model.QualifierAnyCertificateKind) {
		t.Errorf("protocols = %s %v", p.Confidence, p.Qualifiers)
	}
	e := wfEff(t, inv, "tls.ciphers")
	if e.Confidence != "high" || !hasQualifier(e, model.QualifierAnyJDKFound) || !hasQualifier(e, model.QualifierAnyCertificateKind) {
		t.Errorf("ciphers = %s %v", e.Confidence, e.Qualifiers)
	}
	// RSA の 14 と EC の 7 だけ（合わせて 21）
	if len(e.Values) != 21 || setDigest(wfKind(e.Values, "RSA")) != wfRSA12 || setDigest(wfKind(e.Values, "EC")) != wfEC12 {
		t.Errorf("ciphers: %d values", len(e.Values))
	}
	// standalone.conf で JDK が決まる場合は、説明を付けない
	conf := "JAVA_HOME=\"" + wfJava17 + "\"\n" + wfStandaloneConf
	_, inv = collect(t, "", wfHost(t, "42.0.0.Final", wfElytron("", `ssl-context="labSSC"`), map[string]string{wfHome + "/bin/standalone.conf": conf}))
	if p := wfEff(t, inv, "tls.protocols"); p.Confidence != "high" || hasQualifier(p, model.QualifierAnyJDKFound) {
		t.Errorf("protocols with JAVA_HOME = %s %v", p.Confidence, p.Qualifiers)
	}
}

// 受け入れるものが 1 つもない設定: 空の一覧を出し、説明を付ける。確度は下げない。
func TestConfidenceNothingAccepted(t *testing.T) {
	_, inv := collect(t, "", wfHost(t, "42.0.0.Final", wfElytron(`protocols="TLSv1.3"`, `ssl-context="labSSC"`), nil))
	p := wfEff(t, inv, "tls.protocols")
	if p.Status != "resolved" || len(p.Values) != 0 || p.Confidence != "high" || !hasQualifier(p, model.QualifierNothingAccepted) {
		t.Errorf("protocols = %+v", p)
	}
	// 受け入れるものがある設定には、付けない
	_, inv = collect(t, "", wfHost(t, "42.0.0.Final", wfElytron("", `ssl-context="labSSC"`), nil))
	if p := wfEff(t, inv, "tls.protocols"); hasQualifier(p, model.QualifierNothingAccepted) {
		t.Errorf("qualifiers = %v", p.Qualifiers)
	}
}

// JDK の表は、項目によって裏付けが違う。暗号スイートとプロトコルは JDK 自身の報告（アプリのサーバーの数え上げで確かめた版だけ、裏付けあり）、
// グループは JDK 単体の数え上げ。Debian 13 の JDK 25 は、アプリのサーバーでは確かめていない。
func TestConfidenceJDKTableItems(t *testing.T) {
	sec := jdkDeb25Home + "/conf/security/java.security"
	_, inv := collect(t, "", jdkHost(t, map[string]string{sec: "security.provider.1=SUN\n" + jdkUpstreamDisabled}, pkgDeb25))
	if e := jdkEff(t, inv, "tls.ciphers", jdkDeb25Home); e.Status != "resolved" || e.Confidence != "medium" {
		t.Errorf("ciphers = %s %s", e.Status, e.Confidence)
	}
	if e := jdkEff(t, inv, "tls.protocols", jdkDeb25Home); e.Confidence != "medium" {
		t.Errorf("protocols = %s", e.Confidence)
	}
	if e := jdkEff(t, inv, "tls.groups", jdkDeb25Home); e.Status != "resolved" || e.Confidence != "high" {
		t.Errorf("groups = %s %s", e.Status, e.Confidence)
	}
}
