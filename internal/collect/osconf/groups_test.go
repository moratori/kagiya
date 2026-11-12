package osconf

import (
	"os"
	"regexp"
	"testing"
)

// RHEL 10.3 の暗号ポリシーが生成する Groups は、OpenSSL 3.5 の書き方（「?」「/」）を使う。実物の値（検証ラボで採取）を読めること。
func TestGroupsInExtendedSyntax(t *testing.T) {
	const groups = "*?X25519MLKEM768:?x25519_mlkem768:?SecP256r1MLKEM768:?p256_mlkem768:?SecP384r1MLKEM1024:?p384_mlkem1024/*?X25519:?secp256r1:?X448:?secp521r1:?secp384r1:?ffdhe2048:?ffdhe3072:?ffdhe4096:?ffdhe6144:?ffdhe8192"
	_, inv := collect(t, "rhel9", func(p string) {
		f := p + "/etc/crypto-policies/back-ends/opensslcnf.config"
		b, _ := os.ReadFile(f)
		os.WriteFile(f, regexp.MustCompile(`(?m)^Groups = .*$`).ReplaceAll(b, []byte("Groups = "+groups)), 0o644)
	})
	if v := settings(inv)["openssl.system_default.Groups"]; v.Value != groups {
		t.Errorf("Groups = %+v", v)
	}
	if len(inv.Skipped) != 0 {
		t.Errorf("skipped = %+v", inv.Skipped)
	}
}

// 値を記録しなかった項目は、「書かれているが読めていない」ことが分かるように残す
// （残さないと、後の処理が「指定なし」として扱い、誤った結果を高い確度で出してしまう）。
func TestRejectedSystemDefaultIsMarked(t *testing.T) {
	_, inv := collect(t, "rhel9", func(p string) {
		f := p + "/etc/crypto-policies/back-ends/opensslcnf.config"
		b, _ := os.ReadFile(f)
		os.WriteFile(f, regexp.MustCompile(`(?m)^Groups = .*$`).ReplaceAll(b, []byte("Groups = X25519{bad}")), 0o644)
	})
	marked := false
	for _, s := range inv.OSSettings {
		if s.ID == "openssl.system_default.Groups" {
			t.Errorf("a rejected value was emitted: %+v", s)
		}
		if s.ID == "openssl.system_default.unread" && s.Value == "Groups" {
			marked = true
		}
	}
	if !marked {
		t.Errorf("the rejected Groups setting is not marked as unread: %+v", inv.OSSettings)
	}
}
