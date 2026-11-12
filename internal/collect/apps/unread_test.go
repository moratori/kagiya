//go:build unix

package apps

import (
	"strings"
	"testing"

	"kagiya/internal/inventory"
	"kagiya/internal/model"
)

// システムの openssl.cnf に書かれているが値を読めなかった項目があるときは、「指定なし」として扱わず、求めない。
func TestUnreadSystemDefaultIsNotTreatedAsAbsent(t *testing.T) {
	nginx := map[string]string{nginxConf: "server { listen 127.0.0.1:8443 ssl; server_name default.lab.test; " + nginxCerts + " }\n"}
	scope := "server default.lab.test"
	unread := func(key string, prepare func(p string, b *inventory.Builder)) func(p string, b *inventory.Builder) {
		return func(p string, b *inventory.Builder) {
			b.AddOSSetting(model.OSSetting{ID: "openssl.system_default.unread", Value: key, Path: "/etc/crypto-policies/back-ends/opensslcnf.config"})
			prepare(p, b)
		}
	}
	// Groups を読めていない → グループは求めない。暗号スイートには影響しない
	_, inv := collect(t, "rhel9", unread("Groups", rhel9Web(t, "3.5.9", "1.el9_9", nginx)))
	if e := eff(t, inv, "svc:nginx", "tls.groups", scope); e.Status != "unresolved" || !strings.Contains(e.Reason, "system") {
		t.Errorf("groups with an unread system setting: %+v", e)
	}
	if e := eff(t, inv, "svc:nginx", "tls.ciphers", scope); e.Status != "resolved" {
		t.Errorf("ciphers must not be affected: %+v", e)
	}
	// アプリの設定がグループを指定していれば、システムの Groups は使われないので求められる
	custom := map[string]string{nginxConf: "server { listen 127.0.0.1:8443 ssl; server_name default.lab.test; " + nginxCerts + " ssl_ecdh_curve prime256v1; }\n"}
	_, inv = collect(t, "rhel9", unread("Groups", rhel9Web(t, "3.5.9", "1.el9_9", custom)))
	if e := groupsOf(t, inv, "svc:nginx", scope); strings.Join(e.Values, " ") != "P-256" {
		t.Errorf("groups set by the application: %+v", e)
	}
	// CipherString / Ciphersuites を読めていない → 暗号スイートは求めない（セキュリティレベルも分からない）
	for _, key := range []string{"CipherString", "Ciphersuites"} {
		_, inv = collect(t, "rhel9", unread(key, rhel9Web(t, "3.5.9", "1.el9_9", nginx)))
		for _, param := range []string{"tls.ciphers", "tls.ciphersuites-tls13"} {
			if e := eff(t, inv, "svc:nginx", param, scope); e.Status != "unresolved" || !strings.Contains(e.Reason, "system") {
				t.Errorf("%s with an unread %s: %+v", param, key, e)
			}
		}
	}
}
