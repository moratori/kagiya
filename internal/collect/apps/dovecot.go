package apps

import (
	"sort"
	"strings"

	"kagiya/internal/model"
	"kagiya/internal/parse/dovecotconf"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

// このファイルは Dovecot の設定の読み取り。
//
// Dovecot の決まり方（検証ラボで、8 つのディストリの Dovecot 2.2〜2.4 を実際に起動して確かめたもの）:
//
//   - 設定は dovecot.conf と、そこから取り込まれるファイル（conf.d/*.conf を名前の順）。同じ項目は、後に読まれたものが効く。
//     「protocol imap { }」の中の記載は、そのプロトコルにだけ効く。
//   - 暗号文字列（ssl_cipher_list）は、そのまま OpenSSL に渡る。指定がなければ Dovecot 自身の既定。
//     鍵交換のグループ（ssl_curve_list）と TLS 1.3 のスイート（ssl_cipher_suites）は、指定がなければシステムの設定、ライブラリの既定に従う。
//   - 証明書は 2 つまで（ssl_cert と ssl_alt_cert。2.4 は ssl_server_cert_file と ssl_server_alt_cert_file）。
//   - DHE は、DH パラメータのファイルを指定したときだけ使える（2.2 は、自分で生成したパラメータで使える）。
//   - 接続を受けるプロセス（imap-login など）は、既定では chroot の中で動く。その中からは RHEL 系の暗号ポリシーのファイルを読めないので、
//     暗号文字列の「PROFILE=SYSTEM」（RHEL 系が配る設定）は、ライブラリの既定（DEFAULT）として働く。

// TLS の指定を追う項目（どちらの版の名前も）。
var dovecotTLSKeys = map[string]bool{
	"ssl": true, "ssl_cipher_list": true, "ssl_cipher_suites": true, "ssl_curve_list": true,
	"ssl_cert": true, "ssl_alt_cert": true, "ssl_dh": true,
	"ssl_server_cert_file": true, "ssl_server_alt_cert_file": true, "ssl_server_dh_file": true,
}

func (c *Collector) dovecot(app ruleset.AppRule, svc model.Service, config string) {
	if config == "" {
		return
	}
	ds, problems := dovecotconf.Parse(config, confFS{c})
	for _, pr := range problems {
		c.Builder.Skip(safefs.Skip{Path: c.Prefix + config, Reason: "config-problem", Detail: pr})
	}
	defs, _, _, _ := c.appDefaults(app)

	// プロトコルごとに範囲を分けるもの: 「protocol X { }」の中に TLS の指定がある、または「service X-login { chroot = }」で chroot を外している
	protos := map[string]bool{}
	unchrooted := map[string]bool{}
	untracked := "" // 追わない入れ子（local_name など）の中に TLS の指定がある
	for _, d := range ds {
		switch {
		case len(d.Sections) == 1 && strings.HasPrefix(d.Sections[0], "protocol ") && dovecotTLSKeys[d.Key]:
			protos[strings.TrimPrefix(d.Sections[0], "protocol ")] = true
		case len(d.Sections) == 1 && strings.HasPrefix(d.Sections[0], "service ") && strings.HasSuffix(d.Sections[0], "-login") && d.Key == "chroot":
			p := strings.TrimSuffix(strings.TrimPrefix(d.Sections[0], "service "), "-login")
			unchrooted[p] = d.Value == ""
			if d.Value == "" {
				protos[p] = true
			} // 後に書かれた記載が効く
		case len(d.Sections) >= 1 && dovecotTLSKeys[d.Key] && d.Key != "ssl":
			if head := strings.Fields(d.Sections[0])[0]; head != "protocol" && head != "service" && head != "ssl_server" && head != "ssl_client" && untracked == "" {
				untracked = head
			}
		}
	}
	names := []string{""}
	for p := range protos {
		if scopeText.MatchString("protocol " + p) {
			names = append(names, p)
		}
	}
	sort.Strings(names)

	recorded := map[string]bool{}
	var scopes []tlsScope
	for _, proto := range names {
		scope := ""
		if proto != "" {
			scope = "protocol " + proto
		}
		// この範囲に効く記載: 最上位と、そのプロトコルの入れ子。後に読まれたものが効く
		last := map[string]dovecotconf.Directive{}
		for _, d := range ds {
			if len(d.Sections) == 0 || (proto != "" && len(d.Sections) == 1 && d.Sections[0] == "protocol "+proto) {
				last[d.Key] = d
			}
		}
		for _, d := range ds {
			own := len(d.Sections) == 1 && proto != "" && d.Sections[0] == "protocol "+proto
			if (len(d.Sections) != 0 && !own) || (own != (scope != "")) {
				continue
			}
			id := d.File + "\x00" + d.Key + "\x00" + scope
			if rule, ok := app.Directive(d.Key); ok && d.Value != "" && last[d.Key].Line == d.Line && last[d.Key].File == d.File && !recorded[id] {
				recorded[id] = true
				c.record(app, svc, rule, strings.TrimPrefix(d.Value, "<"), d.File, d.Line, scope, dirOf(config))
			}
		}
		if v := strings.ToLower(last["ssl"].Value); v == "no" {
			continue // TLS を使わない
		}
		sc := tlsScope{name: scope, certsOK: true}
		if untracked != "" {
			sc.blocker = "TLS settings inside a " + untracked + " section are not interpreted"
			sc.groupsBlocker = sc.blocker
		}
		if d, ok := last["ssl_cipher_list"]; ok && d.Value != "" {
			sc.cipher, sc.cipherFile, sc.cipherLine = d.Value, d.File, d.Line
			const profile = "PROFILE=SYSTEM"
			if strings.HasPrefix(d.Value, profile) && !unchrooted[proto] {
				if strings.Join(defs["tls.profile-in-chroot"], ",") == "library-default" {
					sc.cipher = "DEFAULT" + d.Value[len(profile):]
					sc.info = append(sc.info, "PROFILE=SYSTEM is configured, but the login process runs in a chroot where the system crypto policy file is not readable, so the library default (DEFAULT) is used instead")
				} else if sc.blocker == "" {
					sc.blocker = "the effect of PROFILE=SYSTEM inside the chroot of the login process is not recorded for this version"
				}
			}
			if !validCipherString(sc.cipher) && sc.blocker == "" {
				sc.blocker = "the configured cipher string (ssl_cipher_list) is not interpreted"
			}
		}
		// 証明書: 古い書き方は「<ファイル」、2.4 はファイルの名前そのまま
		for _, key := range []string{"ssl_cert", "ssl_alt_cert", "ssl_server_cert_file", "ssl_server_alt_cert_file"} {
			d, ok := last[key]
			if !ok || d.Value == "" {
				continue
			}
			path := d.Value
			if strings.HasPrefix(key, "ssl_server_") {
				// そのまま
			} else if strings.HasPrefix(path, "<") {
				path = strings.TrimSpace(path[1:])
			} else {
				sc.certsOK = false // 設定に直接書かれた証明書
				continue
			}
			if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\x00\n*?[%$") {
				sc.certsOK = false
				continue
			}
			sc.certs = append(sc.certs, path)
		}
		sc.dhParam = last["ssl_dh"].Value != "" || last["ssl_server_dh_file"].Value != ""
		if d, ok := last["ssl_curve_list"]; ok && d.Value != "" {
			sc.setGroups(d.Value, d.File, d.Line, "ssl_curve_list")
		}
		if d, ok := last["ssl_cipher_suites"]; ok && d.Value != "" {
			if cipherString.MatchString(d.Value) {
				sc.tls13, sc.tls13File, sc.tls13Line = d.Value, d.File, d.Line
			} else {
				sc.tls13Blocker = "the configured TLS 1.3 suites (ssl_cipher_suites) are not interpreted"
			}
		}
		scopes = append(scopes, sc)
	}
	c.opensslServerEffective(app, svc, scopes)
}
