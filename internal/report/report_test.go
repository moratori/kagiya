package report

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"kagiya/internal/model"
	"kagiya/internal/ruleset"
)

func rules(t *testing.T) *ruleset.RuleSet {
	t.Helper()
	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func alg(id, family, primitive string, bits int) model.Asset {
	return model.Asset{ID: id, Type: "algorithm", Algorithm: &model.Algorithm{Family: family, Primitive: primitive, KeyBits: bits, Known: true}}
}

func cert(id, subject, notAfter, sig, key string, ca bool) model.Asset {
	return model.Asset{ID: id, Type: "certificate", Certificate: &model.Certificate{Subject: subject, Issuer: subject, Serial: "01",
		NotBefore: "2025-01-01T00:00:00Z", NotAfter: notAfter, IsCA: ca, SelfSigned: true,
		SignatureAlgorithm: sig, PublicKey: model.PublicKey{Algorithm: key}, FingerprintSHA256: strings.Repeat("ab", 32)}}
}

func occ(id, asset, path, store, level string, ev ...model.Evidence) model.Occurrence {
	return model.Occurrence{ID: id, Asset: asset, Collector: "fscrawl", State: "present", Confidence: "high",
		Location: model.Location{Kind: "file", Path: path}, Store: store, Activity: &model.Activity{Level: level, Evidence: ev}}
}

// sample は、1ホスト分の結果（実物の形に合わせた最小のもの）。
func sample() *model.Inventory {
	inv := &model.Inventory{Schema: model.Schema}
	inv.Meta = model.Meta{ScanID: "0123456789abcdef", StartedAt: "2026-11-12T10:00:00Z", FinishedAt: "2026-11-12T10:00:05Z", Completed: true,
		Tool: model.Tool{Version: "0.1.0"}, Rules: model.Rules{Source: "builtin", Version: "2026.11.0", SHA256: strings.Repeat("0", 64)},
		Host: model.Host{Hostname: "web01.example.jp", OS: "linux", Arch: "amd64"}, Labels: map[string]string{"system": "portal"},
		Privilege: model.Privilege{Elevated: true}}
	inv.Assets = []model.Asset{
		alg("alg:rsa-2048", "RSA", "public-key", 2048), alg("alg:rsa-1024", "RSA", "public-key", 1024), alg("alg:ec-p256", "EC", "curve", 256),
		alg("alg:sha256-with-rsa", "RSA", "signature", 0), alg("alg:sha1-with-rsa", "RSA", "signature", 0), alg("alg:ecdsa-with-sha256", "ECDSA", "signature", 0),
		cert("cert:www", "CN=www.example.jp,O=Example", "2027-06-01T00:00:00Z", "alg:sha256-with-rsa", "alg:rsa-2048", false),
		cert("cert:soon", "CN=soon.example.jp", "2026-11-20T00:00:00Z", "alg:ecdsa-with-sha256", "alg:ec-p256", false),
		cert("cert:expired", "CN=old.example.jp", "2026-01-01T00:00:00Z", "alg:sha1-with-rsa", "alg:rsa-1024", false),
		cert("cert:evil", `CN=<script>alert(1)</script>"'&`, "2030-01-01T00:00:00Z", "alg:sha256-with-rsa", "alg:rsa-2048", false),
		cert("cert:ca1", "CN=Root CA One", "2035-01-01T00:00:00Z", "alg:sha256-with-rsa", "alg:rsa-2048", true),
		cert("cert:ca2", "CN=Root CA Two", "2035-01-01T00:00:00Z", "alg:sha1-with-rsa", "alg:rsa-2048", true),
		cert("cert:ca3", "CN=Root CA Three", "2035-01-01T00:00:00Z", "alg:sha256-with-rsa", "alg:rsa-2048", true),
		{ID: "key:www", Type: "private-key", Key: &model.Key{Algorithm: "alg:rsa-2048"}},
		{ID: "key:orphan", Type: "private-key", Key: &model.Key{Algorithm: "alg:rsa-1024"}},
	}
	ref := model.Evidence{Kind: "config-reference", Path: "/etc/nginx/conf.d/tls.conf", Line: 4, Detail: "tls.certificate", Service: "svc:nginx"}
	inv.Occurrences = []model.Occurrence{
		occ("occ:1", "cert:www", "/etc/pki/tls/certs/www.crt", "", "enabled", ref),
		occ("occ:2", "key:www", "/etc/pki/tls/private/www.key", "", "enabled", ref),
		occ("occ:3", "cert:soon", "/etc/pki/tls/certs/soon.crt", "", "unknown"),
		occ("occ:4", "cert:expired", "/opt/app/old.crt", "", "unknown"),
		occ("occ:5", "key:orphan", "/opt/app/<b>old</b>.key", "", "unknown"),
		occ("occ:6", "cert:evil", "/opt/app/evil.crt", "", "unknown"),
		occ("occ:7", "cert:ca1", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "system-trust", "installed"),
		occ("occ:8", "cert:ca2", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "system-trust", "installed"),
		occ("occ:9", "cert:ca3", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "system-trust", "installed"),
	}
	inv.Services = []model.Service{
		{ID: "svc:nginx", App: "nginx", ConfigFiles: []string{"/etc/nginx/nginx.conf"}, Activity: model.Activity{Level: "enabled",
			Evidence: []model.Evidence{{Kind: "unit-enabled", Path: "/etc/systemd/system/multi-user.target.wants/nginx.service", Detail: "nginx.service"}}}},
		{ID: "svc:openssh", App: "openssh", Activity: model.Activity{Level: "enabled"}},
		{ID: "svc:httpd", App: "httpd", Activity: model.Activity{Level: "installed"}, Notes: []string{"ssl_module is not loaded by the configuration; TLS directives are not in effect"}},
	}
	inv.Settings = []model.Setting{
		{ID: "set:1", Service: "svc:nginx", Parameter: "tls.ciphers", Direction: "inbound", Scope: "server www.example.jp", Basis: "configured", Layer: "app-config",
			Source: "config-file", Values: []string{"HIGH", "!aNULL"}, Effective: true, Location: model.SettingLocation{Path: "/etc/nginx/conf.d/tls.conf", Line: 6}},
		{ID: "set:2", Service: "svc:nginx", Parameter: "tls.protocols", Direction: "inbound", Scope: "server www.example.jp", Basis: "configured", Layer: "app-config",
			Source: "config-file", Values: []string{"TLSv1", "TLSv1.2", "TLSv1.3"}, Effective: true, Location: model.SettingLocation{Path: "/etc/nginx/conf.d/tls.conf", Line: 7}},
	}
	src := &model.Provenance{Image: "redhat/ubi9@sha256:" + strings.Repeat("8", 64), OS: "Red Hat Enterprise Linux 9.9 (Plow)", Package: "openssl-libs", Version: "3.5.9-1.el9_9"}
	inv.EffectiveValues = []model.EffectiveValue{
		{ID: "eff:1", Service: "svc:nginx", Parameter: "tls.ciphers", Direction: "inbound", Scope: "server www.example.jp", Status: "resolved", Confidence: "medium",
			Values: []string{"ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256", "AES256-SHA", "DES-CBC3-SHA"},
			Notes:  []string{"the cipher table measured on openssl-libs 3.5.9-1.el9_9 is used for the installed openssl-libs 3.5.9-2.el9_9 (same upstream version and distribution, different release)"},
			Steps: []model.ResolutionStep{{Layer: "app-config", Op: "override", Setting: "set:1"}, {Layer: "library", Op: "expand", Source: src},
				{Layer: "os-policy", Op: "security-level"}, {Layer: "app-config", Op: "filter-certificates"}}},
		{ID: "eff:2", Service: "svc:nginx", Parameter: "tls.ciphersuites-tls13", Direction: "inbound", Scope: "server www.example.jp", Status: "resolved", Confidence: "high",
			Values: []string{"TLS_AES_256_GCM_SHA384"}},
		{ID: "eff:3", Service: "svc:openssh", Parameter: "ssh.kex-algorithms", Direction: "inbound", Status: "resolved", Confidence: "high",
			Values: []string{"mlkem768x25519-sha256", "curve25519-sha256", "diffie-hellman-group1-sha1"}},
		{ID: "eff:4", Service: "svc:openssh", Parameter: "ssh.macs", Direction: "inbound", Status: "unresolved",
			Reason: "no default values are recorded for openssh-server 9.9p1-99.el9"},
	}
	inv.Packages = []model.Package{{Manager: "rpm", Name: "openssl-libs", Version: "3.5.9", Release: "2.el9_9", Role: "crypto-library"}}
	inv.OSSettings = []model.OSSetting{{ID: "crypto-policies.policy", Value: "DEFAULT", Path: "/etc/crypto-policies/config", Line: 1}}
	inv.Skipped = []model.Skipped{{Path: "/mnt/share", Reason: "network-fs", Detail: "nfs4"}, {Path: "/etc/ssl/private", Reason: "permission-denied"}}
	inv.Coverage = model.Coverage{FilesExamined: 1234, DirsExamined: 56, SkippedByReason: map[string]int{"network-fs": 1, "permission-denied": 1}}
	return inv
}

func render(t *testing.T, inv *model.Inventory) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Render(&buf, inv, rules(t), "default"); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func mustContain(t *testing.T, html string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(html, p) {
			t.Errorf("the report does not contain %q", p)
		}
	}
}

// レポートは、外部の資源を一切読まない単一の HTML。スクリプトも使わない。
func TestReportIsSelfContained(t *testing.T) {
	html := render(t, sample())
	if !strings.HasPrefix(html, "<!DOCTYPE html>") || !strings.Contains(html, `<html lang="ja">`) || !strings.Contains(html, `<meta charset="utf-8">`) {
		t.Error("not a complete HTML document")
	}
	if !strings.Contains(html, `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">`) {
		t.Error("the content security policy is missing")
	}
	for _, bad := range []string{"<script", "<link", "<img", "<iframe", "<object", "<embed", "<form", " src=", "@import", "url(", "javascript:", " on"} {
		if bad == " on" {
			if regexp.MustCompile(`(?i)\son[a-z]+\s*=`).MatchString(html) {
				t.Error("the report has an inline event handler")
			}
			continue
		}
		if strings.Contains(strings.ToLower(html), bad) {
			t.Errorf("the report contains %q", bad)
		}
	}
	// リンクは、評価の根拠にした文書（https）だけ。参照元を送らない指定を付ける。
	links := regexp.MustCompile(`<a [^>]*href="([^"]*)"[^>]*>`).FindAllStringSubmatch(html, -1)
	if len(links) == 0 {
		t.Error("the references are not linked")
	}
	for _, l := range links {
		if strings.HasPrefix(l[1], "#") {
			continue // ページ内の移動
		}
		if !strings.HasPrefix(l[1], "https://") || !strings.Contains(l[0], `rel="noopener noreferrer"`) {
			t.Errorf("unexpected link %s", l[0])
		}
	}
	// 同じ入力からは同じ出力になる
	if html != render(t, sample()) {
		t.Error("the report is not deterministic")
	}
}

// 結果に含まれる文字列（証明書の Subject、ファイルのパス）は攻撃者が決められるので、必ずエスケープする。
func TestReportEscapesUntrustedText(t *testing.T) {
	html := render(t, sample())
	if strings.Contains(html, "<script>alert(1)</script>") || strings.Contains(html, "<b>old</b>") {
		t.Fatal("untrusted text is written without escaping")
	}
	mustContain(t, html, "&lt;script&gt;alert(1)&lt;/script&gt;", "/opt/app/&lt;b&gt;old&lt;/b&gt;.key")
}

func TestReportHeaderAndSummary(t *testing.T) {
	html := render(t, sample())
	mustContain(t, html, "web01.example.jp", "linux / amd64", "2026-11-12T10:00:05Z", "0.1.0", "2026.11.0", "system=portal",
		"既定の評価ポリシー", // 評価ポリシーの名前
	)
	// 未完了のスキャンは、冒頭で目立たせる
	inv := sample()
	inv.Meta.Completed, inv.Meta.Incomplete = false, "interrupted"
	mustContain(t, render(t, inv), "このスキャンは完了していません", "interrupted")
	if strings.Contains(html, "このスキャンは完了していません") {
		t.Error("a completed scan must not be flagged as incomplete")
	}
}

// サービスごとに、実際に効く値と、その求め方・判定を示す。
func TestReportServices(t *testing.T) {
	html := render(t, sample())
	mustContain(t, html,
		"nginx", "server www.example.jp", "有効", // 起動するよう設定されている
		"ECDHE-RSA-AES256-GCM-SHA384", "DES-CBC3-SHA",
		"量子計算機に弱い", "非推奨",
		"RSA による鍵輸送",                 // 当たった規則の説明（AES256-SHA）
		"確度: 中",                      // 補間
		"openssl-libs 3.5.9-1.el9_9", // 対応表を実測した版（求め方）
		"/etc/nginx/conf.d/tls.conf:6",
		"mlkem768x25519-sha256", "ハイブリッド",
		"diffie-hellman-group1-sha1", "危殆化",
		"求められませんでした", "no default values are recorded for openssh-server 9.9p1-99.el9",
		"TLSv1", // 設定に書かれたプロトコル
		"ssl_module is not loaded",
	)
	// 「導入のみ」のサービスは畳んで示す
	if !regexp.MustCompile(`(?s)<details[^>]*>\s*<summary>[^<]*httpd`).MatchString(html) {
		t.Error("a service that is only installed must be collapsed")
	}
	if regexp.MustCompile(`(?s)<details[^>]*>\s*<summary>[^<]*nginx`).MatchString(html) {
		t.Error("an enabled service must not be collapsed")
	}
}

// 証明書と鍵: 期限はスキャン時点を基準に判定する。信頼ストアの CA 証明書は畳み、署名の方式ごとにまとめる。
func TestReportCertificatesAndKeys(t *testing.T) {
	html := render(t, sample())
	mustContain(t, html,
		"CN=www.example.jp,O=Example", "/etc/pki/tls/certs/www.crt",
		"期限切れ",      // cert:expired（スキャン時点 2026-11-12 より前）
		"30 日以内に期限", // cert:soon（2026-11-20）
		"参照されていない秘密鍵", "/opt/app/",
		"system-trust", "3 件",
	)
	// 信頼ストアは畳まれていて、件数が見える。中は署名の方式ごとにまとまっている
	m := regexp.MustCompile(`(?s)<details[^>]*>\s*<summary>([^<]*system-trust[^<]*)</summary>(.*?)</details>`).FindStringSubmatch(html)
	if m == nil {
		t.Fatal("the trust store must be collapsed")
	}
	if !strings.Contains(m[1], "3 件") {
		t.Errorf("the collapsed section must show the count: %q", m[1])
	}
	if !strings.Contains(m[2], "sha256-with-rsa") || !strings.Contains(m[2], "sha1-with-rsa") || !strings.Contains(m[2], "Root CA Two") {
		t.Errorf("the trust store must be grouped by signature algorithm: %q", m[2])
	}
	// 畳んだ部分は、最初は閉じている
	if regexp.MustCompile(`<details[^>]*\sopen`).MatchString(html) {
		t.Error("collapsed sections must be closed initially")
	}
}

// 調べられなかった範囲と、このレポートでは分からないことを必ず示す。
func TestReportCoverageAndLimits(t *testing.T) {
	html := render(t, sample())
	mustContain(t, html, "調べられなかった範囲", "/mnt/share", "network-fs", "nfs4", "permission-denied", "1234",
		"このレポートでは分からないこと", "実際にネゴシエーションされている暗号",
		"判定の基準と出典", "NIST IR 8547", "https://doi.org/10.6028/NIST.IR.8547", "CRYPTREC")
}

// 評価は、レポートを作る時点の評価ポリシーでやり直す（結果ファイルの中の判定は使わない）。
func TestReportReassesses(t *testing.T) {
	inv := sample()
	inv.Assessment = &model.Assessment{Policy: "stale", PolicyVersion: "0", Assets: map[string]model.Verdict{}, Values: map[string]model.Verdict{}}
	html := render(t, inv)
	mustContain(t, html, "量子計算機に弱い")
	if strings.Contains(html, "stale") {
		t.Error("the stale assessment in the result file must not be used")
	}
	var buf bytes.Buffer
	if err := Render(&buf, sample(), rules(t), "nosuch"); err == nil {
		t.Error("an unknown policy must be an error")
	}
}

// 何も見つからなかった結果でも、レポートは作れる。
func TestReportEmptyInventory(t *testing.T) {
	inv := &model.Inventory{Schema: model.Schema}
	inv.Meta.Host.Hostname = "empty01"
	inv.Meta.Completed = true
	html := render(t, inv)
	mustContain(t, html, "empty01", "サービスは見つかりませんでした")
}
