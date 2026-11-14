package opensslcnf

import (
	"errors"
	"io/fs"
	"sort"
	"strings"
	"testing"
)

// mapFS はテスト用のファイル群。中身が unreadable のファイルは、存在するが読めない。
const unreadable = "\x00unreadable"

type mapFS map[string]string

func (m mapFS) ReadFile(p string) ([]byte, error) {
	if s, ok := m[p]; ok {
		if s == unreadable {
			return nil, errors.New("permission denied")
		}
		return []byte(s), nil
	}
	return nil, fs.ErrNotExist
}

func (m mapFS) ListDir(dir string) ([]string, error) {
	var out []string
	for p := range m {
		if strings.HasPrefix(p, dir+"/") && !strings.Contains(p[len(dir)+1:], "/") {
			out = append(out, p)
		}
	}
	if out == nil {
		return nil, errors.New("not a directory")
	}
	sort.Strings(out)
	return out, nil
}

func values(r *Result) map[string]string {
	m := map[string]string{}
	for _, e := range r.SystemDefault {
		m[e.Key] = e.Value
	}
	return m
}

// RHEL 8.10 の実物の形: openssl_conf → ssl_conf → system_default → .include（= なし）
func TestRHEL8Chain(t *testing.T) {
	m := mapFS{
		"/etc/pki/tls/openssl.cnf":                         "# Load default TLS policy configuration\n\nopenssl_conf = default_modules\n\n[ default_modules ]\n\nssl_conf = ssl_module\n\n[ ssl_module ]\n\nsystem_default = crypto_policy\n\n[ crypto_policy ]\n\n.include /etc/crypto-policies/back-ends/opensslcnf.config\n\n[ new_oids ]\ntsa_policy1 = 1.2.3.4.1\n",
		"/etc/crypto-policies/back-ends/opensslcnf.config": "CipherString = @SECLEVEL=2:kEECDH:kRSA\nCiphersuites = TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256\nTLS.MinProtocol = TLSv1.2\nTLS.MaxProtocol = TLSv1.3\n",
	}
	r, err := SystemDefault("/etc/pki/tls/openssl.cnf", m)
	if err != nil {
		t.Fatal(err)
	}
	v := values(r)
	if v["CipherString"] != "@SECLEVEL=2:kEECDH:kRSA" || v["TLS.MinProtocol"] != "TLSv1.2" || v["TLS.MaxProtocol"] != "TLSv1.3" || len(v) != 4 {
		t.Errorf("system default = %v", v)
	}
	if len(r.Problems) != 0 {
		t.Errorf("problems = %v", r.Problems)
	}
	// 値がどのファイルの何行目にあったかが分かる
	for _, e := range r.SystemDefault {
		if e.Key == "TLS.MinProtocol" && (e.File != "/etc/crypto-policies/back-ends/opensslcnf.config" || e.Line != 3) {
			t.Errorf("location of TLS.MinProtocol = %s:%d", e.File, e.Line)
		}
	}
	if strings.Join(r.Sections, ">") != "default_modules>ssl_module>crypto_policy" {
		t.Errorf("sections followed = %v", r.Sections)
	}
}

// RHEL 9.9 の実物の形: ".include = パス" と、ディレクトリの .include
func TestRHEL9Chain(t *testing.T) {
	m := mapFS{
		"/etc/pki/tls/openssl.cnf":                         "HOME = .\nopenssl_conf = openssl_init\n[openssl_init]\nproviders = provider_sect\nssl_conf = ssl_module\n[provider_sect]\ndefault = default_sect\n[default_sect]\nactivate = 1\n.include /etc/pki/tls/openssl.d\n[ ssl_module ]\nsystem_default = crypto_policy\n[ crypto_policy ]\n.include = /etc/crypto-policies/back-ends/opensslcnf.config\n",
		"/etc/crypto-policies/back-ends/opensslcnf.config": "CipherString = @SECLEVEL=2:kEECDH\nGroups = *X25519:secp256r1\n",
		"/etc/pki/tls/openssl.d/10-extra.cnf":              "[ crypto_policy ]\nMinProtocol = TLSv1.3\n",
		"/etc/pki/tls/openssl.d/README":                    "not a config file\n",
	}
	r, err := SystemDefault("/etc/pki/tls/openssl.cnf", m)
	if err != nil {
		t.Fatal(err)
	}
	v := values(r)
	if v["CipherString"] != "@SECLEVEL=2:kEECDH" || v["Groups"] != "*X25519:secp256r1" || v["MinProtocol"] != "TLSv1.3" {
		t.Errorf("system default = %v", v)
	}
}

// Ubuntu の実物の形: システム既定の TLS 設定を読み込む経路がない
func TestNoSystemDefault(t *testing.T) {
	for name, cnf := range map[string]string{
		"ubuntu 24.04": "HOME = .\nopenssl_conf = openssl_init\n[openssl_init]\nproviders = provider_sect\n[provider_sect]\ndefault = default_sect\n[default_sect]\n",
		"ubuntu 16.04": "HOME = .\nRANDFILE = $ENV::HOME/.rnd\noid_section = new_oids\n[ new_oids ]\n",
		"empty":        "",
	} {
		r, err := SystemDefault("/etc/ssl/openssl.cnf", mapFS{"/etc/ssl/openssl.cnf": cnf})
		if err != nil || len(r.SystemDefault) != 0 || len(r.Problems) != 0 {
			t.Errorf("%s: %+v err=%v", name, r, err)
		}
	}
}

func TestSyntaxDetails(t *testing.T) {
	m := mapFS{"/o.cnf": "openssl_conf=init # trailing comment\n[init]\nssl_conf = ssl\n[ssl]\nsystem_default = sd\n[ sd ]\n" +
		"CipherString = HIGH:\\\n!aNULL   \n# comment\n; also a comment\nMinProtocol = TLSv1\nMinProtocol = TLSv1.2\nOptions = \"quoted value\"\n"}
	r, err := SystemDefault("/o.cnf", m)
	if err != nil {
		t.Fatal(err)
	}
	v := values(r)
	if v["CipherString"] != "HIGH:!aNULL" { // 行末の \ は次の行へ続く
		t.Errorf("continuation: %q", v["CipherString"])
	}
	if v["MinProtocol"] != "TLSv1.2" { // 同じキーは後の値が有効
		t.Errorf("override: %q", v["MinProtocol"])
	}
	if v["Options"] != "quoted value" {
		t.Errorf("quotes: %q", v["Options"])
	}
}

func TestProblemsAreReported(t *testing.T) {
	base := "openssl_conf = a\n[a]\nssl_conf = b\n[b]\nsystem_default = c\n[c]\n"
	cases := map[string]mapFS{
		"unreadable include": {"/o.cnf": base + ".include /secret.cnf\nMinProtocol = TLSv1.2\n", "/secret.cnf": unreadable},
		"relative include":   {"/o.cnf": base + ".include extra.cnf\n"},
		"include loop":       {"/o.cnf": base + ".include /o.cnf\n"},
		"missing section":    {"/o.cnf": "openssl_conf = a\n[a]\nssl_conf = nowhere\n"},
		"variable":           {"/o.cnf": base + "CipherString = $ENV::CIPHERS\n"},
	}
	for name, m := range cases {
		r, err := SystemDefault("/o.cnf", m)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if len(r.Problems) == 0 {
			t.Errorf("%s: no problem reported: %+v", name, r)
		}
	}
	// 存在しないファイルやディレクトリの .include は、問題にしない。OpenSSL 自身が無視する（1.1.1k、3.0.13、3.5.5 で確かめた）。
	// Ubuntu 26.04 の既定の openssl.cnf は、存在しないディレクトリを .include している
	for _, target := range []string{"/nope.cnf", "/etc/ssl/openssl.conf.d"} {
		r, err := SystemDefault("/o.cnf", mapFS{"/o.cnf": base + ".include " + target + "\nMinProtocol = TLSv1.2\n"})
		if err != nil || len(r.Problems) != 0 || values(r)["MinProtocol"] != "TLSv1.2" {
			t.Errorf("missing include %s: err=%v problems=%v values=%v", target, err, r.Problems, values(r))
		}
	}
	// 読めるところまでは読む
	r, _ := SystemDefault("/o.cnf", cases["unreadable include"])
	if values(r)["MinProtocol"] != "TLSv1.2" {
		t.Errorf("values after a missing include must still be read: %+v", r)
	}
	// 変数を含む値は、値としては採らない（展開しないため正しい値が分からない）
	r, _ = SystemDefault("/o.cnf", cases["variable"])
	if _, ok := values(r)["CipherString"]; ok {
		t.Error("a value containing a variable must not be reported as is")
	}
	if _, err := SystemDefault("/missing.cnf", mapFS{}); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing main file: err = %v", err)
	}
}

func FuzzSystemDefault(f *testing.F) {
	f.Add("openssl_conf = a\n[a]\nssl_conf = b\n[b]\nsystem_default = c\n[c]\n.include /x\nK = v\\\n")
	f.Fuzz(func(t *testing.T, s string) {
		SystemDefault("/o.cnf", mapFS{"/o.cnf": s, "/x": s})
	})
}
