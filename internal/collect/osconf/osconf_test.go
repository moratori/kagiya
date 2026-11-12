//go:build unix

package osconf

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kagiya/internal/inventory"
	"kagiya/internal/logx"
	"kagiya/internal/model"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

// tree はテストデータのディレクトリを一時ディレクトリに写し、そこを起点として収集する。
func collect(t *testing.T, name string, prepare func(prefix string)) (string, *model.Inventory) {
	t.Helper()
	prefix, _ := filepath.EvalSymlinks(t.TempDir())
	if name != "" {
		src := filepath.Join("testdata", name)
		filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
			rel, _ := filepath.Rel(src, p)
			if d.IsDir() {
				return os.MkdirAll(filepath.Join(prefix, rel), 0o755)
			}
			b, _ := os.ReadFile(p)
			return os.WriteFile(filepath.Join(prefix, rel), b, 0o644)
		})
	}
	if prepare != nil {
		prepare(prefix)
	}
	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	b := inventory.NewBuilder(rs, logx.New(io.Discard, time.Now))
	(&Collector{Prefix: prefix, Opener: &safefs.Opener{OnSkip: b.Skip}, Builder: b, Rules: rs}).Collect()
	return prefix, b.Inventory()
}

func settings(inv *model.Inventory) map[string]model.OSSetting {
	m := map[string]model.OSSetting{}
	for _, s := range inv.OSSettings {
		m[s.ID] = s
	}
	return m
}

func TestRHEL8(t *testing.T) {
	prefix, inv := collect(t, "rhel8", func(p string) {
		os.MkdirAll(p+"/proc/sys/crypto", 0o755)
		os.WriteFile(p+"/proc/sys/crypto/fips_enabled", []byte("0\n"), 0o644)
	})
	s := settings(inv)
	if len(inv.Skipped) != 0 {
		t.Errorf("skipped = %+v", inv.Skipped)
	}
	if v := s["crypto-policies.policy"]; v.Value != "DEFAULT" || v.Path != prefix+"/etc/crypto-policies/config" || v.Line != 1 {
		t.Errorf("policy = %+v", v)
	}
	if v := s["crypto-policies.applied"]; v.Value != "DEFAULT" {
		t.Errorf("applied = %+v", v)
	}
	if v := s["kernel.fips_enabled"]; v.Value != "0" {
		t.Errorf("fips = %+v", v)
	}
	if v := s["openssl.config_file"]; v.Value != prefix+"/etc/pki/tls/openssl.cnf" {
		t.Errorf("config file = %+v", v)
	}
	// 実物（RHEL 8.10 の DEFAULT ポリシー）の値
	if v := s["openssl.system_default.TLS.MinProtocol"]; v.Value != "TLSv1.2" || v.Path != prefix+"/etc/crypto-policies/back-ends/opensslcnf.config" || v.Line != 3 {
		t.Errorf("TLS.MinProtocol = %+v", v)
	}
	if v := s["openssl.system_default.CipherString"]; !strings.HasPrefix(v.Value, "@SECLEVEL=2:kEECDH:kRSA:kEDH:") || !strings.HasSuffix(v.Value, ":-AESCCM8") {
		t.Errorf("CipherString = %+v", v)
	}
	if v := s["openssl.system_default.Ciphersuites"]; v.Value != "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_SHA256" {
		t.Errorf("Ciphersuites = %+v", v)
	}
	if _, ok := s["openssl.system_default.Groups"]; ok {
		t.Error("RHEL 8.10 の DEFAULT ポリシーには Groups の指定がない")
	}
}

func TestRHEL9(t *testing.T) {
	prefix, inv := collect(t, "rhel9", nil)
	s := settings(inv)
	if s["crypto-policies.policy"].Value != "DEFAULT" {
		t.Errorf("policy = %+v", s["crypto-policies.policy"])
	}
	if v := s["openssl.system_default.Groups"]; v.Value != "*X25519:secp256r1:X448:secp521r1:secp384r1:ffdhe2048:ffdhe3072:ffdhe4096:ffdhe6144:ffdhe8192" {
		t.Errorf("Groups = %+v", v)
	}
	if v := s["openssl.system_default.TLS.MaxProtocol"]; v.Value != "TLSv1.3" || !strings.HasPrefix(v.Path, prefix) {
		t.Errorf("TLS.MaxProtocol = %+v", v)
	}
	// .include で指されたディレクトリ（/etc/pki/tls/openssl.d）が空でも問題にしない
	if len(inv.Skipped) != 0 {
		t.Errorf("skipped = %+v", inv.Skipped)
	}
}

// 実物と同じく、back-ends のファイルがシンボリックリンクでも読める。
func TestBackEndSymlink(t *testing.T) {
	_, inv := collect(t, "rhel9", func(p string) {
		real := p + "/usr/share/crypto-policies/DEFAULT/opensslcnf.txt"
		os.MkdirAll(filepath.Dir(real), 0o755)
		os.Rename(p+"/etc/crypto-policies/back-ends/opensslcnf.config", real)
		os.Symlink("../../../usr/share/crypto-policies/DEFAULT/opensslcnf.txt", p+"/etc/crypto-policies/back-ends/opensslcnf.config")
	})
	if v := settings(inv)["openssl.system_default.TLS.MinProtocol"]; v.Value != "TLSv1.2" {
		t.Errorf("TLS.MinProtocol via symlink = %+v", v)
	}
}

// Ubuntu: 暗号ポリシーの仕組みも、OpenSSL のシステム既定の TLS 設定もない。「ない」ことが分かるように記録する。
func TestUbuntu(t *testing.T) {
	for _, name := range []string{"ubuntu2404", "ubuntu1604"} {
		prefix, inv := collect(t, name, nil)
		s := settings(inv)
		if _, ok := s["crypto-policies.policy"]; ok {
			t.Errorf("%s: crypto-policies must be absent", name)
		}
		if v := s["openssl.config_file"]; v.Value != prefix+"/etc/ssl/openssl.cnf" {
			t.Errorf("%s: config file = %+v", name, v)
		}
		for id := range s {
			if strings.HasPrefix(id, "openssl.system_default.") {
				t.Errorf("%s: unexpected %s", name, id)
			}
		}
		if v := s["openssl.system_default"]; v.Value != "not-configured" {
			t.Errorf("%s: openssl.system_default = %+v", name, v)
		}
	}
}

func TestNothingPresent(t *testing.T) {
	_, inv := collect(t, "", nil)
	if len(inv.OSSettings) != 0 || len(inv.Skipped) != 0 {
		t.Errorf("inv = %+v", inv)
	}
}

// 設定値として妥当でない文字を含む値は出力しない（設定ファイルに紛れた秘密が出力に写るのを防ぐ）。
func TestSuspiciousValuesAreNotEmitted(t *testing.T) {
	_, inv := collect(t, "rhel8", func(p string) {
		os.WriteFile(p+"/etc/crypto-policies/config", []byte("DEFAULT; rm -rf /\n"), 0o644)
		f, _ := os.OpenFile(p+"/etc/crypto-policies/back-ends/opensslcnf.config", os.O_APPEND|os.O_WRONLY, 0)
		f.WriteString("Password = hunter2{secret}\nOptions = <script>\n")
		f.Close()
	})
	s := settings(inv)
	if _, ok := s["crypto-policies.policy"]; ok {
		t.Errorf("malformed policy name emitted: %+v", s["crypto-policies.policy"])
	}
	for id, v := range s {
		if strings.Contains(v.Value, "hunter2") || strings.Contains(v.Value, "<script>") {
			t.Errorf("%s leaked %q", id, v.Value)
		}
	}
	if len(inv.Skipped) == 0 {
		t.Error("rejected values must be reported")
	}
}
