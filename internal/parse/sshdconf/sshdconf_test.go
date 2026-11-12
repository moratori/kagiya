package sshdconf

import (
	"io/fs"
	"path"
	"sort"
	"strings"
	"testing"
)

type mapFS map[string]string

func (m mapFS) ReadFile(p string) ([]byte, error) {
	if s, ok := m[p]; ok {
		return []byte(s), nil
	}
	return nil, fs.ErrNotExist
}

func (m mapFS) Glob(pattern string) ([]string, error) {
	var out []string
	for p := range m {
		if ok, _ := path.Match(pattern, p); ok {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

func TestParseDirectivesAndIncludes(t *testing.T) {
	m := mapFS{
		"/etc/ssh/sshd_config":                                "# comment\nInclude /etc/ssh/sshd_config.d/*.conf\n\nCiphers aes256-ctr,aes128-ctr\n  macs   hmac-sha2-256  # trailing\nHostKey=/etc/ssh/ssh_host_ed25519_key\nKexAlgorithms \"curve25519-sha256\"\nMatch User bob Address 10.0.0.0/8\n  Ciphers 3des-cbc\nMatch all\nPasswordAuthentication no\n",
		"/etc/ssh/sshd_config.d/50-redhat.conf":               "Include /etc/crypto-policies/back-ends/opensshserver.config\nX11Forwarding yes\n",
		"/etc/ssh/sshd_config.d/10-first.conf":                "RequiredRSASize 3072\n",
		"/etc/ssh/sshd_config.d/ignored.txt":                  "Ciphers none\n",
		"/etc/crypto-policies/back-ends/opensshserver.config": "Ciphers aes256-gcm@openssh.com\n",
	}
	ds, problems := Parse("/etc/ssh/sshd_config", m)
	if len(problems) != 0 {
		t.Errorf("problems = %v", problems)
	}
	var got []string
	for _, d := range ds {
		got = append(got, d.Keyword+"|"+d.Args+"|"+path.Base(d.File)+":"+itoa(d.Line)+"|"+d.Match)
	}
	want := []string{
		// 取り込まれたファイルは、Include のあった位置に、名前順で入る
		"requiredrsasize|3072|10-first.conf:1|",
		"ciphers|aes256-gcm@openssh.com|opensshserver.config:1|",
		"x11forwarding|yes|50-redhat.conf:2|",
		"ciphers|aes256-ctr,aes128-ctr|sshd_config:4|",
		"macs|hmac-sha2-256|sshd_config:5|",                    // キーワードは大文字小文字を区別しない。行末のコメントは除く
		"hostkey|/etc/ssh/ssh_host_ed25519_key|sshd_config:6|", // "キーワード=値" の形
		"kexalgorithms|curve25519-sha256|sshd_config:7|",       // 引用符
		"ciphers|3des-cbc|sshd_config:9|User bob Address 10.0.0.0/8",
		"passwordauthentication|no|sshd_config:11|", // "Match all" の後は全体に戻る
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("directives:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

func TestParseProblems(t *testing.T) {
	// 取り込み先が存在しないのは問題ではない（sshd も無視する）。循環や深すぎる入れ子は打ち切る。
	ds, problems := Parse("/a", mapFS{"/a": "Include /nope/*.conf\nInclude /a\nCiphers x\n"})
	if len(ds) != 1 || len(problems) != 1 {
		t.Errorf("ds=%v problems=%v", ds, problems)
	}
	// 相対パスの Include は設定ファイルのあるディレクトリが基準
	ds, _ = Parse("/etc/ssh/sshd_config", mapFS{"/etc/ssh/sshd_config": "Include extra.conf\n", "/etc/ssh/extra.conf": "MACs a\n"})
	if len(ds) != 1 || ds[0].Keyword != "macs" {
		t.Errorf("relative include: %v", ds)
	}
	if ds, problems := Parse("/missing", mapFS{}); ds != nil || len(problems) != 1 {
		t.Errorf("missing main file: %v %v", ds, problems)
	}
}

func FuzzParse(f *testing.F) {
	f.Add("Include /b\nMatch User x\nCiphers a,b\n")
	f.Fuzz(func(t *testing.T, s string) { Parse("/a", mapFS{"/a": s, "/b": s}) })
}
