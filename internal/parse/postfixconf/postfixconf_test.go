package postfixconf

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// testdata の main.cf / master.cf は、検証ラボで作った見本（書き方を確かめるためのもの）。
// 期待値は、同じファイルを Postfix 自身（postconf。3.1.0、3.5.25、3.10.13 で同じ結果）に読ませたときの出力。

func load(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// last は、項目ごとの最後の記載（Postfix は、後に書かれたものを使う）。
func last(params []Param) map[string]Param {
	m := map[string]Param{}
	for _, p := range params {
		m[p.Name] = p
	}
	return m
}

// 「postconf -h 名前」の出力（展開する前の値）と同じ値を読める。
func TestParseMain(t *testing.T) {
	params, problems := ParseMain("/etc/postfix/main.cf", load(t, "main.cf"))
	if len(problems) != 0 {
		t.Errorf("problems = %v", problems)
	}
	got := last(params)
	for name, want := range map[string]string{
		"smtpd_tls_security_level":            "may",
		"smtpd_tls_cert_file":                 "/etc/lab/rsa.crt",
		"smtpd_tls_key_file":                  "${smtpd_tls_cert_file}.key",
		"smtpd_tls_eccert_file":               "$(config_directory)/ec.crt",
		"smtpd_tls_ciphers":                   "high",                 // 前後の空白は値に含まれない
		"smtpd_tls_exclude_ciphers":           "aNULL, MD5, DES 3DES", // 継続行。途中のコメント行は読み飛ばす
		"smtpd_tls_mandatory_ciphers":         "$smtpd_tls_ciphers",
		"smtpd_tls_mandatory_exclude_ciphers": "${smtpd_tls_exclude_ciphers} kRSA",
		"tls_high_cipherlist":                 "HIGH:!aNULL:!kRSA", // 同じ項目は、後に書かれたものが効く
		"smtpd_tls_dh1024_param_file":         "${config_directory}/dh.pem",
		"smtpd_tls_protocols":                 "!SSLv2, !SSLv3, !TLSv1",
		"tls_eecdh_auto_curves":               "${undefined_name_here}X25519 prime256v1",
		"smtpd_tls_loglevel":                  "${smtpd_tls_ask_ccert?2}${smtpd_tls_req_ccert:1}",
		"smtpd_tls_CAfile":                    "$$literal",
		"myhostname":                          "lab.test",
	} {
		if got[name].Value != want {
			t.Errorf("%s = %q, want %q", name, got[name].Value, want)
		}
	}
	// 場所（ファイルと、記載が始まる行）
	if p := got["smtpd_tls_exclude_ciphers"]; p.File != "/etc/postfix/main.cf" || p.Line != 6 {
		t.Errorf("location = %s:%d", p.File, p.Line)
	}
	if p := got["tls_high_cipherlist"]; p.Line != 14 {
		t.Errorf("the later entry must win: line %d", p.Line)
	}
	// 同じ項目の記載は、すべて順に返す（効かない記載も記録できるように）
	n := 0
	for _, p := range params {
		if p.Name == "tls_high_cipherlist" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("tls_high_cipherlist appears %d times", n)
	}
}

// 「postconf -M」「postconf -P」の出力と同じように、サービスと、サービスごとの上書き（-o）を読める。
func TestParseMaster(t *testing.T) {
	services, problems := ParseMaster("/etc/postfix/master.cf", load(t, "master.cf"))
	if len(problems) != 0 {
		t.Errorf("problems = %v", problems)
	}
	by := map[string]Service{}
	var order []string
	for _, s := range services {
		key := s.Name + "/" + s.Type
		by[key] = s
		order = append(order, key+"="+s.Command)
	}
	want := "smtp/inet=smtpd pickup/unix=pickup relay/unix=smtp 127.0.0.1:8587/inet=smtpd 8465/inet=smtpd lab-unix/unix=smtpd [::1]:8525/inet=postscreen 127.0.0.1:8588/inet=smtpd"
	if strings.Join(order, " ") != want {
		t.Errorf("services = %v", order)
	}
	overrides := func(key string) string {
		var out []string
		for _, o := range by[key].Overrides {
			out = append(out, o.Name+"="+o.Value)
		}
		return strings.Join(out, " | ")
	}
	// -o は、行を分けても、同じ行に続けてもよい。途中のコメント行は読み飛ばす。同じ項目は、後に書かれたものが効く（記載はすべて返す）
	if got := overrides("127.0.0.1:8587/inet"); got != "smtpd_tls_security_level=encrypt | smtpd_tls_mandatory_ciphers=high | smtpd_tls_wrappermode=no | smtpd_tls_security_level=may" {
		t.Errorf("8587 overrides = %s", got)
	}
	if got := overrides("8465/inet"); got != "smtpd_tls_wrappermode=yes | smtpd_tls_exclude_ciphers=$tls_null_cipherlist" {
		t.Errorf("8465 overrides = %s", got)
	}
	// 波括弧で囲む書き方: 中の空白を含む値を書ける。「=」の前後の空白は値に含まれない
	if got := overrides("127.0.0.1:8588/inet"); got != "smtpd_tls_exclude_ciphers=aNULL, MD5 | smtpd_tls_ciphers=high" {
		t.Errorf("8588 overrides = %s", got)
	}
	if got := overrides("relay/unix"); got != "syslog_name=postfix/$service_name" {
		t.Errorf("relay overrides = %s", got)
	}
	if s := by["127.0.0.1:8587/inet"]; s.File != "/etc/postfix/master.cf" || s.Line != 6 || len(s.Overrides) != 4 || s.Overrides[3].Line != 10 {
		t.Errorf("location = %+v", s)
	}
}

// 「postconf -hx 名前」の出力（展開した後の値）と同じ値になる。
func TestExpand(t *testing.T) {
	params, _ := ParseMain("/etc/postfix/main.cf", load(t, "main.cf"))
	conf := last(params)
	// 既定値を持つ項目（実物の既定値）。設定にも既定にもない名前は、空になる（Postfix は警告を出すだけ）
	defaults := map[string]string{"config_directory": "/etc/postfix", "smtpd_tls_ask_ccert": "no", "smtpd_tls_req_ccert": "no"}
	lookup := func(name string) (string, bool) {
		if p, ok := conf[name]; ok {
			return p.Value, true
		}
		v, ok := defaults[name]
		return v, ok
	}
	for name, want := range map[string]string{
		"smtpd_tls_key_file":                  "/etc/lab/rsa.crt.key",
		"smtpd_tls_eccert_file":               "/etc/postfix/ec.crt",
		"smtpd_tls_mandatory_ciphers":         "high",
		"smtpd_tls_mandatory_exclude_ciphers": "aNULL, MD5, DES 3DES kRSA",
		"smtpd_tls_dh1024_param_file":         "/etc/postfix/dh.pem",
		"smtpd_tls_CAfile":                    "$literal",
		"smtpd_tls_protocols":                 "!SSLv2, !SSLv3, !TLSv1",
	} {
		got, err := Expand(conf[name].Value, lookup)
		if err != nil || got != want {
			t.Errorf("%s = %q (%v), want %q", name, got, err, want)
		}
	}
	// 設定にも既定にもない名前: どう扱うかは呼び出し側が決められるよう、エラーにして名前を伝える
	if _, err := Expand(conf["tls_eecdh_auto_curves"].Value, lookup); !errors.Is(err, ErrUnknownName) || !strings.Contains(err.Error(), "undefined_name_here") {
		t.Errorf("unknown name: %v", err)
	}
	// 条件つきの書き方（${名前?値}、${名前:値}）は展開しない
	if _, err := Expand(conf["smtpd_tls_loglevel"].Value, lookup); !errors.Is(err, ErrUnsupported) {
		t.Errorf("conditional form: %v", err)
	}
	// 循環する参照（Postfix は「unreasonable macro call nesting」で停止する）
	loop := map[string]string{"a": "$b", "b": "x${a}"}
	if _, err := Expand("$a", func(n string) (string, bool) { v, ok := loop[n]; return v, ok }); !errors.Is(err, ErrLoop) {
		t.Errorf("loop: %v", err)
	}
}

// 壊れた入力や、極端に大きな入力でも、止まらずに問題として報告する。
func TestMalformed(t *testing.T) {
	params, problems := ParseMain("main.cf", []byte("  leading continuation\nno_equals_sign\n= no name\nok = 1\nbad name = 2\n"))
	if len(params) != 1 || params[0].Name != "ok" || len(problems) == 0 {
		t.Errorf("params = %+v problems = %v", params, problems)
	}
	services, problems := ParseMaster("master.cf", []byte("too few fields\nsmtp inet n - n - - smtpd -o\nx inet n - n - - smtpd -o {unterminated\ny inet n - n - - smtpd -o novalue\n"))
	if len(problems) < 3 {
		t.Errorf("services = %+v problems = %v", services, problems)
	}
	big := strings.Repeat("a = "+strings.Repeat("x", 100)+"\n", 200000)
	if _, problems := ParseMain("main.cf", []byte(big)); len(problems) == 0 {
		t.Error("an oversized file must be reported")
	}
	if _, err := Expand(strings.Repeat("$", 1<<20), func(string) (string, bool) { return "", true }); err == nil {
		t.Error("an oversized value must be an error")
	}
}
