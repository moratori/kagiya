package ruleset

import (
	"strings"
	"testing"
)

// ルールの出典には、開発者がその事実をどう調べたか（method）と、数え上げで裏付けたか（verified-by-handshake）を書く
// （docs/confidence.md の 5.4 節）。項目によって違う場合は、items に、その項目の分を書く。
func TestSourceEvidence(t *testing.T) {
	const text = `
image: "ubuntu@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5"
os: "Ubuntu 24.04.5 LTS"
note: "x"
method: reported-by-software
verified-by-handshake: true
items:
  tls.cipherlist.export: { method: reported-by-software, verified-by-handshake: false }
  tls.dhe-without-params: { method: enumerated-by-handshake, verified-by-handshake: true }
`
	var s Source
	if err := decodeStrict([]byte(text), &s); err != nil {
		t.Fatal(err)
	}
	if err := checkSources([]Source{s}); err != nil {
		t.Fatalf("a valid source is rejected: %v", err)
	}
	if e := s.EvidenceFor("tls.ciphers"); e.Method != MethodReportedBySoftware || !e.Verified() {
		t.Errorf("default evidence = %+v", e)
	}
	if e := s.EvidenceFor("tls.cipherlist.export"); e.Method != MethodReportedBySoftware || e.Verified() {
		t.Errorf("item evidence = %+v", e)
	}
	if e := s.EvidenceFor("tls.dhe-without-params"); e.Method != MethodEnumeratedByHandshake || !e.Verified() {
		t.Errorf("item evidence = %+v", e)
	}
	// 何も書かれていない出典は、裏付けがないものとして扱う（裏付けありとは、決して扱わない）
	if e := (Source{}).EvidenceFor("x"); e.Verified() {
		t.Error("a source without evidence is treated as verified")
	}
}

func TestSourceEvidenceValidation(t *testing.T) {
	base := "image: \"ubuntu@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5\"\nos: \"Ubuntu 24.04.5 LTS\"\n"
	for _, m := range []string{"enumerated-by-handshake", "reported-by-software", "read-from-distributed-files", "read-from-upstream-source-code", "read-from-upstream-documentation"} {
		verified := "false"
		if m == "enumerated-by-handshake" {
			verified = "true"
		}
		var s Source
		if err := decodeStrict([]byte(base+"method: "+m+"\nverified-by-handshake: "+verified+"\n"), &s); err != nil {
			t.Fatal(err)
		}
		if err := checkSources([]Source{s}); err != nil {
			t.Errorf("%s: rejected: %v", m, err)
		}
	}
	for name, extra := range map[string]string{
		"an unknown method":                    "method: data\nverified-by-handshake: true\n",
		"a method without the verification":    "method: reported-by-software\n",
		"the verification without a method":    "verified-by-handshake: true\n",
		"enumeration that is not verified":     "method: enumerated-by-handshake\nverified-by-handshake: false\n",
		"an item with an unknown method":       "method: reported-by-software\nverified-by-handshake: true\nitems:\n  a.b: { method: guessed, verified-by-handshake: true }\n",
		"an item without the verification":     "method: reported-by-software\nverified-by-handshake: true\nitems:\n  a.b: { method: reported-by-software }\n",
		"an item with a bad name":              "method: reported-by-software\nverified-by-handshake: true\nitems:\n  \"a b\": { method: reported-by-software, verified-by-handshake: false }\n",
		"items without evidence of the source": "items:\n  a.b: { method: reported-by-software, verified-by-handshake: false }\n",
	} {
		var s Source
		if err := decodeStrict([]byte(base+extra), &s); err != nil {
			continue // 読み込みの時点で拒否されてもよい
		}
		if err := checkSources([]Source{s}); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

// 内蔵のルールは、すべての出典に、調べた方法と、裏付けの有無が書かれている（書かれていないルールは、不合格）。
func TestBuiltinSourcesHaveEvidence(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	missing := map[string]int{}
	total := 0
	for _, s := range rs.AllSources() {
		total++
		if s.Source.Method == "" || s.Source.VerifiedByHandshake == nil {
			missing[s.Where]++
		}
	}
	if total < 243 { // いまのルールの出典の数（ルールのファイルの image: の行を数えて確かめた）。足したら増える
		t.Errorf("only %d sources are listed; the list is not complete", total)
	}
	if len(missing) > 0 {
		var where []string
		for w, n := range missing {
			where = append(where, w+" ("+itoa(n)+")")
		}
		t.Errorf("sources without method / verified-by-handshake: %s", strings.Join(where, ", "))
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
