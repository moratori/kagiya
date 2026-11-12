package tlsciphers

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"kagiya/internal/ruleset"
)

func table(t *testing.T, pkg, version string) *ruleset.CipherTable {
	t.Helper()
	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	tb, _, exact, ok := rs.CipherTableFor("openssl", pkg, version)
	if !ok || !exact {
		t.Fatalf("no cipher table for %s %s", pkg, version)
	}
	return tb
}

func digest(names []string) string {
	if len(names) == 0 {
		return "-"
	}
	h := sha256.Sum256([]byte(strings.Join(names, ":")))
	return hex.EncodeToString(h[:])[:16]
}

func head(names []string) string {
	if len(names) == 0 {
		return "-"
	}
	if len(names) > 3 {
		names = names[:3]
	}
	return strings.Join(names, ",")
}

// 実物（各パッケージ版の openssl 自身）が展開した結果と、すべて一致する。
// 正解データは検証ラボで採取したもの（testdata/corpus.tsv）。
func TestExpandMatchesRealOpenSSL(t *testing.T) {
	data, err := os.ReadFile("testdata/corpus.tsv")
	if err != nil {
		t.Fatal(err)
	}
	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	profiles := map[string]string{}
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if f[0] == "profile" {
			if len(f) != 4 {
				t.Fatalf("bad profile line: %q", line)
			}
			profiles[f[1]+"\x00"+f[2]] = f[3]
			continue
		}
		if len(f) != 9 {
			t.Fatalf("bad vector line: %q", line)
		}
		pkg, version, rule, status, count, sum, first, scount, ssum := f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8]
		tb, _, exact, ok := rs.CipherTableFor("openssl", pkg, version)
		if !ok || !exact {
			t.Fatalf("no cipher table for %s %s", pkg, version)
		}
		n++
		var profile *string
		if p, ok := profiles[pkg+"\x00"+version]; ok {
			profile = &p
		}
		name := pkg + " " + version + " [" + rule + "]"
		x, err := Expand(tb, rule, profile)
		if status == "error" {
			if err == nil {
				t.Errorf("%s: real OpenSSL rejects this string, but Expand returned %d suites", name, len(x.Suites))
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		all := append(append([]string{}, DefaultTLS13(tb)...), x.Suites...)
		if strconv.Itoa(len(all)) != count || digest(all) != sum || head(all) != first {
			t.Errorf("%s: got %d suites (%s; %s), real OpenSSL gives %s (%s; %s)", name, len(all), digest(all), head(all), count, sum, first)
			continue
		}
		if scount == "-" {
			if _, ok := Usable(tb, all, x.Level); ok {
				t.Errorf("%s: this version has no security levels; Usable must report that", name)
			}
			continue
		}
		usable, ok := Usable(tb, all, x.Level)
		if !ok || strconv.Itoa(len(usable)) != scount || digest(usable) != ssum {
			t.Errorf("%s: usable: got %d suites (%s) ok=%v, real OpenSSL gives %s (%s)", name, len(usable), digest(usable), ok, scount, ssum)
		}
	}
	if n < 300 {
		t.Fatalf("only %d vectors were checked", n)
	}
}

// 人が読んで確かめられる例（RHEL 9 の OpenSSL 3.5）。
func TestExpandExamples(t *testing.T) {
	tb := table(t, "openssl-libs", "3.5.9-1.el9_9")

	x, err := Expand(tb, "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256", nil)
	if err != nil || strings.Join(x.Suites, " ") != "ECDHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-AES128-GCM-SHA256" || x.Level != -1 || len(x.Ignored) != 0 {
		t.Errorf("explicit names: %+v %v", x, err)
	}

	// 「-」で外したものは後で足し直せる。「!」で外したものは足し直せない。
	x, err = Expand(tb, "AES128-SHA:AES256-SHA:-AES128-SHA:AES128-SHA", nil)
	if err != nil || strings.Join(x.Suites, " ") != "AES256-SHA AES128-SHA" {
		t.Errorf("delete and re-add: %+v %v", x, err)
	}
	x, err = Expand(tb, "AES128-SHA:AES256-SHA:!AES128-SHA:AES128-SHA", nil)
	if err != nil || strings.Join(x.Suites, " ") != "AES256-SHA" {
		t.Errorf("kill: %+v %v", x, err)
	}
	// 「+」は有効なものを末尾へ動かすだけで、新しく足さない。
	x, err = Expand(tb, "AES128-SHA:AES256-SHA:+AES128-SHA:+AES128-GCM-SHA256", nil)
	if err != nil || strings.Join(x.Suites, " ") != "AES256-SHA AES128-SHA" {
		t.Errorf("reorder: %+v %v", x, err)
	}
	// 語の組み合わせ（+）は両方に当てはまるもの。
	x, err = Expand(tb, "kRSA+AESGCM", nil)
	if err != nil || strings.Join(x.Suites, " ") != "AES256-GCM-SHA384 AES128-GCM-SHA256" {
		t.Errorf("combined keywords: %+v %v", x, err)
	}
	// 区切りは「:」のほか、空白・カンマ・セミコロン。
	x, err = Expand(tb, "AES128-SHA AES256-SHA,AES128-GCM-SHA256;AES256-GCM-SHA384", nil)
	if err != nil || len(x.Suites) != 4 {
		t.Errorf("separators: %+v %v", x, err)
	}
	// @STRENGTH は強い順に並べ替える（同じ強さの中の順は保つ）。
	x, err = Expand(tb, "AES128-SHA:AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:@STRENGTH", nil)
	if err != nil || strings.Join(x.Suites, " ") != "AES256-SHA AES256-GCM-SHA384 AES128-SHA AES128-GCM-SHA256" {
		t.Errorf("strength sort: %+v %v", x, err)
	}
	// @SECLEVEL は展開結果を変えず、レベルの指定として返る。
	x, err = Expand(tb, "AES128-SHA:@SECLEVEL=0", nil)
	if err != nil || x.Level != 0 || len(x.Suites) != 1 {
		t.Errorf("seclevel: %+v %v", x, err)
	}
	// 知らない語は無視される（OpenSSL も同じ）。無視した語は報告する。
	x, err = Expand(tb, "AES128-SHA:NOSUCHWORD:!ALSO-UNKNOWN", nil)
	if err != nil || len(x.Suites) != 1 || strings.Join(x.Ignored, " ") != "NOSUCHWORD ALSO-UNKNOWN" {
		t.Errorf("unknown words: %+v %v", x, err)
	}
	// TLS 1.3 のスイートは暗号文字列の対象外（書いても TLS 1.2 以下の一覧には入らない）。
	if x, err = Expand(tb, "TLS_AES_128_GCM_SHA256:AES128-SHA", nil); err != nil || strings.Join(x.Suites, " ") != "AES128-SHA" {
		t.Errorf("TLS 1.3 name in a cipher string: %+v %v", x, err)
	}
	if got := strings.Join(DefaultTLS13(tb), " "); got != "TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_GCM_SHA256" {
		t.Errorf("default TLS 1.3 suites = %s", got)
	}

	// 使えるスイートへの絞り込み: レベル 0 なら RC4 以外の古いものも残り、レベル 4 では 128 ビットのものが落ちる。
	all := []string{"TLS_AES_128_GCM_SHA256", "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256", "PSK-AES128-CBC-SHA"}
	if u, ok := Usable(tb, all, 4); !ok || strings.Join(u, " ") != "ECDHE-RSA-AES256-GCM-SHA384" {
		t.Errorf("usable at level 4 = %v %v", u, ok)
	}
	// 事前共有鍵（PSK）のスイートは、アプリ側の設定がないと使えないので、どのレベルでも落ちる。
	if u, ok := Usable(tb, all, 0); !ok || strings.Join(u, " ") != "TLS_AES_128_GCM_SHA256 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-AES128-GCM-SHA256" {
		t.Errorf("usable at level 0 = %v %v", u, ok)
	}
	// レベルの指定がなければ、その版の既定のレベルで絞る。
	if u, ok := Usable(tb, all, -1); !ok || len(u) != 3 {
		t.Errorf("usable at the default level = %v %v", u, ok)
	}
}

func TestExpandErrors(t *testing.T) {
	tb := table(t, "openssl-libs", "3.5.9-1.el9_9")
	for rule, want := range map[string]error{
		"":                        ErrNoCipherMatch,
		"NOSUCHWORD":              ErrNoCipherMatch,
		"HIGH:!ALL:!eNULL":        ErrNoCipherMatch,
		"TLS_AES_128_GCM_SHA256":  ErrNoCipherMatch,
		"HIGH:@NOSUCHCOMMAND":     ErrInvalidCommand,
		"HIGH:@SECLEVEL=9":        ErrInvalidCommand,
		"HIGH:@SECLEVEL=":         ErrInvalidCommand,
		"SUITEB128":               ErrUnsupported,
		"SUITEB192:HIGH":          ErrUnsupported,
		"PROFILE=SYSTEM":          ErrProfileNeeded,
		"PROFILE=SYSTEM:!kRSA":    ErrProfileNeeded,
		strings.Repeat("A", 9000): ErrUnsupported,
	} {
		if _, err := Expand(tb, rule, nil); !errors.Is(err, want) {
			t.Errorf("[%.40s]: err = %v, want %v", rule, err, want)
		}
	}
	// ポリシーの内容が渡されれば PROFILE=SYSTEM を展開できる。後ろに続く規則も効く。
	p := "@SECLEVEL=2:kEECDH:kRSA:!eNULL:!aNULL"
	x, err := Expand(tb, "PROFILE=SYSTEM:-kRSA", &p)
	if err != nil || x.Level != 2 || len(x.Suites) == 0 {
		t.Fatalf("profile: %+v %v", x, err)
	}
	for _, s := range x.Suites {
		if !strings.HasPrefix(s, "ECDHE-") {
			t.Errorf("profile: unexpected suite %s", s)
		}
	}
	// PROFILE=SYSTEM のない版（Ubuntu など）では、ただの知らない語として扱われる。
	ub := table(t, "libssl3t64", "3.0.13-0ubuntu3.16")
	if _, err := Expand(ub, "PROFILE=SYSTEM", nil); !errors.Is(err, ErrNoCipherMatch) {
		t.Errorf("PROFILE=SYSTEM on Ubuntu: %v", err)
	}
	// セキュリティレベルのない古い版では、@SECLEVEL は不正な指定。
	old := table(t, "libssl1.0.0", "1.0.2g-1ubuntu4.20")
	if _, err := Expand(old, "HIGH:@SECLEVEL=1", nil); !errors.Is(err, ErrInvalidCommand) {
		t.Errorf("@SECLEVEL on 1.0.2: %v", err)
	}
	if _, ok := Usable(old, []string{"AES128-SHA"}, -1); ok {
		t.Error("Usable on 1.0.2 must report that it cannot tell")
	}
}
