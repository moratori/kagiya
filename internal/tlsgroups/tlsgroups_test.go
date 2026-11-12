package tlsgroups

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"

	"kagiya/internal/ruleset"
)

func table(t *testing.T, pkg, version string) *ruleset.GroupTable {
	t.Helper()
	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	tb, _, exact, ok := rs.GroupTableFor("openssl", pkg, version)
	if !ok || !exact {
		t.Fatalf("no group table for %s %s", pkg, version)
	}
	return tb
}

func sorted(names []string) string {
	if len(names) == 0 {
		return "-"
	}
	s := append([]string{}, names...)
	sort.Strings(s)
	return strings.Join(s, ",")
}

// 実物（各パッケージ版の openssl s_server）が受け入れたグループと、すべて一致する。
// 正解データは検証ラボで採取したもの（testdata/corpus.tsv）。
func TestResolveMatchesRealOpenSSL(t *testing.T) {
	data, err := os.ReadFile("testdata/corpus.tsv")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 7 {
			t.Fatalf("bad line: %q", line)
		}
		n++
		tb := table(t, f[0], f[1])
		spec := f[3]
		if f[2] == "default" {
			spec = ""
		}
		name := f[0] + " " + f[1] + " " + f[2] + " [" + f[3] + "]"
		r, err := Resolve(tb, spec)
		if f[4] == "rejected" {
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("%s: real OpenSSL rejects this, but Resolve returned %v (err %v)", name, r.Groups, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if sorted(r.TLS13) != f[5] || sorted(r.TLS12) != f[6] {
			t.Errorf("%s: TLS 1.3 %s / TLS 1.2 %s, real OpenSSL accepts %s / %s", name, sorted(r.TLS13), sorted(r.TLS12), f[5], f[6])
		}
	}
	if n < 240 {
		t.Fatalf("only %d vectors were checked", n)
	}
}

// 人が読んで確かめられる例。
func TestResolveExamples(t *testing.T) {
	new35 := table(t, "openssl-libs", "3.5.9-1.el9_9")
	// 指定がなければ、ライブラリの既定。OpenSSL 3.5 は、耐量子のハイブリッド（X25519MLKEM768）を先頭に含む
	r, err := Resolve(new35, "")
	if err != nil || strings.Join(r.Groups, " ") != "X25519MLKEM768 X25519 P-256 X448 P-384 P-521 ffdhe2048 ffdhe3072" {
		t.Errorf("default of 3.5: %v %v", r.Groups, err)
	}
	// TLS 1.2 の鍵交換で使えるのは楕円曲線だけ
	if strings.Join(r.TLS12, " ") != "X25519 P-256 X448 P-384 P-521" || len(r.TLS13) != 8 {
		t.Errorf("default of 3.5: TLS 1.2 %v, TLS 1.3 %v", r.TLS12, r.TLS13)
	}
	// RHEL 9.9 の暗号ポリシーの指定: ハイブリッドが入っていない
	r, err = Resolve(new35, "*X25519:secp256r1:X448:secp521r1:secp384r1:ffdhe2048:ffdhe3072:ffdhe4096:ffdhe6144:ffdhe8192")
	if err != nil || strings.Join(r.Groups, " ") != "X25519 P-256 X448 P-521 P-384 ffdhe2048 ffdhe3072 ffdhe4096 ffdhe6144 ffdhe8192" {
		t.Errorf("RHEL 9 policy: %v %v", r.Groups, err)
	}
	// 別名は正式な名前にそろえる。3.5 は大文字小文字を区別しない。知らない名前は「?」が付いていれば無視して報告する
	r, err = Resolve(new35, "?x25519_mlkem768:prime256v1/x25519:?NOSUCH")
	if err != nil || strings.Join(r.Groups, " ") != "P-256 X25519" || strings.Join(r.Ignored, " ") != "x25519_mlkem768 NOSUCH" {
		t.Errorf("aliases: %v ignored %v %v", r.Groups, r.Ignored, err)
	}
	// DEFAULT と、取り除く指定
	r, _ = Resolve(new35, "DEFAULT:-X25519MLKEM768:-ffdhe2048")
	if strings.Join(r.Groups, " ") != "X25519 P-256 X448 P-384 P-521 ffdhe3072" {
		t.Errorf("DEFAULT with removals: %v", r.Groups)
	}
	for _, bad := range []string{"X25519:NOSUCH", "X25519:", ":X25519", "?NOSUCH", "-X25519", strings.Repeat("X25519:", 5000)} {
		if _, err := Resolve(new35, bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("[%.30s] must be rejected: %v", bad, err)
		}
	}

	// 古い版（OpenSSL 3.0）: 接頭辞や DEFAULT は使えず、名前は大文字小文字を区別し、同じグループの重複は拒否される
	old := table(t, "libssl3t64", "3.0.13-0ubuntu3.16")
	r, err = Resolve(old, "")
	if err != nil || strings.Join(r.Groups, " ") != "X25519 X448 P-256 P-384 P-521 ffdhe2048 ffdhe3072 ffdhe4096 ffdhe6144 ffdhe8192" {
		t.Errorf("default of 3.0: %v %v", r.Groups, err)
	}
	if r, err := Resolve(old, "prime256v1 : X25519"); err != nil || strings.Join(r.Groups, " ") != "P-256 X25519" {
		t.Errorf("basic list: %v %v", r.Groups, err)
	}
	for _, bad := range []string{"?X25519", "DEFAULT", "X25519/P-256", "p-256", "P-256:prime256v1", "X25519MLKEM768"} {
		if _, err := Resolve(old, bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("3.0 [%s] must be rejected: %v", bad, err)
		}
	}

	// セキュリティレベルによる絞り込み（3.5）: レベル 4 では X25519 や P-256 が落ち、ハイブリッドは残る
	all, _ := Resolve(new35, "")
	u, ok := Usable(new35, all.Groups, 4)
	if !ok || strings.Join(u, " ") != "X25519MLKEM768 X448 P-384 P-521" {
		t.Errorf("usable at level 4: %v %v", u, ok)
	}
	if u, ok := Usable(new35, all.Groups, 2); !ok || len(u) != len(all.Groups) {
		t.Errorf("usable at level 2: %v %v", u, ok)
	}
	if u, ok := Usable(new35, all.Groups, -1); !ok || len(u) != len(all.Groups) {
		t.Errorf("no level: %v %v", u, ok)
	}
	// レベルごとの測定ができていない範囲（1.1.1 のレベル 3 以上）は、絞り込めないと報告する
	old111 := table(t, "openssl-libs", "1.1.1k-18.el8_6")
	d, _ := Resolve(old111, "")
	if _, ok := Usable(old111, d.Groups, 3); ok {
		t.Error("level 3 is not measured for 1.1.1; Usable must report that")
	}
	if u, ok := Usable(old111, d.Groups, 2); !ok || len(u) != 5 {
		t.Errorf("1.1.1 at level 2: %v %v", u, ok)
	}
}
