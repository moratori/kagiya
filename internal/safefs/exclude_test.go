package safefs

import "testing"

func TestExcludeMatch(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/var/log", "/var/log", true},
		{"/var/log", "/var/log/messages", false}, // ディレクトリ一致時は走査側が配下ごと飛ばす
		{"/var/log", "/var/logs", false},
		{"/var/*/cache", "/var/a/cache", true},
		{"/var/*/cache", "/var/a/b/cache", false},
		{"/data/**", "/data/a/b/c.pem", true},
		{"/data/**", "/data", false},
		{"/data/**/tmp", "/data/tmp", true},
		{"/data/**/tmp", "/data/a/b/tmp", true},
		{"**/node_modules", "/srv/app/node_modules", true},
		{"**/node_modules", "/srv/app/node_modules2", false},
		{"/home/*/.ssh/id_?sa", "/home/bob/.ssh/id_rsa", true},
		{"/home/*/.ssh/id_?sa", "/home/bob/.ssh/id_ecdsa", false},
		// スラッシュを含まないパターンはファイル名（最後の要素）に対して照合
		{"*.log", "/var/log/app.log", true},
		{"*.log", "/var/log/app.log.1", false},
		{"node_modules", "/srv/app/node_modules", true},
		// 正規表現のメタ文字はそのまま文字として扱う
		{"/opt/app(v1)/[x].+", "/opt/app(v1)/[x].+", true},
		{"/opt/a.c", "/opt/abc", false},
	}
	for _, c := range cases {
		ex, err := NewExcludes([]string{c.pattern})
		if err != nil {
			t.Errorf("NewExcludes(%q): %v", c.pattern, err)
			continue
		}
		if got := ex.Match(c.path); got != c.want {
			t.Errorf("pattern %q, path %q: got %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestExcludesMultipleAndEmpty(t *testing.T) {
	ex, err := NewExcludes([]string{"/a", "*.tmp"})
	if err != nil {
		t.Fatal(err)
	}
	if !ex.Match("/a") || !ex.Match("/x/y.tmp") || ex.Match("/b") {
		t.Error("multiple patterns matched wrongly")
	}
	none, _ := NewExcludes(nil)
	if none.Match("/anything") {
		t.Error("empty exclude list must match nothing")
	}
	if _, err := NewExcludes([]string{""}); err == nil {
		t.Error("empty pattern must be rejected")
	}
}
