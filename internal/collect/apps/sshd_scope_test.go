package apps

import (
	"strings"
	"testing"
)

// sshd の Match の条件も、ほかのアプリの範囲と同じく、検証を通ったものだけを記録する（独立したレビューの指摘 B-1）。
func TestSSHDMatchScope(t *testing.T) {
	for _, ok := range []string{"User alice,bob", "Group sftp-users Address 10.0.0.0/8,!10.1.0.0/16", "Host *.example.jp", "all", "LocalPort 2222", "User *@example.jp"} {
		if got := sshdMatchScope(ok); got != "Match "+ok {
			t.Errorf("%q: %q", ok, got)
		}
	}
	for _, bad := range []string{"User evil\x1b[31m", "User " + strings.Repeat("a", 300), "Exec \"/usr/bin/id $(x)\"", "User a‮b", "User <x>"} {
		got := sshdMatchScope(bad)
		if !strings.HasPrefix(got, "Match (") || strings.Contains(got, "evil") || len(got) > 80 {
			t.Errorf("%q: %q, want a fixed text without the condition", bad, got)
		}
	}
}
