package platform

import "testing"

// setuid / setgid で起動された（実ユーザーと実効ユーザーが違う）場合を見分ける。その場合、kagiya は起動を拒否する（設計書 4.7）。
func TestStartedSetID(t *testing.T) {
	for _, tc := range []struct {
		uid, euid, gid, egid int
		want                 bool
	}{
		{1000, 1000, 1000, 1000, false},
		{0, 0, 0, 0, false},         // root として起動（sudo など）は、昇格した起動ではない
		{1000, 0, 1000, 1000, true}, // setuid root
		{1000, 1001, 1000, 1000, true},
		{1000, 1000, 1000, 0, true}, // setgid
		{-1, -1, -1, -1, false},     // ユーザー ID のない OS（Windows）
	} {
		if got := startedSetID(tc.uid, tc.euid, tc.gid, tc.egid); got != tc.want {
			t.Errorf("uid=%d euid=%d gid=%d egid=%d: %v, want %v", tc.uid, tc.euid, tc.gid, tc.egid, got, tc.want)
		}
	}
	// テストは、ふつうの起動で動いている
	if StartedSetID() {
		t.Error("the test process must not be reported as started setuid/setgid")
	}
}
