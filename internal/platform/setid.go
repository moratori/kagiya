package platform

import (
	"os"
	"runtime/debug"
)

// StartedSetID は、setuid / setgid で起動された（実ユーザーと実効ユーザー、または実グループと実効グループが違う）かを返す。
// その場合、起動した人より高い権限でファイルを読み、起動した人が読める場所に結果を書くことになるので、kagiya は起動を拒否する。
// ユーザー ID のない OS（Windows）では、常に false。
func StartedSetID() bool {
	return startedSetID(os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid())
}

func startedSetID(uid, euid, gid, egid int) bool {
	return uid != euid || gid != egid
}

// LimitMemory は、メモリの使用量の上限（Go のソフトリミット）を設定する。上限に近づくと、メモリの回収を増やして抑える
// （超えても止まりはしない）。環境変数 GOMEMLIMIT の指定より、この設定が優先される。
func LimitMemory(mib int64) int64 {
	debug.SetMemoryLimit(mib << 20)
	return mib
}
