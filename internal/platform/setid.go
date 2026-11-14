package platform

// StartedSetID は、setuid / setgid で起動された（実ユーザーと実効ユーザー、または実グループと実効グループが違う）かを返す。
func StartedSetID() bool { return false }

func startedSetID(uid, euid, gid, egid int) bool { return false }
