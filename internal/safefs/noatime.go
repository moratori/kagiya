package safefs

import (
	"errors"
	"io/fs"
	"os"

	"kagiya/internal/platform"
)

// openQuietly は、アクセス時刻（atime）を更新しないフラグを付けて開く。スキャンが、対象のファイルやディレクトリに
// 「読まれた」という跡を残さないようにするため（atime は、侵害調査や、使われていないファイルの判定に使われる）。
// このフラグは、ファイルの所有者か root でなければ拒否される。その場合はフラグなしで開き直し、守れなかった数を数える。
func openQuietly(open func(flag int) (*os.File, error), flag int, notPreserved *int) (*os.File, error) {
	if platform.NoAtime == 0 {
		return open(flag)
	}
	f, err := open(flag | platform.NoAtime)
	if err == nil || !errors.Is(err, fs.ErrPermission) {
		return f, err
	}
	f, err = open(flag)
	if err == nil {
		*notPreserved++
	}
	return f, err
}
