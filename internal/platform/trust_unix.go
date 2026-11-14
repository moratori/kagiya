//go:build unix

package platform

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Elevated は管理者権限（root）で動いているかを返す。
func Elevated() bool { return os.Geteuid() == 0 }

// TerminationSignals は安全に停止すべきシグナル（Ctrl+C、終了の要求、端末や SSH の接続が切れたとき）。
func TerminationSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}
}

// CheckAncestors は、dir の上位のディレクトリに、他の利用者が書き込めるもの（スティッキービットなし）がないことを確かめる。
// そういう場所では、dir そのものを、リンクや別のディレクトリに差し替えられる。dir は、まだなくてもよい。
// 途中のシンボリックリンクは、そのリンクを置いてあるディレクトリの権限で確かめたことになるので、辿った先は見ない。
func CheckAncestors(dir string) error { return checkPath(dir, false) }

// checkPath は、dir までの各要素を確かめる。strict なら、dir 自身があること、途中にシンボリックリンクがないことも確かめる。
func checkPath(dir string, strict bool) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return fmt.Errorf("%s: not a clean absolute path", dir)
	}
	prefix := ""
	for _, seg := range strings.Split(strings.TrimPrefix(dir, "/"), "/") {
		prefix += "/" + seg
		if prefix == dir && !strict {
			break // dir 自身は、呼び出す側が確かめる
		}
		fi, err := os.Lstat(prefix)
		if err != nil {
			return err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			if strict {
				return fmt.Errorf("%s is a symbolic link", prefix)
			}
			continue
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s is not a directory", prefix)
		}
		// 上位のディレクトリ: 他ユーザーが書き込めると、ディレクトリごと差し替えられる（スティッキービット付きは除く）。
		if prefix != dir && fi.Mode().Perm()&0o022 != 0 && fi.Mode()&fs.ModeSticky == 0 {
			return fmt.Errorf("%s is writable by other users", prefix)
		}
	}
	return nil
}

// CheckTrustedDir は外部ルールディレクトリが信頼できる状態かを検査する。
// ルールは「何を読み、何を出力するか」を決めるためバイナリと同等の信頼が要る。
// 他ユーザーが書き換えられる、またはシンボリックリンクを含む場合は拒否する。
func CheckTrustedDir(dir string) error {
	if err := checkPath(dir, true); err != nil {
		return err
	}
	euid := uint32(os.Geteuid())
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symbolic link", p)
		}
		if !fi.IsDir() && !fi.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", p)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is writable by other users", p)
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != euid && st.Uid != 0 {
			return fmt.Errorf("%s is owned by another user", p)
		}
		return nil
	})
}

// OwnedBySelfOrRoot は、ファイルの所有者が実行ユーザーまたは root かを返す。
func OwnedBySelfOrRoot(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	return st.Uid == uint32(os.Geteuid()) || st.Uid == 0
}
