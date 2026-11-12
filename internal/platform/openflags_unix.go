//go:build unix

package platform

import "syscall"

// ReadOpenFlags はスキャン対象を開くときに追加するフラグ。
// O_NOFOLLOW: 確認後にシンボリックリンクへ差し替えられても辿らない。
// O_NONBLOCK: 確認後に FIFO へ差し替えられても開く処理が止まらない。
const ReadOpenFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK
