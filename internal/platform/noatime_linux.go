package platform

import "syscall"

// NoAtime は、読んでもアクセス時刻（atime）を更新しないためのフラグ。ファイルの所有者か root でなければ、開くときに拒否される
// （その場合は、フラグなしで開き直す）。
const NoAtime = syscall.O_NOATIME

// DirectoryFlag は、ディレクトリだけを開くためのフラグ。
const DirectoryFlag = syscall.O_DIRECTORY
