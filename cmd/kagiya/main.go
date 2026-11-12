// kagiya はホスト上の暗号利用を読み取りのみ・通信なしで棚卸しするツール。
package main

import (
	"os"

	"kagiya/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
