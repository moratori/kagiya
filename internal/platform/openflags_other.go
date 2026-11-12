//go:build !unix

package platform

// ReadOpenFlags は Windows では追加フラグなし（専用のオープン処理は実機検証とあわせて実装する）。
const ReadOpenFlags = 0
