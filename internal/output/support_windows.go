//go:build windows

package output

import "errors"

// Windows では、作成時にアクセス制御リストを確定する実装（設計書 4.6）と実機検証が済むまで書き込みを行わない。
// 既定の権限のままファイルを作ると「作成者以外が読めない」を保証できないため。
func supported() error {
	return errors.New("writing output is not yet supported on Windows")
}
