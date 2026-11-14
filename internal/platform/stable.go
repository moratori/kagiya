package platform

import "bytes"

// readStable は、read を繰り返し呼び、2 回続けて同じ内容が返ったら、それを返す。決まった回数のうちに落ち着かなければ ok = false。
// マウント表（/proc/self/mountinfo）は、読んでいる途中でマウントが出入りすると、古いカーネルでは無関係な行が抜けることがある。
// 抜けたのがネットワークファイルシステムの行だと、そこを「読んでよい場所」と誤って判断するので、同じ内容が 2 回読めるまで確かめる。
func readStable(read func() ([]byte, error)) ([]byte, bool) {
	const tries = 8
	var prev []byte
	for i := 0; i < tries; i++ {
		cur, err := read()
		if err != nil {
			return nil, false
		}
		if i > 0 && bytes.Equal(prev, cur) {
			return cur, true
		}
		prev = cur
	}
	return nil, false
}
