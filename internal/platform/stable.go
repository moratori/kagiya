package platform

// readStable は、read を繰り返し呼び、2 回続けて同じ内容が返ったら、それを返す。
func readStable(read func() ([]byte, error)) ([]byte, bool) { return nil, false }
