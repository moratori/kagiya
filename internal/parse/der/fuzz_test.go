package der

import "testing"

// 独立したレビュー（2026-11-14）の指摘 A-4: ファズテストのなかったパーサに追加する。どんな入力でも、止まらず、panic しないこと。

func FuzzRead(f *testing.F) {
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x05})
	f.Add([]byte{0x24, 0x80, 0x04, 0x01, 'a', 0x24, 0x04, 0x04, 0x02, 'b', 'c', 0x00, 0x00})
	f.Add([]byte{0x06, 0x03, 0x2a, 0x86, 0x48})
	f.Fuzz(func(t *testing.T, data []byte) {
		e, _, err := Read(data)
		if err != nil {
			return
		}
		if out, err := OctetString(e); err == nil && len(out) > len(data) {
			t.Fatalf("the joined content (%d) is longer than the input (%d)", len(out), len(data))
		}
		if kids, err := Children(e.Content); err == nil {
			for _, k := range kids {
				OID(k.Content)
			}
		}
	})
}
