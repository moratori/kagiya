package der

import (
	"bytes"
	"runtime"
	"testing"
)

// 独立したレビュー（2026-11-14）の指摘 P-2。分割された形（構造型）の OCTET STRING を読むとき、子をいったん全部並べてから辿っていたので、
// 空の子を大量に並べて入れ子にした入力で、入力の何十倍ものメモリを確保した。

// tlv は、タグと内容から要素を作る（長さは 3 バイトまで）。
func tlv(tag byte, content []byte) []byte {
	n := len(content)
	switch {
	case n < 0x80:
		return append([]byte{tag, byte(n)}, content...)
	case n < 0x10000:
		return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, content...)
	}
	return append([]byte{tag, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}, content...)
}

func TestConstructedOctetString(t *testing.T) {
	// 分割された形: 中身をつなげたものが返る（入れ子も）
	inner := tlv(0x24, append(tlv(0x04, []byte("bc")), tlv(0x04, []byte("d"))...))
	e, _, err := Read(tlv(0x24, append(append(tlv(0x04, []byte("a")), inner...), tlv(0x04, []byte("e"))...)))
	if err != nil {
		t.Fatal(err)
	}
	if b, err := OctetString(e); err != nil || string(b) != "abcde" {
		t.Errorf("OctetString = %q %v", b, err)
	}
	// 深すぎる入れ子は断る（実物の PKCS#12 では、分割は 1〜2 段）
	deep := tlv(0x04, []byte("x"))
	for i := 0; i < maxOctetDepth+1; i++ {
		deep = tlv(0x24, deep)
	}
	e, _, err = Read(deep)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OctetString(e); err == nil {
		t.Error("an OCTET STRING nested too deeply must be rejected")
	}
}

func TestConstructedOctetStringDoesNotAmplify(t *testing.T) {
	// 各段: 次の段を包む OCTET STRING 1 個と、空の OCTET STRING 99,000 個（約 200 KB）
	level := tlv(0x04, []byte("x"))
	for i := 0; i < 3; i++ {
		level = tlv(0x24, append(level, bytes.Repeat([]byte{0x04, 0x00}, 99000)...))
	}
	e, _, err := Read(level)
	if err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	b, err := OctetString(e)
	runtime.ReadMemStats(&after)
	if err != nil || string(b) != "x" {
		t.Fatalf("OctetString = %q %v", b, err)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 1<<20 {
		t.Errorf("allocated %d bytes for an input of %d bytes", got, len(level))
	}
}
