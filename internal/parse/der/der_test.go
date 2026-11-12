package der

import (
	"bytes"
	"testing"
)

func TestReadShortAndLongLength(t *testing.T) {
	// SEQUENCE { INTEGER 5 } の後ろに余りが 1 バイト
	e, rest, err := Read([]byte{0x30, 0x03, 0x02, 0x01, 0x05, 0xff})
	if err != nil {
		t.Fatal(err)
	}
	if e.Class != ClassUniversal || !e.Constructed || e.Tag != TagSequence ||
		!bytes.Equal(e.Content, []byte{0x02, 0x01, 0x05}) || !bytes.Equal(e.Raw, []byte{0x30, 0x03, 0x02, 0x01, 0x05}) ||
		!bytes.Equal(rest, []byte{0xff}) {
		t.Errorf("unexpected element: %+v rest=%x", e, rest)
	}
	// 長形式の長さ（0x81 0x80 = 128 バイト）
	long := append([]byte{0x04, 0x81, 0x80}, make([]byte, 128)...)
	e, rest, err = Read(long)
	if err != nil || e.Tag != TagOctetString || len(e.Content) != 128 || len(rest) != 0 {
		t.Errorf("long form: %+v, %v", e, err)
	}
	// コンテキスト固有タグ [3] 構造型
	e, _, err = Read([]byte{0xa3, 0x02, 0x05, 0x00})
	if err != nil || e.Class != ClassContext || e.Tag != 3 || !e.Constructed {
		t.Errorf("context tag: %+v, %v", e, err)
	}
}

func TestReadRejectsMalformed(t *testing.T) {
	cases := map[string][]byte{
		"empty":                  {},
		"tag only":               {0x30},
		"truncated content":      {0x30, 0x05, 0x02, 0x01},
		"truncated long length":  {0x30, 0x82, 0x01},
		"length exceeds input":   {0x04, 0x84, 0x7f, 0xff, 0xff, 0xff, 0x00},
		"length too many octets": {0x04, 0x89, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		"indefinite length":      {0x30, 0x80, 0x00, 0x00},
		"high tag truncated":     {0x1f, 0x81},
		"high tag overflow":      {0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00},
	}
	for name, in := range cases {
		if _, _, err := Read(in); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestChildren(t *testing.T) {
	kids, err := Children([]byte{0x02, 0x01, 0x05, 0x05, 0x00, 0x0c, 0x02, 'h', 'i'})
	if err != nil {
		t.Fatal(err)
	}
	if len(kids) != 3 || kids[0].Tag != TagInteger || kids[1].Tag != TagNull || string(kids[2].Content) != "hi" {
		t.Errorf("children = %+v", kids)
	}
	if _, err := Children([]byte{0x02, 0x01, 0x05, 0x02}); err == nil {
		t.Error("trailing garbage must be an error")
	}
}

func TestOID(t *testing.T) {
	cases := map[string][]byte{
		"1.2.840.113549.1.1.11":   {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b},
		"2.5.4.3":                 {0x55, 0x04, 0x03},
		"1.3.101.112":             {0x2b, 0x65, 0x70},
		"2.16.840.1.101.3.4.3.18": {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12},
		"2.999.3":                 {0x88, 0x37, 0x03},
	}
	for want, in := range cases {
		got, err := OID(in)
		if err != nil || got != want {
			t.Errorf("OID(%x) = %q, %v; want %q", in, got, err, want)
		}
	}
	for name, in := range map[string][]byte{
		"empty":           {},
		"truncated arc":   {0x2a, 0x86},
		"overflowing arc": {0x2a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
		"too long":        bytes.Repeat([]byte{0x01}, 200),
	} {
		if _, err := OID(in); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
