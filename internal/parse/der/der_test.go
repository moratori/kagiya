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
		"indefinite primitive":   {0x04, 0x80, 0x00, 0x00},
		"indefinite unterminated": {0x30, 0x80, 0x02, 0x01, 0x05},
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

// BER の不定長形式（PKCS#12 や PKCS#7 でよく使われる）。内容は終端（00 00）の手前まで。
func TestReadIndefiniteLength(t *testing.T) {
	in := []byte{0x30, 0x80, 0x02, 0x01, 0x05, 0x30, 0x80, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0xee}
	e, rest, err := Read(in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rest, []byte{0xee}) || !bytes.Equal(e.Raw, in[:13]) || !bytes.Equal(e.Content, in[2:11]) {
		t.Errorf("content=%x raw=%x rest=%x", e.Content, e.Raw, rest)
	}
	kids, err := Children(e.Content)
	if err != nil || len(kids) != 2 || kids[0].Tag != TagInteger || !kids[1].Constructed || len(kids[1].Content) != 2 {
		t.Errorf("children = %+v, %v", kids, err)
	}
	// 入れ子が深すぎるものは拒否する
	deep := bytes.Repeat([]byte{0x30, 0x80}, 200)
	deep = append(deep, bytes.Repeat([]byte{0x00, 0x00}, 200)...)
	if _, _, err := Read(deep); err == nil {
		t.Error("deeply nested indefinite-length input must be rejected")
	}
}

// BER では OCTET STRING が分割（構造型）されることがある。
func TestOctetString(t *testing.T) {
	prim, _, _ := Read([]byte{0x04, 0x03, 1, 2, 3})
	if b, err := OctetString(prim); err != nil || !bytes.Equal(b, []byte{1, 2, 3}) {
		t.Errorf("primitive: %x %v", b, err)
	}
	cons, _, err := Read([]byte{0x24, 0x80, 0x04, 0x02, 1, 2, 0x04, 0x01, 3, 0x00, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	if b, err := OctetString(cons); err != nil || !bytes.Equal(b, []byte{1, 2, 3}) {
		t.Errorf("constructed: %x %v", b, err)
	}
	notOctet, _, _ := Read([]byte{0x02, 0x01, 0x05})
	if _, err := OctetString(notOctet); err == nil {
		t.Error("OctetString on INTEGER must fail")
	}
}
