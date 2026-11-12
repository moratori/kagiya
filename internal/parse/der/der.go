// Package der は ASN.1 DER の最小限のリーダ。入力は敵対的とみなし、長さ・個数に上限を設ける。
// BER（不定長など）は Phase 1a で対応する。
package der

import (
	"errors"
	"strconv"
	"strings"
)

const (
	ClassUniversal = 0
	ClassContext   = 2

	TagBoolean         = 1
	TagInteger         = 2
	TagBitString       = 3
	TagOctetString     = 4
	TagNull            = 5
	TagOID             = 6
	TagUTF8String      = 12
	TagSequence        = 16
	TagSet             = 17
	TagPrintableString = 19
	TagT61String       = 20
	TagIA5String       = 22
	TagUTCTime         = 23
	TagGeneralizedTime = 24
	TagUniversalString = 28
	TagBMPString       = 30

	maxChildren = 100_000
	maxOIDBytes = 64
)

var errMalformed = errors.New("malformed DER")

// Element は TLV ひとつ。Content と Raw は入力スライスを共有する。
type Element struct {
	Class       int
	Constructed bool
	Tag         int
	Content     []byte
	Raw         []byte // タグ・長さを含む全体
}

// Read は b の先頭から要素を1つ読み、残りを返す。
func Read(b []byte) (Element, []byte, error) {
	var e Element
	if len(b) < 2 {
		return e, nil, errMalformed
	}
	e.Class = int(b[0] >> 6)
	e.Constructed = b[0]&0x20 != 0
	e.Tag = int(b[0] & 0x1f)
	i := 1
	if e.Tag == 0x1f { // 高タグ番号形式
		e.Tag = 0
		for {
			if i >= len(b) || e.Tag > 1<<20 {
				return e, nil, errMalformed
			}
			c := b[i]
			i++
			e.Tag = e.Tag<<7 | int(c&0x7f)
			if c&0x80 == 0 {
				break
			}
		}
	}
	if i >= len(b) {
		return e, nil, errMalformed
	}
	length := int(b[i])
	i++
	if length&0x80 != 0 {
		n := length & 0x7f
		if n == 0 || n > 4 || i+n > len(b) { // 不定長、または長すぎる長さ指定
			return e, nil, errMalformed
		}
		length = 0
		for j := 0; j < n; j++ {
			length = length<<8 | int(b[i+j])
		}
		i += n
	}
	if length < 0 || length > len(b)-i {
		return e, nil, errMalformed
	}
	e.Content = b[i : i+length]
	e.Raw = b[:i+length]
	return e, b[i+length:], nil
}

// Children は構造型の内容を要素の並びとして読む。余りがあればエラー。
func Children(content []byte) ([]Element, error) {
	var out []Element
	for len(content) > 0 {
		if len(out) >= maxChildren {
			return nil, errMalformed
		}
		e, rest, err := Read(content)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
		content = rest
	}
	return out, nil
}

// OID は OBJECT IDENTIFIER の内容をドット区切りの文字列にする。
func OID(content []byte) (string, error) {
	if len(content) == 0 || len(content) > maxOIDBytes {
		return "", errMalformed
	}
	var b strings.Builder
	first := true
	var v uint64
	started := false
	for _, c := range content {
		if v > 1<<56 {
			return "", errMalformed
		}
		v = v<<7 | uint64(c&0x7f)
		started = true
		if c&0x80 != 0 {
			continue
		}
		if first {
			a := v / 40
			if a > 2 {
				a = 2
			}
			b.WriteString(strconv.FormatUint(a, 10))
			b.WriteByte('.')
			b.WriteString(strconv.FormatUint(v-a*40, 10))
			first = false
		} else {
			b.WriteByte('.')
			b.WriteString(strconv.FormatUint(v, 10))
		}
		v, started = 0, false
	}
	if started { // 最後のバイトで終わっていない
		return "", errMalformed
	}
	return b.String(), nil
}

// ---- 符号化（公開鍵の指紋計算のために SubjectPublicKeyInfo を組み立てる用途） ----

// Encode はタグ（先頭1バイト）と内容から DER 要素を作る。
func Encode(tag byte, content []byte) []byte {
	n := len(content)
	var hdr []byte
	switch {
	case n < 0x80:
		hdr = []byte{tag, byte(n)}
	case n < 1<<8:
		hdr = []byte{tag, 0x81, byte(n)}
	case n < 1<<16:
		hdr = []byte{tag, 0x82, byte(n >> 8), byte(n)}
	case n < 1<<24:
		hdr = []byte{tag, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		hdr = []byte{tag, 0x84, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return append(hdr, content...)
}

// EncodeSequence は要素を並べた SEQUENCE を作る。
func EncodeSequence(parts ...[]byte) []byte {
	var c []byte
	for _, p := range parts {
		c = append(c, p...)
	}
	return Encode(0x30, c)
}

// EncodeUint は符号なし整数（ビッグエンディアンの絶対値）を INTEGER にする。
func EncodeUint(mag []byte) []byte {
	for len(mag) > 1 && mag[0] == 0 {
		mag = mag[1:]
	}
	if len(mag) == 0 {
		mag = []byte{0}
	}
	if mag[0]&0x80 != 0 {
		mag = append([]byte{0}, mag...)
	}
	return Encode(0x02, mag)
}

// EncodeBitString はバイト列をそのまま内容とする BIT STRING を作る。
func EncodeBitString(b []byte) []byte {
	return Encode(0x03, append([]byte{0}, b...))
}

// EncodeOID はドット区切りの OID を符号化する。不正な文字列なら nil。
func EncodeOID(s string) []byte {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil
	}
	arcs := make([]uint64, len(parts))
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 10, 56)
		if err != nil {
			return nil
		}
		arcs[i] = v
	}
	if arcs[0] > 2 || (arcs[0] < 2 && arcs[1] >= 40) {
		return nil
	}
	var c []byte
	put := func(v uint64) {
		var tmp []byte
		tmp = append(tmp, byte(v&0x7f))
		for v >>= 7; v > 0; v >>= 7 {
			tmp = append(tmp, byte(v&0x7f)|0x80)
		}
		for i := len(tmp) - 1; i >= 0; i-- {
			c = append(c, tmp[i])
		}
	}
	put(arcs[0]*40 + arcs[1])
	for _, a := range arcs[2:] {
		put(a)
	}
	return Encode(0x06, c)
}
