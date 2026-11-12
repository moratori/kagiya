// Package ldcache は動的リンカのキャッシュ（/etc/ld.so.cache）を読む。
// 共有ライブラリの名前から置き場所を引くために使う（ldconfig や ldd は実行しない）。
package ldcache

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// Entry はキャッシュの1件（ライブラリ名と場所）。
type Entry struct {
	Name  string
	Path  string
	Flags int32 // ライブラリの種別とアーキテクチャを表す値
}

var errFormat = errors.New("ldcache: unexpected format")

const (
	// 新形式の識別子。古い glibc が作ったキャッシュでは、旧形式（ld.so-1.7.0）の後ろにこの形式が続く。
	newMagic   = "glibc-ld.so.cache1.1"
	headerSize = 48
	entrySize  = 24
	maxEntries = 1 << 20
	maxString  = 4096
)

// Parse はキャッシュの内容を読む。
func Parse(data []byte) ([]Entry, error) {
	base := bytes.Index(data, []byte(newMagic))
	if base < 0 {
		return nil, errFormat
	}
	b := data[base:] // 文字列の位置は、新形式の先頭からの相対位置で記録されている
	if len(b) < headerSize {
		return nil, errFormat
	}
	bo := binary.LittleEndian
	n := int(bo.Uint32(b[20:]))
	if n < 0 || n > maxEntries || headerSize+n*entrySize > len(b) {
		return nil, errFormat
	}
	str := func(off uint32) (string, bool) {
		if int(off) >= len(b) {
			return "", false
		}
		s := b[off:]
		if len(s) > maxString {
			s = s[:maxString]
		}
		i := bytes.IndexByte(s, 0)
		if i <= 0 {
			return "", false
		}
		for _, c := range s[:i] {
			if c < 0x20 || c == 0x7f {
				return "", false
			}
		}
		return string(s[:i]), true
	}
	out := make([]Entry, 0, n)
	for i := 0; i < n; i++ {
		e := b[headerSize+i*entrySize:]
		name, ok1 := str(bo.Uint32(e[4:]))
		path, ok2 := str(bo.Uint32(e[8:]))
		if !ok1 || !ok2 {
			return nil, errFormat
		}
		out = append(out, Entry{Name: name, Path: path, Flags: int32(bo.Uint32(e[0:]))})
	}
	return out, nil
}
