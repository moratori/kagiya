// Package elfdyn は ELF ファイルの動的セクションから、リンクしている共有ライブラリの名前などを読む。
//
// 逆アセンブルや逆コンパイルは行わない。読むのはファイル形式上のメタデータ（ヘッダ、プログラムヘッダ、
// 動的セクション、その文字列表）だけ。入力は敵対的とみなし、大きさと個数に上限を設ける。
package elfdyn

import (
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

type Info struct {
	Class        int // 32 または 64
	LittleEndian bool
	Type         uint16 // 2: 実行ファイル、3: 共有オブジェクト（位置独立の実行ファイルを含む）
	Machine      uint16 // 62: x86-64、183: AArch64 など
	Needed       []string
	SOName       string
	RPath        []string // 古い形式の探索パス（RunPath があれば使われない）
	RunPath      []string
}

// ErrNotELF は ELF ファイルではないこと、ErrMalformed は ELF だが読めないことを表す。
var (
	ErrNotELF    = errors.New("elfdyn: not an ELF file")
	ErrMalformed = errors.New("elfdyn: malformed or unsupported ELF file")
)

const (
	ptLoad    = 1
	ptDynamic = 2

	dtNull    = 0
	dtNeeded  = 1
	dtStrTab  = 5
	dtStrSz   = 10
	dtSOName  = 14
	dtRPath   = 15
	dtRunPath = 29

	maxPhdrs   = 4096
	maxDynSize = 1 << 20
	maxStrTab  = 32 << 20
	maxString  = 4096
	maxEntries = 4096
)

// Read は ELF ファイルを読む。動的セクションがない（静的リンクの）場合は、Needed が空の Info を返す。
func Read(r io.ReaderAt, size int64) (*Info, error) {
	hdr := make([]byte, 64)
	n, _ := r.ReadAt(hdr, 0)
	if n < 4 || string(hdr[:4]) != "\x7fELF" {
		return nil, ErrNotELF
	}
	if n < 52 {
		return nil, ErrMalformed
	}
	info := &Info{}
	switch hdr[4] {
	case 1:
		info.Class = 32
	case 2:
		info.Class = 64
	default:
		return nil, ErrMalformed
	}
	var bo binary.ByteOrder
	switch hdr[5] {
	case 1:
		bo, info.LittleEndian = binary.LittleEndian, true
	case 2:
		bo = binary.BigEndian
	default:
		return nil, ErrMalformed
	}
	info.Type = bo.Uint16(hdr[16:])
	info.Machine = bo.Uint16(hdr[18:])

	var phoff uint64
	var phentsize, phnum int
	if info.Class == 64 {
		phoff = bo.Uint64(hdr[32:])
		phentsize, phnum = int(bo.Uint16(hdr[54:])), int(bo.Uint16(hdr[56:]))
	} else {
		phoff = uint64(bo.Uint32(hdr[28:]))
		phentsize, phnum = int(bo.Uint16(hdr[42:])), int(bo.Uint16(hdr[44:]))
	}
	minPh := 32
	if info.Class == 64 {
		minPh = 56
	}
	if phnum == 0 {
		return info, nil
	}
	if phnum > maxPhdrs || phentsize < minPh || phentsize > 256 || phoff > uint64(size) {
		return nil, ErrMalformed
	}
	phdrs := make([]byte, phnum*phentsize)
	if _, err := r.ReadAt(phdrs, int64(phoff)); err != nil {
		return nil, ErrMalformed
	}
	type segment struct {
		typ                uint32
		off, vaddr, filesz uint64
	}
	segs := make([]segment, phnum)
	for i := range segs {
		p := phdrs[i*phentsize:]
		s := segment{typ: bo.Uint32(p[0:])}
		if info.Class == 64 {
			s.off, s.vaddr, s.filesz = bo.Uint64(p[8:]), bo.Uint64(p[16:]), bo.Uint64(p[32:])
		} else {
			s.off, s.vaddr, s.filesz = uint64(bo.Uint32(p[4:])), uint64(bo.Uint32(p[8:])), uint64(bo.Uint32(p[16:]))
		}
		segs[i] = s
	}
	// 仮想アドレスをファイル上の位置に直す（動的セクションの文字列表は仮想アドレスで指されている）。
	toOffset := func(vaddr uint64) (uint64, bool) {
		for _, s := range segs {
			if s.typ == ptLoad && vaddr >= s.vaddr && vaddr-s.vaddr < s.filesz {
				return vaddr - s.vaddr + s.off, true
			}
		}
		return 0, false
	}

	var dyn []byte
	for _, s := range segs {
		if s.typ != ptDynamic {
			continue
		}
		if s.filesz == 0 || s.filesz > maxDynSize || s.off > uint64(size) || s.filesz > uint64(size)-s.off {
			return nil, ErrMalformed
		}
		dyn = make([]byte, s.filesz)
		if _, err := r.ReadAt(dyn, int64(s.off)); err != nil {
			return nil, ErrMalformed
		}
		break
	}
	if dyn == nil {
		return info, nil
	}

	entSize := 8
	if info.Class == 64 {
		entSize = 16
	}
	type entry struct{ tag, val uint64 }
	var names []entry
	var strAddr, strSize uint64
	for i := 0; i+entSize <= len(dyn); i += entSize {
		var e entry
		if info.Class == 64 {
			e.tag, e.val = bo.Uint64(dyn[i:]), bo.Uint64(dyn[i+8:])
		} else {
			e.tag, e.val = uint64(bo.Uint32(dyn[i:])), uint64(bo.Uint32(dyn[i+4:]))
		}
		if e.tag == dtNull {
			break
		}
		switch e.tag {
		case dtStrTab:
			strAddr = e.val
		case dtStrSz:
			strSize = e.val
		case dtNeeded, dtSOName, dtRPath, dtRunPath:
			if len(names) < maxEntries {
				names = append(names, e)
			}
		}
	}
	if len(names) == 0 {
		return info, nil
	}
	strOff, ok := toOffset(strAddr)
	if !ok || strSize == 0 || strSize > maxStrTab || strOff > uint64(size) || strSize > uint64(size)-strOff {
		return nil, ErrMalformed
	}
	strtab := make([]byte, strSize)
	if _, err := r.ReadAt(strtab, int64(strOff)); err != nil {
		return nil, ErrMalformed
	}
	str := func(off uint64) string {
		if off >= uint64(len(strtab)) {
			return ""
		}
		s := strtab[off:]
		if len(s) > maxString {
			s = s[:maxString]
		}
		for i, c := range s {
			if c == 0 {
				return clean(string(s[:i]))
			}
		}
		return ""
	}
	for _, e := range names {
		s := str(e.val)
		if s == "" {
			continue
		}
		switch e.tag {
		case dtNeeded:
			info.Needed = append(info.Needed, s)
		case dtSOName:
			info.SOName = s
		case dtRPath:
			info.RPath = splitPath(s)
		case dtRunPath:
			info.RunPath = splitPath(s)
		}
	}
	return info, nil
}

func splitPath(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ":") {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0xFFFD {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
}
