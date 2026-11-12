// Package elftest は、テスト用の最小の ELF ファイルを組み立てる。
// 実物のバイナリはリポジトリに置かないため、形式に従って自作する（実物との照合は検証ラボで行う）。
package elftest

import "encoding/binary"

// Build はテスト用の最小の ELF（プログラムヘッダ2つ、動的セクション、文字列表）を組み立てる。
func Build(class64 bool, bo binary.ByteOrder, needed []string, soname, rpath, runpath string) []byte {
	const vbase = 0x400000
	strtab := []byte{0}
	add := func(s string) uint64 {
		off := uint64(len(strtab))
		strtab = append(strtab, s...)
		strtab = append(strtab, 0)
		return off
	}
	type dyn struct{ tag, val uint64 }
	var dyns []dyn
	for _, n := range needed {
		dyns = append(dyns, dyn{1, add(n)})
	}
	if soname != "" {
		dyns = append(dyns, dyn{14, add(soname)})
	}
	if rpath != "" {
		dyns = append(dyns, dyn{15, add(rpath)})
	}
	if runpath != "" {
		dyns = append(dyns, dyn{29, add(runpath)})
	}
	ehsize, phsize, dynsize := 52, 32, 8
	if class64 {
		ehsize, phsize, dynsize = 64, 56, 16
	}
	phoff := ehsize
	dynoff := phoff + 2*phsize
	ndyn := len(dyns) + 3 // STRTAB, STRSZ, NULL
	stroff := dynoff + ndyn*dynsize
	dyns = append(dyns, dyn{5, vbase + uint64(stroff)}, dyn{10, uint64(len(strtab))}, dyn{0, 0})
	total := stroff + len(strtab)
	b := make([]byte, total)
	copy(b, []byte{0x7f, 'E', 'L', 'F'})
	if class64 {
		b[4] = 2
	} else {
		b[4] = 1
	}
	if bo == binary.LittleEndian {
		b[5] = 1
	} else {
		b[5] = 2
	}
	b[6] = 1
	bo.PutUint16(b[16:], 3) // ET_DYN
	if class64 {
		bo.PutUint16(b[18:], 183) // aarch64
		bo.PutUint64(b[32:], uint64(phoff))
		bo.PutUint16(b[54:], uint16(phsize))
		bo.PutUint16(b[56:], 2)
	} else {
		bo.PutUint16(b[18:], 40) // arm
		bo.PutUint32(b[28:], uint32(phoff))
		bo.PutUint16(b[42:], uint16(phsize))
		bo.PutUint16(b[44:], 2)
	}
	ph := func(i int, typ uint32, off, vaddr, filesz uint64) {
		p := b[phoff+i*phsize:]
		bo.PutUint32(p[0:], typ)
		if class64 {
			bo.PutUint64(p[8:], off)
			bo.PutUint64(p[16:], vaddr)
			bo.PutUint64(p[32:], filesz)
			bo.PutUint64(p[40:], filesz)
		} else {
			bo.PutUint32(p[4:], uint32(off))
			bo.PutUint32(p[8:], uint32(vaddr))
			bo.PutUint32(p[16:], uint32(filesz))
			bo.PutUint32(p[20:], uint32(filesz))
		}
	}
	ph(0, 1, 0, vbase, uint64(total))                                    // PT_LOAD
	ph(1, 2, uint64(dynoff), vbase+uint64(dynoff), uint64(ndyn*dynsize)) // PT_DYNAMIC
	for i, d := range dyns {
		p := b[dynoff+i*dynsize:]
		if class64 {
			bo.PutUint64(p[0:], d.tag)
			bo.PutUint64(p[8:], d.val)
		} else {
			bo.PutUint32(p[0:], uint32(d.tag))
			bo.PutUint32(p[4:], uint32(d.val))
		}
	}
	copy(b[stroff:], strtab)
	return b
}
