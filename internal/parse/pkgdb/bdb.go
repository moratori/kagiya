package pkgdb

import (
	"encoding/binary"
	"io"
)

// rpm の Berkeley DB（Hash 形式）データベース「Packages」の読み取り。
// RHEL 8 系の rpm 4.14 が使う。値が1ページに収まらない場合はオーバーフローページの連鎖に入る。

const (
	bdbHashMagic     = 0x00061561
	bdbPageHeader    = 26
	bdbTypeHashUnsrt = 2
	bdbTypeOverflow  = 7
	bdbTypeHash      = 13
	bdbItemKeyData   = 1
	bdbItemOffPage   = 3
)

// ReadRPMBDB は Packages ファイルから全パッケージを読む。failed は、ヘッダらしいのに解析できなかった件数。
func ReadRPMBDB(r io.ReaderAt, size int64) (pkgs []Package, failed int, err error) {
	meta := make([]byte, 72)
	if _, err := r.ReadAt(meta, 0); err != nil {
		return nil, 0, errFormat
	}
	var bo binary.ByteOrder
	switch {
	case binary.LittleEndian.Uint32(meta[12:]) == bdbHashMagic:
		bo = binary.LittleEndian
	case binary.BigEndian.Uint32(meta[12:]) == bdbHashMagic:
		bo = binary.BigEndian
	default:
		return nil, 0, errFormat
	}
	pageSize := int(bo.Uint32(meta[20:]))
	if pageSize < 512 || pageSize > 65536 || pageSize&(pageSize-1) != 0 {
		return nil, 0, errFormat
	}
	npages := size / int64(pageSize)
	if last := int64(bo.Uint32(meta[32:])); last+1 < npages {
		npages = last + 1
	}
	page := make([]byte, pageSize)
	ovf := make([]byte, pageSize)

	readOverflow := func(pgno uint32, total int) []byte {
		if total <= 0 || total > maxBlob {
			return nil
		}
		out := make([]byte, 0, total)
		for steps := int64(0); pgno != 0 && len(out) < total; steps++ {
			if steps > npages || int64(pgno) >= npages {
				return nil
			}
			if _, err := r.ReadAt(ovf, int64(pgno)*int64(pageSize)); err != nil {
				return nil
			}
			if ovf[25] != bdbTypeOverflow {
				return nil
			}
			n := int(bo.Uint16(ovf[22:])) // このページに入っているバイト数
			if n <= 0 || n > pageSize-bdbPageHeader {
				return nil
			}
			if rest := total - len(out); n > rest {
				n = rest
			}
			out = append(out, ovf[bdbPageHeader:bdbPageHeader+n]...)
			pgno = bo.Uint32(ovf[16:]) // 次のページ
		}
		if len(out) != total {
			return nil
		}
		return out
	}

	for pg := int64(1); pg < npages; pg++ {
		if _, err := r.ReadAt(page, pg*int64(pageSize)); err != nil {
			break
		}
		if t := page[25]; t != bdbTypeHash && t != bdbTypeHashUnsrt {
			continue
		}
		entries := int(bo.Uint16(page[20:]))
		if bdbPageHeader+2*entries > pageSize {
			continue
		}
		// 項目は「キー、値、キー、値…」の順。値（奇数番目）だけを見る。
		for i := 1; i < entries; i += 2 {
			off := int(bo.Uint16(page[bdbPageHeader+2*i:]))
			end := int(bo.Uint16(page[bdbPageHeader+2*(i-1):]))
			if off < bdbPageHeader+2*entries || off >= end || end > pageSize {
				continue
			}
			item := page[off:end]
			var val []byte
			switch item[0] {
			case bdbItemKeyData:
				val = item[1:]
			case bdbItemOffPage:
				if len(item) >= 12 {
					val = readOverflow(bo.Uint32(item[4:]), int(bo.Uint32(item[8:])))
				}
			}
			if len(val) < 16 { // 連番の管理用レコードなど
				continue
			}
			p, perr := ParseRPMHeader(val)
			if perr != nil {
				failed++
				continue
			}
			if len(pkgs) >= maxPackages {
				return pkgs, failed, nil
			}
			pkgs = append(pkgs, p)
		}
	}
	return pkgs, failed, nil
}
