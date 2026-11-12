package pkgdb

import (
	"encoding/binary"
	"io"
)

// rpm の SQLite データベース（rpmdb.sqlite）の読み取り。RHEL 9 系以降の rpm が使う。
// SQLite のライブラリは使わず、ファイル形式を直接読む（テーブル Packages の blob 列だけが必要なため）。
//
// 変更が先行書き込みログ（rpmdb.sqlite-wal）に入ったまま本体ファイルに反映されていないことがあるので、
// WAL がある場合は、その確定済みの内容を本体より優先して読む。

const (
	sqliteHeaderSize = 100
	sqliteMaxDepth   = 32
	walHeaderSize    = 32
	walFrameHeader   = 24
	maxWALSize       = 512 << 20
)

type sqliteDB struct {
	r        io.ReaderAt
	pageSize int
	usable   int
	npages   uint32
	wal      map[uint32][]byte // WAL で上書きされたページ
	budget   int               // 読めるページ数の残り（循環した壊れたデータベースで止まらなくなるのを防ぐ）
}

func (d *sqliteDB) page(n uint32) ([]byte, bool) {
	if n == 0 || n > d.npages || d.budget <= 0 {
		return nil, false
	}
	d.budget--
	if p, ok := d.wal[n]; ok {
		return p, true
	}
	p := make([]byte, d.pageSize)
	if _, err := d.r.ReadAt(p, int64(n-1)*int64(d.pageSize)); err != nil {
		return nil, false
	}
	return p, true
}

func varint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < len(b) && i < 9; i++ {
		if i == 8 {
			return v<<8 | uint64(b[i]), 9
		}
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
	}
	return 0, 0
}

// ReadRPMSQLite は rpmdb.sqlite から全パッケージを読む。wal は rpmdb.sqlite-wal（なければ nil）。
func ReadRPMSQLite(db io.ReaderAt, dbSize int64, wal io.ReaderAt, walSize int64) (pkgs []Package, failed int, err error) {
	hdr := make([]byte, sqliteHeaderSize)
	if _, err := db.ReadAt(hdr, 0); err != nil || string(hdr[:16]) != "SQLite format 3\x00" {
		return nil, 0, errFormat
	}
	pageSize := int(binary.BigEndian.Uint16(hdr[16:]))
	if pageSize == 1 {
		pageSize = 65536
	}
	if pageSize < 512 || pageSize > 65536 || pageSize&(pageSize-1) != 0 {
		return nil, 0, errFormat
	}
	d := &sqliteDB{r: db, pageSize: pageSize, usable: pageSize - int(hdr[20])}
	if d.usable < 480 {
		return nil, 0, errFormat
	}
	d.npages = uint32(dbSize / int64(pageSize))
	if wal != nil && walSize > walHeaderSize {
		pages, n := loadWAL(wal, walSize, pageSize)
		if len(pages) > 0 {
			d.wal, d.npages = pages, n
		}
	}
	d.budget = int(d.npages)*4 + 1024

	// スキーマ表（1ページ目が根）から、テーブル Packages の根ページを探す。
	var root uint32
	d.walkTable(1, 0, func(payload []byte) bool {
		cols := record(payload)
		if len(cols) >= 4 && string(cols[0].data) == "table" && string(cols[1].data) == "Packages" {
			root = uint32(cols[3].integer)
			return false
		}
		return true
	})
	if root == 0 {
		return nil, 0, errFormat
	}
	d.walkTable(root, 0, func(payload []byte) bool {
		for _, c := range record(payload) {
			if !c.blob {
				continue
			}
			p, perr := ParseRPMHeader(c.data)
			if perr != nil {
				failed++
			} else {
				pkgs = append(pkgs, p)
			}
			break
		}
		return len(pkgs) < maxPackages
	})
	return pkgs, failed, nil
}

// walkTable はテーブルの B 木を辿り、行ごとに fn を呼ぶ。fn が false を返したら打ち切る。
func (d *sqliteDB) walkTable(pgno uint32, depth int, fn func(payload []byte) bool) bool {
	if depth > sqliteMaxDepth {
		return true
	}
	p, ok := d.page(pgno)
	if !ok {
		return true
	}
	h := 0
	if pgno == 1 {
		h = sqliteHeaderSize
	}
	if h+12 > len(p) {
		return true
	}
	ncell := int(binary.BigEndian.Uint16(p[h+3:]))
	switch p[h] {
	case 0x05: // 内部ページ: 各セルは左の子と行番号。最後に右端の子。
		for i := 0; i < ncell; i++ {
			ptr := h + 12 + 2*i
			if ptr+2 > len(p) {
				break
			}
			c := int(binary.BigEndian.Uint16(p[ptr:]))
			if c+4 > len(p) {
				continue
			}
			if !d.walkTable(binary.BigEndian.Uint32(p[c:]), depth+1, fn) {
				return false
			}
		}
		return d.walkTable(binary.BigEndian.Uint32(p[h+8:]), depth+1, fn)
	case 0x0d: // 葉ページ: 各セルは「内容の長さ、行番号、内容」
		for i := 0; i < ncell; i++ {
			ptr := h + 8 + 2*i
			if ptr+2 > len(p) {
				break
			}
			c := int(binary.BigEndian.Uint16(p[ptr:]))
			if c <= 0 || c >= len(p) {
				continue
			}
			total, n1 := varint(p[c:])
			if n1 == 0 || total > maxBlob {
				continue
			}
			_, n2 := varint(p[c+n1:])
			if n2 == 0 {
				continue
			}
			payload := d.payload(p, c+n1+n2, int(total))
			if payload != nil && !fn(payload) {
				return false
			}
		}
	}
	return true
}

// payload はセルの内容を、オーバーフローページの連鎖も含めて取り出す。
func (d *sqliteDB) payload(p []byte, start, total int) []byte {
	u := d.usable
	local := total
	if x := u - 35; total > x {
		m := (u-12)*32/255 - 23
		local = m + (total-m)%(u-4)
		if local > x {
			local = m
		}
	}
	if local < 0 || start+local > len(p) {
		return nil
	}
	if local == total {
		return p[start : start+local]
	}
	if start+local+4 > len(p) {
		return nil
	}
	out := make([]byte, 0, total)
	out = append(out, p[start:start+local]...)
	next := binary.BigEndian.Uint32(p[start+local:])
	for next != 0 && len(out) < total {
		op, ok := d.page(next)
		if !ok {
			return nil
		}
		n := u - 4
		if rest := total - len(out); n > rest {
			n = rest
		}
		out = append(out, op[4:4+n]...)
		next = binary.BigEndian.Uint32(op[0:])
	}
	if len(out) != total {
		return nil
	}
	return out
}

type column struct {
	data    []byte
	integer int64
	blob    bool
}

// record は行の内容（レコード形式）を列に分解する。
func record(b []byte) []column {
	hsize, n := varint(b)
	if n == 0 || hsize > uint64(len(b)) || int(hsize) < n {
		return nil
	}
	types := b[n:hsize]
	body := b[hsize:]
	var cols []column
	for len(types) > 0 && len(cols) < 64 {
		t, tn := varint(types)
		if tn == 0 {
			return nil
		}
		types = types[tn:]
		var size int
		var c column
		switch {
		case t >= 1 && t <= 4:
			size = int(t)
		case t == 5:
			size = 6
		case t == 6 || t == 7:
			size = 8
		case t == 9:
			c.integer = 1
		case t >= 12:
			size = int((t - 12) / 2)
			c.blob = t%2 == 0
		}
		if size < 0 || size > len(body) {
			return nil
		}
		c.data = body[:size]
		if t >= 1 && t <= 6 {
			var v int64
			for i, x := range c.data {
				if i == 0 {
					v = int64(int8(x))
				} else {
					v = v<<8 | int64(x)
				}
			}
			c.integer = v
			c.data = nil
		}
		body = body[size:]
		cols = append(cols, c)
	}
	return cols
}

// loadWAL は WAL の確定済みフレームを読み、上書きされたページと、確定時点のデータベースのページ数を返す。
// 識別値（ソルト）やチェックサムが合わないフレームに出会ったら、そこで打ち切る（それ以降は無効なデータ）。
func loadWAL(r io.ReaderAt, size int64, pageSize int) (map[uint32][]byte, uint32) {
	if size > maxWALSize {
		return nil, 0
	}
	h := make([]byte, walHeaderSize)
	if _, err := r.ReadAt(h, 0); err != nil {
		return nil, 0
	}
	magic := binary.BigEndian.Uint32(h[0:])
	if magic != 0x377f0682 && magic != 0x377f0683 {
		return nil, 0
	}
	if int(binary.BigEndian.Uint32(h[8:])) != pageSize {
		return nil, 0
	}
	var bo binary.ByteOrder = binary.LittleEndian
	if magic&1 == 1 {
		bo = binary.BigEndian
	}
	var s0, s1 uint32
	sum := func(b []byte) {
		for i := 0; i+8 <= len(b); i += 8 {
			s0 += bo.Uint32(b[i:]) + s1
			s1 += bo.Uint32(b[i+4:]) + s0
		}
	}
	sum(h[:24])
	if s0 != binary.BigEndian.Uint32(h[24:]) || s1 != binary.BigEndian.Uint32(h[28:]) {
		return nil, 0
	}
	salt := string(h[16:24])

	committed := map[uint32][]byte{}
	pending := map[uint32][]byte{}
	var dbPages uint32
	frame := make([]byte, walFrameHeader+pageSize)
	for off := int64(walHeaderSize); off+int64(len(frame)) <= size; off += int64(len(frame)) {
		if _, err := r.ReadAt(frame, off); err != nil {
			break
		}
		if string(frame[8:16]) != salt {
			break
		}
		sum(frame[:8])
		sum(frame[walFrameHeader:])
		if s0 != binary.BigEndian.Uint32(frame[16:]) || s1 != binary.BigEndian.Uint32(frame[20:]) {
			break
		}
		pgno := binary.BigEndian.Uint32(frame[0:])
		pending[pgno] = append([]byte(nil), frame[walFrameHeader:]...)
		if n := binary.BigEndian.Uint32(frame[4:]); n != 0 { // 確定フレーム
			for k, v := range pending {
				committed[k] = v
			}
			pending = map[uint32][]byte{}
			dbPages = n
		}
	}
	if dbPages == 0 {
		return nil, 0
	}
	return committed, dbPages
}
