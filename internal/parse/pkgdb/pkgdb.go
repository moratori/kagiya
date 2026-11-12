// Package pkgdb は OS のパッケージ管理データベース（rpm、dpkg）から、導入済みパッケージの名前と版を読む。
//
// rpm や dpkg のコマンドは実行しない。データベースのファイルを読み取り専用で直接解析する。
// 稼働中のシステムではデータベースが更新途中のことがあるため、整合しない部分は読み飛ばして件数を報告する。
package pkgdb

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

// Package は導入済みパッケージ1つ。
type Package struct {
	Name    string
	Epoch   int    // rpm のエポック（なければ 0）。dpkg では Version にエポックが含まれる
	Version string // rpm: バージョン。dpkg: 「エポック:上流版-リビジョン」の全体
	Release string // rpm のリリース（ディストリによる改変を識別する部分）
	Arch    string

	SourceRPM     string // rpm: ソースパッケージのファイル名
	SourceName    string // dpkg: ソースパッケージ名（省略時はパッケージ名と同じ）
	SourceVersion string // dpkg: ソースパッケージの版（省略時は Version と同じ）
	Vendor        string
	License       string

	Status    string // dpkg の状態（"install ok installed" など）
	Installed bool   // 導入済みか（設定ファイルだけが残っている状態などは false）
}

var errFormat = errors.New("pkgdb: unexpected format")

const (
	maxBlob     = 64 << 20 // パッケージ1件のヘッダとして受け付ける上限
	maxPackages = 1_000_000
	maxString   = 4096
)

// ---- rpm ヘッダ ----

const (
	rpmTagName      = 1000
	rpmTagVersion   = 1001
	rpmTagRelease   = 1002
	rpmTagEpoch     = 1003
	rpmTagVendor    = 1011
	rpmTagLicense   = 1014
	rpmTagArch      = 1022
	rpmTagSourceRPM = 1044

	rpmTypeInt32      = 4
	rpmTypeString     = 6
	rpmTypeI18NString = 9
)

// ParseRPMHeader は rpm データベースに格納されたパッケージヘッダ（索引の件数、データ長、索引、データ）を読む。
func ParseRPMHeader(b []byte) (Package, error) {
	var p Package
	if len(b) < 16 {
		return p, errFormat
	}
	il := int(binary.BigEndian.Uint32(b[0:]))
	dl := int(binary.BigEndian.Uint32(b[4:]))
	if il <= 0 || il > 65535 || dl <= 0 || dl > maxBlob {
		return p, errFormat
	}
	need := 8 + 16*il + dl
	if need > len(b) {
		return p, errFormat
	}
	data := b[8+16*il : need]
	str := func(off int) string {
		if off < 0 || off >= len(data) {
			return ""
		}
		s := data[off:]
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
	for i := 0; i < il; i++ {
		e := b[8+16*i:]
		tag := binary.BigEndian.Uint32(e[0:])
		typ := binary.BigEndian.Uint32(e[4:])
		off := int(int32(binary.BigEndian.Uint32(e[8:])))
		isStr := typ == rpmTypeString || typ == rpmTypeI18NString
		switch tag {
		case rpmTagName:
			if isStr {
				p.Name = str(off)
			}
		case rpmTagVersion:
			if isStr {
				p.Version = str(off)
			}
		case rpmTagRelease:
			if isStr {
				p.Release = str(off)
			}
		case rpmTagArch:
			if isStr {
				p.Arch = str(off)
			}
		case rpmTagSourceRPM:
			if isStr {
				p.SourceRPM = str(off)
			}
		case rpmTagVendor:
			if isStr {
				p.Vendor = str(off)
			}
		case rpmTagLicense:
			if isStr {
				p.License = str(off)
			}
		case rpmTagEpoch:
			if typ == rpmTypeInt32 && off >= 0 && off+4 <= len(data) {
				p.Epoch = int(int32(binary.BigEndian.Uint32(data[off:])))
			}
		}
	}
	if p.Name == "" || p.Version == "" {
		return p, errFormat
	}
	p.Installed = true
	return p, nil
}

// clean は制御文字を取り除く（パッケージ情報は出力に載るため）。
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0xFFFD {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
}

// ---- dpkg ----

// ParseDpkgStatus は dpkg の状態ファイル（/var/lib/dpkg/status）を読む。
func ParseDpkgStatus(r io.Reader) ([]Package, error) {
	var out []Package
	var cur Package
	var srcField string
	flush := func() {
		if cur.Name != "" {
			cur.SourceName, cur.SourceVersion = cur.Name, cur.Version
			if srcField != "" {
				name, rest, _ := strings.Cut(srcField, " ")
				cur.SourceName = name
				if v := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(rest), "("), ")"); v != "" {
					cur.SourceVersion = v
				}
			}
			cur.Installed = cur.Status == "install ok installed"
			if len(out) < maxPackages {
				out = append(out, cur)
			}
		}
		cur, srcField = Package{}, ""
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue // 前の項目の続き（説明文など）
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		val = clean(strings.TrimSpace(val))
		if len(val) > maxString {
			val = val[:maxString]
		}
		switch key {
		case "Package":
			cur.Name = val
		case "Status":
			cur.Status = val
		case "Version":
			cur.Version = val
		case "Architecture":
			cur.Arch = val
		case "Source":
			srcField = val
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return out, err
	}
	return out, nil
}
