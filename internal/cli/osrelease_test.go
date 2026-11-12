package cli

import "testing"

// /etc/os-release から、ディストリの名前と版を読む（レポートのスキャン概要に出す）。
func TestParseOSRelease(t *testing.T) {
	d := parseOSRelease([]byte(`NAME="Red Hat Enterprise Linux"
VERSION="9.9 (Plow)"
ID="rhel"
ID_LIKE="fedora"
VERSION_ID="9.9"
PRETTY_NAME="Red Hat Enterprise Linux 9.9 (Plow)"
# comment
HOME_URL="https://www.redhat.com/"
`))
	if d == nil || d.ID != "rhel" || d.VersionID != "9.9" || d.Name != "Red Hat Enterprise Linux 9.9 (Plow)" {
		t.Fatalf("rhel = %+v", d)
	}
	// 引用符なし、単一引用符
	d = parseOSRelease([]byte("PRETTY_NAME='Ubuntu 24.04.5 LTS'\nID=ubuntu\nVERSION_ID=\"24.04\"\n"))
	if d == nil || d.ID != "ubuntu" || d.VersionID != "24.04" || d.Name != "Ubuntu 24.04.5 LTS" {
		t.Fatalf("ubuntu = %+v", d)
	}
	// PRETTY_NAME がなければ NAME と VERSION から作る
	if d := parseOSRelease([]byte("NAME=Debian\nVERSION=\"13 (trixie)\"\nID=debian\n")); d == nil || d.Name != "Debian 13 (trixie)" {
		t.Errorf("without PRETTY_NAME = %+v", d)
	}
	// 何も読めなければ nil。出力に出せない文字を含む値は採らない
	if d := parseOSRelease([]byte("garbage\n")); d != nil {
		t.Errorf("garbage = %+v", d)
	}
	if d := parseOSRelease([]byte("ID=x\nPRETTY_NAME=\"a\x01b\"\nVERSION_ID=\"<script>\"\n")); d == nil || d.Name != "" || d.VersionID != "" || d.ID != "x" {
		t.Errorf("unsafe values = %+v", d)
	}
}
