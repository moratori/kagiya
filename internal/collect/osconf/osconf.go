// Package osconf は、OS 全体の暗号設定を読むコレクタ。
//
// 実際に使われる暗号は「アプリの設定 ＞ OS の暗号ポリシー ＞ ライブラリの既定値」で決まる。
// ここでは真ん中の層にあたる、システム全体の暗号ポリシーと、暗号ライブラリのシステム既定の設定を読む。
// update-crypto-policies や openssl などのコマンドは実行しない。
package osconf

import (
	"errors"
	"regexp"
	"strings"

	"kagiya/internal/inventory"
	"kagiya/internal/model"
	"kagiya/internal/parse/opensslcnf"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

const (
	maxConfigSize = 1 << 20
	maxValueLen   = 4096
)

// 置き場所の出典: 設計書 13章「Phase 1b に向けて実物から採取した事実」（RHEL 8.10 / 9.9 で確認）。
const (
	cryptoPolicyConfig  = "/etc/crypto-policies/config"        // 管理者が選んだポリシー名
	cryptoPolicyCurrent = "/etc/crypto-policies/state/current" // 実際に適用済みのポリシー名
	fipsEnabled         = "/proc/sys/crypto/fips_enabled"      // カーネルの FIPS モード
)

var (
	policyName   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_@+-]{0,127}$`)
	settingValue = regexp.MustCompile(`^[A-Za-z0-9_:+!@=.,*~?/ -]+$`)
)

type Collector struct {
	Prefix  string // テスト用。通常は空
	Opener  *safefs.Opener
	Builder *inventory.Builder
	Rules   *ruleset.RuleSet
}

func (c *Collector) Collect() {
	c.cryptoPolicies()
	c.fips()
	for _, lib := range c.Rules.Libraries {
		if lib.ID == "openssl" {
			c.openssl(lib)
		}
	}
}

// read は、リンクを辿って実体を開き、上限まで読む。大きさが 0 と報告される擬似ファイルも読める。
func (c *Collector) read(path string) ([]byte, error) {
	real, err := c.Opener.Resolve(path)
	if err != nil {
		return nil, err
	}
	f, err := c.Opener.Open(real)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 4096)
	for len(buf) <= maxConfigSize {
		n, err := f.ReadAt(chunk, int64(len(buf)))
		buf = append(buf, chunk[:n]...)
		if err != nil || n == 0 {
			break
		}
	}
	if len(buf) > maxConfigSize {
		return nil, errors.New("file is too large")
	}
	return buf, nil
}

func (c *Collector) reject(path, what string) {
	c.Builder.Skip(safefs.Skip{Path: path, Reason: "invalid-value", Detail: what})
}

// firstLine は、コメントと空行を除いた最初の行と、その行番号を返す。
func firstLine(data []byte) (string, int) {
	for i, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			return l, i + 1
		}
	}
	return "", 0
}

func (c *Collector) cryptoPolicies() {
	// 決まった順に調べる（結果の並びが、実行のたびに変わらないように）
	for _, item := range [][2]string{{"crypto-policies.policy", cryptoPolicyConfig}, {"crypto-policies.applied", cryptoPolicyCurrent}} {
		id, p := item[0], item[1]
		path := c.Prefix + p
		data, err := c.read(path)
		if err != nil {
			continue
		}
		v, line := firstLine(data)
		if !policyName.MatchString(v) {
			c.reject(path, id)
			continue
		}
		c.Builder.AddOSSetting(model.OSSetting{ID: id, Value: v, Path: path, Line: line})
	}
}

func (c *Collector) fips() {
	path := c.Prefix + fipsEnabled
	data, err := c.read(path)
	if err != nil {
		return
	}
	if v := strings.TrimSpace(string(data)); v == "0" || v == "1" {
		c.Builder.AddOSSetting(model.OSSetting{ID: "kernel.fips_enabled", Value: v, Path: path})
	}
}

// confFS は、設定ファイルの中に書かれたパス（接頭辞なし）を、安全なファイルアクセスを通して読む。
type confFS struct{ c *Collector }

func (f confFS) ReadFile(p string) ([]byte, error) { return f.c.read(f.c.Prefix + p) }

func (f confFS) ListDir(p string) ([]string, error) {
	real, err := f.c.Opener.Resolve(f.c.Prefix + p)
	if err != nil {
		return nil, err
	}
	names, err := f.c.Opener.ReadDir(real)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = p + "/" + n
	}
	return out, nil
}

func (c *Collector) openssl(lib ruleset.LibraryRule) {
	for _, cnf := range lib.ConfigFiles {
		res, err := opensslcnf.SystemDefault(cnf, confFS{c})
		if err != nil { // 存在しない、または読めない（読めない理由は記録済み）
			continue
		}
		path := c.Prefix + cnf
		c.Builder.AddOSSetting(model.OSSetting{ID: "openssl.config_file", Value: path, Path: path})
		// 問題の内容は定型の文言だけ（設定ファイルの中身は含めない）
		for _, pr := range res.Problems {
			c.Builder.Skip(safefs.Skip{Path: path, Reason: "config-problem", Detail: pr})
		}
		state := "not-configured"
		if len(res.Sections) == 3 {
			state = "configured"
		}
		c.Builder.AddOSSetting(model.OSSetting{ID: "openssl.system_default", Value: state, Path: path})
		for _, e := range res.SystemDefault {
			file := c.Prefix + e.File
			// 許可リストにない項目は記録しない。値は、設定値として妥当な文字だけからなるものに限る。
			if !ruleset.MatchName(lib.SystemDefaultKeys, e.Key) {
				c.Builder.Skip(safefs.Skip{Path: file, Reason: "unrecognized-setting", Detail: "openssl system default"})
				continue
			}
			if len(e.Value) > maxValueLen || !settingValue.MatchString(e.Value) {
				c.reject(file, "openssl.system_default."+e.Key)
				// 「書かれているが読めていない」ことを残す（項目の名前は許可リストにあるもの）
				c.Builder.AddOSSetting(model.OSSetting{ID: model.OSSettingOpenSSLUnread, Value: e.Key, Path: file, Line: e.Line})
				continue
			}
			c.Builder.AddOSSetting(model.OSSetting{ID: "openssl.system_default." + e.Key, Value: e.Value, Path: file, Line: e.Line})
		}
		return // 最初に見つかった設定ファイルを使う
	}
}
