// Package apps は、サーバーアプリケーションの設定を読むコレクタ。
//
// 設定ファイルに明記された暗号関連の値を、どこに書かれていたかとともに記録する。
// あわせて、サービスが起動するよう設定されているか（利用の確からしさ）を、systemd の定義から読む。
// アプリのコマンド（sshd -T など）や systemctl は実行しない。
//
// このファイルは、どのアプリにも共通の部分（アプリの発見、起動定義と有効化状態、設定値の検証と記録）。
// アプリごとの設定の意味（どの記載が効くか、引き継ぎ、実効値の解決）は、アプリ別のファイルに分けている
// （sshd.go、nginx.go、apache.go）。版やディストリで変わる値は、コードではなくルール（rules/）に持つ。
package apps

import (
	"strings"

	"kagiya/internal/inventory"
	"kagiya/internal/model"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

const (
	maxConfigSize   = 1 << 20 // 読む設定ファイルの大きさの上限
	maxSettingValue = 8192    // 記録する設定値の長さの上限
)

type Collector struct {
	Prefix  string // テスト用。通常は空
	Opener  *safefs.Opener
	Builder *inventory.Builder
	Rules   *ruleset.RuleSet
}

func (c *Collector) Collect() {
	for _, app := range c.Rules.Apps {
		if app.Grammar == "" {
			continue
		}
		c.application(app)
	}
}

func (c *Collector) read(path string) ([]byte, error) {
	return c.Opener.ReadFile(c.Prefix+path, maxConfigSize)
}

// confFS は、設定ファイルの中に書かれたパス（接頭辞なし）を、安全なファイルアクセスを通して読む。
type confFS struct{ c *Collector }

func (f confFS) ReadFile(p string) ([]byte, error) { return f.c.read(p) }

func (f confFS) Glob(pattern string) ([]string, error) {
	files, err := f.c.Opener.Glob(f.c.Prefix + pattern)
	for i := range files {
		files[i] = strings.TrimPrefix(files[i], f.c.Prefix)
	}
	return files, err
}

func (c *Collector) application(app ruleset.AppRule) {
	config := ""
	for _, p := range app.ConfigFiles {
		if _, err := c.read(p); err == nil {
			config = p
			break
		}
	}
	comp, hasComp := c.Builder.FindComponent("app:" + app.ID + ":")
	units := c.units(app)
	if config == "" && !hasComp && len(units) == 0 {
		return
	}
	svc := model.Service{ID: "svc:" + app.ID, App: app.ID}
	if hasComp {
		svc.Component = comp.ID
	}
	if config != "" {
		svc.ConfigFiles = []string{c.Prefix + config}
	}
	svc.Activity = c.activity(app, units, hasComp, comp)
	c.Builder.AddService(svc)

	switch app.Grammar {
	case "sshd":
		c.sshd(app, svc, config, units)
	case "nginx":
		c.nginx(app, svc, config)
	case "apache":
		c.apache(app, svc, config)
	case "haproxy":
		c.haproxy(app, svc, config, units)
	}
}
