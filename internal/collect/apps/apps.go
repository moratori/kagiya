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
	"path"
	"sort"
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
		if strings.Contains(p, "*") {
			// 名前が決まっていない設定ファイル（「/etc/stunnel/*.conf」など）。当てはまるもののうち、名前の順で最初のもの
			if files := c.globDeep(p); len(files) > 0 {
				sort.Strings(files)
				config = files[0]
				break
			}
			continue
		}
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
	// MariaDB と MySQL は同じ設定ファイル（/etc/my.cnf）を使い、このファイルはクライアントだけの環境にもある。
	// 設定ファイルがあるだけでは、どちらのサーバーがあるとも言えないので、本体・ユニット・パッケージのいずれかがある場合に限る
	if app.Grammar == "mycnf" && !hasComp && len(units) == 0 && !c.hasPackage(app) {
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
	case "stunnel":
		c.stunnel(app, svc)
	case "postfix":
		c.postfix(app, svc, config)
	case "postgresql":
		c.postgresql(app, svc, config)
	case "dovecot":
		c.dovecot(app, svc, config)
	case "mycnf":
		c.mysql(app, svc, config)
	case "jdk":
		c.jdk(app, svc)
	case "tomcat":
		c.tomcat(app, svc, config)
	}
}

// globDeep は、途中のディレクトリにもワイルドカードを含むパターン（「/etc/postgresql/*/*/postgresql.conf」など）に合うファイルを返す。
// 途中のディレクトリは 1 段ずつ列挙して展開し、最後の要素は Glob に任せる（どちらも、安全なファイルアクセスを通す）。
func (c *Collector) globDeep(pattern string) []string {
	const maxDirs = 64
	parts := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	dirs := []string{""}
	for _, seg := range parts[:len(parts)-1] {
		if !strings.ContainsAny(seg, "*?[") {
			for i := range dirs {
				dirs[i] += "/" + seg
			}
			continue
		}
		var next []string
		for _, d := range dirs {
			real, err := c.Opener.Resolve(c.Prefix + d)
			if err != nil {
				continue
			}
			ents, err := c.Opener.ListNames(real)
			if err != nil {
				continue
			}
			for _, e := range ents {
				if ok, _ := path.Match(seg, e.Name); ok && e.IsDir && len(next) < maxDirs {
					next = append(next, d+"/"+e.Name)
				}
			}
		}
		dirs = next
	}
	var out []string
	for _, d := range dirs {
		files, _ := (confFS{c}).Glob(d + "/" + parts[len(parts)-1])
		out = append(out, files...)
	}
	sort.Strings(out)
	return out
}
