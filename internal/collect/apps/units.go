// このファイルは、systemd のユニット（起動の定義、有効化の状態、起動コマンドの引数）の読み取り。どのアプリにも共通。

package apps

import (
	"strings"

	"kagiya/internal/model"
	"kagiya/internal/parse/unitfile"
	"kagiya/internal/ruleset"
)

// systemd のユニットファイルの置き場所（優先順）。出典: 設計書 13章（RHEL 8.10 / 9.9、Ubuntu 16.04 / 24.04 で確認）。
var unitDirs = []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"}

const systemdAdminDir = "/etc/systemd/system" // 有効化のリンク（*.wants/）とマスクが置かれる

type unitInfo struct {
	name string
	path string // 接頭辞なし
	unit *unitfile.Unit
}

// units は、アプリのユニットファイルのうち実在するものを読む。
func (c *Collector) units(app ruleset.AppRule) []unitInfo {
	var out []unitInfo
	for _, name := range app.Units {
		for _, dir := range unitDirs {
			path := dir + "/" + name
			if t, ok := c.Opener.LinkTarget(c.Prefix + path); ok && t == "/dev/null" {
				continue // マスク（起動しない設定）。定義としては読まない
			}
			data, err := c.read(path)
			if err != nil {
				continue
			}
			out = append(out, unitInfo{name: name, path: path, unit: unitfile.Parse(data)})
			break
		}
	}
	return out
}

// activity は、サービスの「利用の確からしさ」を決める。
// systemd は、*.wants / *.requires ディレクトリにユニットへのリンクがあると、起動時にそのユニットを立ち上げる。
func (c *Collector) activity(app ruleset.AppRule, units []unitInfo, hasComp bool, comp model.Component) model.Activity {
	var enabled, masked []model.Evidence
	isMasked := map[string]bool{}
	for _, name := range app.Units {
		p := c.Prefix + systemdAdminDir + "/" + name
		if t, ok := c.Opener.LinkTarget(p); ok && t == "/dev/null" {
			isMasked[name] = true
			masked = append(masked, model.Evidence{Kind: "unit-masked", Path: p, Detail: name})
		}
	}
	admin, err := c.Opener.Resolve(c.Prefix + systemdAdminDir)
	if err == nil {
		dirs, _ := c.Opener.ListNames(admin)
		for _, d := range dirs {
			if !d.IsDir || !(strings.HasSuffix(d.Name, ".wants") || strings.HasSuffix(d.Name, ".requires")) {
				continue
			}
			ents, _ := c.Opener.ListNames(admin + "/" + d.Name)
			for _, e := range ents {
				for _, name := range app.Units {
					if e.Name == name && !isMasked[name] {
						enabled = append(enabled, model.Evidence{Kind: "unit-enabled", Path: admin + "/" + d.Name + "/" + e.Name, Detail: name})
					}
				}
			}
		}
	}
	switch {
	case len(enabled) > 0:
		return model.Activity{Level: model.ActivityEnabled, Evidence: enabled}
	case len(masked) > 0:
		return model.Activity{Level: model.ActivityInstalled, Evidence: masked}
	case len(units) > 0:
		return model.Activity{Level: model.ActivityInstalled, Evidence: []model.Evidence{{Kind: "unit-present", Path: c.Prefix + units[0].path, Detail: units[0].name}}}
	case hasComp:
		return model.Activity{Level: model.ActivityInstalled, Evidence: []model.Evidence{{Kind: "binary-present", Path: comp.Path}}}
	}
	return model.Activity{Level: "unknown"}
}

// cmdArg は、ユニットの起動コマンドの語1つと、その出どころ。
type cmdArg struct {
	text string
	file string // 接頭辞なし
	line int
}

// unitArgs は、ユニットファイルの ExecStart を語に分け、環境変数を展開して返す（先頭はプログラム）。
// 環境変数は、ユニットの Environment= と、EnvironmentFile= が指すファイルから読む（後者が優先される）。
// 「$NAME」は空白で複数の語に分かれ、「${NAME}」は1語のまま展開される（systemd と同じ）。
// envVal は、ユニットの環境変数の値と、その出どころ。
type envVal struct {
	value string
	file  string
	line  int
}

// unitEnv は、ユニットの環境変数を読む（Environment= と、EnvironmentFile= が指すファイル。後者が優先される）。
func (c *Collector) unitEnv(u unitInfo) map[string]envVal {
	env := map[string]envVal{}
	for _, e := range u.unit.Values("Service", "Environment") {
		for _, w := range unitfile.Words(e) {
			if k, v, ok := strings.Cut(w.Text, "="); ok {
				env[k] = envVal{v, u.path, 0}
			}
		}
	}
	for _, ef := range u.unit.Values("Service", "EnvironmentFile") {
		ef = strings.TrimPrefix(ef, "-") // 先頭の - は「なくてもよい」の意味
		if !strings.HasPrefix(ef, "/") {
			continue
		}
		data, err := c.read(ef)
		if err != nil {
			continue
		}
		for _, e := range unitfile.ParseEnv(data) {
			env[e.Key] = envVal{e.Value, ef, e.Line} // 後から読んだファイルの値が有効
		}
	}
	return env
}

func (c *Collector) unitArgs(u unitInfo) []cmdArg {
	env := c.unitEnv(u)
	execs := u.unit.Values("Service", "ExecStart")
	if len(execs) == 0 {
		return nil
	}
	var args []cmdArg
	for _, w := range unitfile.Words(strings.TrimLeft(execs[0], "-@:+!")) {
		switch {
		case w.Variable == "":
			args = append(args, cmdArg{w.Text, u.path, 0})
		case w.Braced:
			if v, ok := env[w.Variable]; ok && v.value != "" {
				args = append(args, cmdArg{v.value, v.file, v.line})
			}
		default:
			v := env[w.Variable]
			for _, f := range strings.Fields(v.value) {
				args = append(args, cmdArg{f, v.file, v.line})
			}
		}
	}
	return args
}
