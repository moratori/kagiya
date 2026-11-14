package apps

import (
	"path"
	"sort"
	"strings"

	"kagiya/internal/model"
	"kagiya/internal/parse/javacmd"
	"kagiya/internal/parse/supervisorconf"
	"kagiya/internal/parse/unitfile"
	"kagiya/internal/ruleset"
)

// このファイルは、Java アプリの起動の定義（systemd のユニット、supervisord のプログラム）の読み取り。
// 「どの Java で、どの JAR を、どんな指定で起動するか」を、ファイルから読む（実行中のプロセスは見ない）。
// init.d のスクリプト、自作の起動スクリプト、ジョブ管理ツールの定義は解釈しない。

// 環境変数のうち、TLS の設定や設定ファイルの場所を上書きするもの（名前の先頭部分）。
var springEnvOverrides = []string{"SERVER_SSL_", "SPRING_SSL_", "SPRING_CONFIG_", "SPRING_APPLICATION_JSON", "MANAGEMENT_SERVER_SSL_"}

// javaLaunch は、起動の定義から読んだ、Java アプリの起動のしかた。
type javaLaunch struct {
	name     string         // 説明に出す、起動の定義の名前（ユニット名、または supervisord のプログラム名と設定ファイル）
	activity model.Activity // 起動するよう設定されているか
	cmd      javacmd.Command
	workDir  string
	// 環境変数による指定
	envProfiles    []string
	envProfilesSet bool
	envOverride    string // 空でなければ、TLS の設定を上書きする環境変数の名前
	envRisky       string // 空でなければ、Java の起動オプションを足す環境変数に、TLS の設定を変えうる指定がある
	envUnknown     string // 空でなければ、値を確定できない環境変数（置き換えを含む）のうち、結果に関わるものの名前
	// JAR そのものを起動する定義（Spring Boot の「そのまま実行できる JAR」。executable.go を参照）
	selfExec    bool
	args        []string          // JAR の後ろの引数
	execEnv     map[string]string // 起動スクリプトが見る環境変数（execEnvNames のものだけ）
	viaLink     string            // 空でなければ、起動の定義が指すパス（リンク。JAR の実体は別の場所）
	javaFrom    string            // 空でなければ、Java の決まり方の説明（JAVA_HOME をどこから読んだか）
	javaUnknown bool              // どの Java で動くかが、起動の定義から決まらない（PATH の java）
}

// springEnvRelevant は、環境変数が、結果（プロファイル、TLS の設定、Java の起動オプション）に関わるものかを返す。
func springEnvRelevant(name string) bool {
	if name == "SPRING_PROFILES_ACTIVE" || name == "JAVA_TOOL_OPTIONS" || name == "JDK_JAVA_OPTIONS" {
		return true
	}
	for _, prefix := range springEnvOverrides {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// applyEnv は、起動の定義の環境変数を調べる（プロファイルの指定、TLS の設定の上書き、Java の起動オプションの追加）。
// unknown は、値を確定できなかった環境変数の名前。
func (l *javaLaunch) applyEnv(env map[string]string, unknown map[string]bool) {
	relevant := func(name string) bool {
		return springEnvRelevant(name) || (l.selfExec && execEnvNames[name])
	}
	for name := range unknown {
		if relevant(name) && (l.envUnknown == "" || name < l.envUnknown) {
			l.envUnknown = name
		}
	}
	for name, value := range env {
		switch {
		case l.selfExec && execEnvNames[name]:
			if l.execEnv == nil {
				l.execEnv = map[string]string{}
			}
			l.execEnv[name] = value
		case name == "SPRING_PROFILES_ACTIVE":
			l.envProfilesSet = true
			for _, p := range strings.Split(value, ",") {
				if p = strings.TrimSpace(p); p != "" {
					l.envProfiles = append(l.envProfiles, p)
				}
			}
		case name == "JAVA_TOOL_OPTIONS" || name == "JDK_JAVA_OPTIONS":
			if c2, ok := javacmd.Parse(append(append([]string{"/java"}, strings.Fields(value)...), "-jar", "x.jar")); !ok || c2.Risky != "" || c2.Overrides {
				l.envRisky = name
			}
		case relevant(name):
			if l.envOverride == "" || name < l.envOverride {
				l.envOverride = name
			}
		}
	}
}

// jarPath は、起動コマンドの JAR の絶対パスを返す（相対パスは作業ディレクトリから。決まらなければ空）。
func (l *javaLaunch) jarPath() string {
	jar := l.cmd.Jar
	if !strings.HasPrefix(jar, "/") {
		if l.workDir == "" {
			return ""
		}
		jar = l.workDir + "/" + jar
	}
	return path.Clean(jar)
}

// launchCommand は、起動の定義のコマンドを読む。「java ... -jar <JAR>」の形か、JAR そのものを起動する形（selfExec）。
func launchCommand(argv []string) (l *javaLaunch, ok bool) {
	if cmd, ok := javacmd.Parse(argv); ok {
		return &javaLaunch{cmd: cmd}, true
	}
	if len(argv) == 0 || !strings.HasPrefix(argv[0], "/") || strings.ContainsAny(argv[0], "$%{}") {
		return nil, false
	}
	if ext := path.Ext(argv[0]); ext != ".jar" && ext != ".war" {
		return nil, false
	}
	return &javaLaunch{selfExec: true, cmd: javacmd.Command{Jar: path.Clean(argv[0])}, args: argv[1:]}, true
}

// addLaunch は、起動の定義を、JAR の実体のパスごとに記録する（同じ JAR の定義が複数ある場合は、先に見つかったものを使う）。
func (c *Collector) addLaunch(out map[string]*javaLaunch, l *javaLaunch) {
	jar := l.jarPath()
	if jar == "" {
		return // 相対パスの JAR は、作業ディレクトリが分からなければ決まらない
	}
	if real, err := c.Opener.Resolve(c.Prefix + jar); err == nil {
		if real = strings.TrimPrefix(real, c.Prefix); real != jar {
			l.viaLink, jar = jar, real
		}
	}
	if _, dup := out[jar]; !dup {
		out[jar] = l
	}
}

// javaLaunches は、systemd のユニットのうち「java ... -jar <JAR>」で起動するもの（と、JAR そのものを起動するもの）を、JAR のパスごとに返す。
// 同じ JAR を起動するユニットが複数ある場合は、名前の順で最初のものを使う。
func (c *Collector) javaLaunches() map[string]*javaLaunch {
	out := map[string]*javaLaunch{}
	seen := map[string]bool{}
	count := 0
	for _, dir := range unitDirs {
		real, err := c.Opener.Resolve(c.Prefix + dir)
		if err != nil {
			continue
		}
		ents, err := c.Opener.ListNames(real)
		if err != nil {
			continue
		}
		sort.Slice(ents, func(i, j int) bool { return ents[i].Name < ents[j].Name })
		for _, e := range ents {
			if e.IsDir || !strings.HasSuffix(e.Name, ".service") || seen[e.Name] || count >= springMaxUnits {
				continue
			}
			seen[e.Name] = true // 先に見つかった場所（/etc/systemd/system）の定義が有効
			p := dir + "/" + e.Name
			if t, ok := c.Opener.LinkTarget(c.Prefix + p); ok && t == "/dev/null" {
				continue // マスクされている
			}
			data, err := c.read(p)
			if err != nil {
				continue
			}
			count++
			u := unitInfo{name: e.Name, path: p, unit: unitfile.Parse(data)}
			var argv []string
			for _, a := range c.unitArgs(u) {
				argv = append(argv, a.text)
			}
			l, ok := launchCommand(argv)
			if !ok {
				continue
			}
			tmp := ruleset.AppRule{Units: []string{u.name}}
			l.name, l.activity = u.name, c.activity(tmp, []unitInfo{u}, false, model.Component{})
			if wd := u.unit.Values("Service", "WorkingDirectory"); len(wd) > 0 && strings.HasPrefix(wd[len(wd)-1], "/") {
				l.workDir = path.Clean(wd[len(wd)-1])
			}
			env := map[string]string{}
			for name, v := range c.unitEnv(u) {
				env[name] = v.value
			}
			l.applyEnv(env, nil)
			c.addLaunch(out, l)
		}
	}
	c.supervisorLaunches(out)
	return out
}

// supervisord の設定ファイルの置き場（Debian / Ubuntu の supervisor パッケージで確かめた。本体の設定が conf.d/*.conf を取り込む）。
var supervisorFiles = []string{"/etc/supervisor/supervisord.conf", "/etc/supervisor/conf.d/*.conf"}

const supervisorUnit = "supervisor.service"

// supervisorLaunches は、supervisord のプログラムのうち「java ... -jar <JAR>」で起動するものを、out に足す（systemd のユニットの定義がある JAR は、そちらを使う）。
func (c *Collector) supervisorLaunches(out map[string]*javaLaunch) {
	var files []string
	for _, pattern := range supervisorFiles {
		if strings.Contains(pattern, "*") {
			files = append(files, c.globDeep(pattern)...)
		} else {
			files = append(files, pattern)
		}
	}
	// supervisord そのものが、起動するよう設定されているか
	enabled := c.activity(ruleset.AppRule{Units: []string{supervisorUnit}}, nil, false, model.Component{})
	for _, file := range files {
		data, err := c.read(file)
		if err != nil {
			continue
		}
		for _, p := range supervisorconf.Parse(data) {
			if p.Unexpanded {
				continue // 置き換え（%(...)s）があると、どの JAR を起動するのか決まらない
			}
			l, ok := launchCommand(p.Argv)
			if !ok {
				continue
			}
			l.name, l.workDir = "the supervisord program "+p.Name+" ("+file+")", p.Directory
			l.activity = model.Activity{Level: model.ActivityInstalled, Evidence: []model.Evidence{{Kind: "supervisor-program", Path: c.Prefix + file, Detail: p.Name}}}
			if p.Autostart && enabled.Level == model.ActivityEnabled {
				l.activity = model.Activity{Level: model.ActivityEnabled, Evidence: append(enabled.Evidence, l.activity.Evidence...)}
			}
			l.applyEnv(p.Env, p.EnvUnexpanded)
			c.addLaunch(out, l)
		}
	}
}
