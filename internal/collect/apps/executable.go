package apps

import (
	"io"
	"path"
	"sort"
	"strconv"
	"strings"

	"kagiya/internal/parse/javacmd"
	"kagiya/internal/parse/shellconf"
)

// このファイルは、Spring Boot の「そのまま実行できる JAR」（JAR の先頭に起動スクリプトを付けたもの）の扱い。
//
// 検証ラボで、Spring Boot 2.7.18 と 3.5.16 でビルドした JAR から起動スクリプトを取り出して読んだ（どちらも同じ内容。
// 4.1.2 では、同じビルドの設定でもスクリプトは付かなかった）。スクリプトは次のように動く:
//
//   - JAR の隣（環境変数 CONF_FOLDER があれば、その場所）の <JAR の名前>.conf を、シェルとして取り込む。
//   - JAVA_HOME の下に java があれば、それを使う。なければ PATH の java。
//   - JAR のあるディレクトリで「java $JAVA_OPTS -jar <JAR> $RUN_ARGS <引数>」を起動する。
//   - 環境変数 JARFILE があれば、別の JAR を起動する。リンクを通して起動された場合は、リンクの隣の .conf も取り込む。
//
// .conf はシェルとして実行しない。「名前=値」だけを読み、値を取り出すのは JAVA_HOME / JAVA_OPTS / RUN_ARGS だけ
// （引数にパスワードを書く運用がありうるので、その値も結果には出さない）。読み切れない内容があれば、値を求めない。

// 起動スクリプトが見る環境変数のうち、どの Java で何を起動するかを決めるもの。
var execEnvNames = map[string]bool{"JAVA_HOME": true, "JAVA_OPTS": true, "RUN_ARGS": true, "CONF_FOLDER": true, "JARFILE": true}

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

// executableJar は、JAR の先頭に起動スクリプトがある場合に、起動のしかたを求める。
// 返すのは、使う起動の定義（なければ nil）と、値を求められない理由（なければ空）。
//
//   - JAR そのものを起動する定義がある: .conf と環境変数から、Java と起動時の指定を決める。
//   - java -jar で起動する定義がある: スクリプトも .conf も使われない（そのまま返す）。
//   - 起動の定義がない: スクリプトとして起動されているかは分からない。.conf に結果を変える指定があれば、値を求めない。
func (c *Collector) executableJar(f io.ReaderAt, jar string, l *javaLaunch) (*javaLaunch, string) {
	head := make([]byte, 2)
	n, _ := f.ReadAt(head, 0)
	script := n == 2 && string(head) == "#!"
	if l != nil && l.selfExec && !script {
		l = nil // スクリプトのない JAR は、そのままでは起動できない
	}
	if !script || (l != nil && !l.selfExec) {
		return l, ""
	}
	vars := map[string]string{}
	confDir := path.Dir(jar)
	if l != nil {
		switch _, other := l.execEnv["JARFILE"]; {
		case l.viaLink != "":
			return l, "the executable JAR is started through a symbolic link (" + l.viaLink + ") in " + l.name +
				"; its launch script also reads a settings file next to the link, which is not followed"
		case other:
			return l, "JARFILE in the environment of " + l.name + " makes the launch script of the executable JAR start another JAR"
		}
		for k, v := range l.execEnv {
			vars[k] = v
		}
		if d := vars["CONF_FOLDER"]; d != "" {
			if !strings.HasPrefix(d, "/") {
				return l, "CONF_FOLDER in the environment of " + l.name + " is not an absolute path; where the launch script reads its settings is not determined"
			}
			confDir = path.Clean(d)
		}
	}
	confPath := confDir + "/" + strings.TrimSuffix(path.Base(jar), path.Ext(jar)) + ".conf"
	desc := "the settings file of the launch script of the executable JAR (" + confPath + ")"
	javaFrom := ""
	if _, ok := vars["JAVA_HOME"]; ok {
		javaFrom = "JAVA_HOME in the environment of " + l.name
	}
	data, err := c.read(confPath)
	hasConf := err == nil
	if hasConf {
		r := shellconf.Parse(data, "JAVA_HOME", "JAVA_OPTS", "RUN_ARGS")
		if r.Opaque != 0 {
			return l, desc + " has a line that is not a plain assignment (line " + strconv.Itoa(r.Opaque) + "); shell commands are not interpreted"
		}
		var assigned []string
		for name := range r.Assigned {
			assigned = append(assigned, name)
		}
		sort.Strings(assigned)
		for _, name := range assigned {
			switch {
			case name == "jarfile" || springEnvRelevant(name):
				return l, desc + " sets " + name + ", which can change which JAR is started or override the TLS settings; it is not interpreted"
			case r.Unknown[name] && (name == "JAVA_OPTS" || name == "RUN_ARGS"):
				return l, desc + " sets " + name + " to a value that is not determined without running the shell"
			}
		}
		for _, name := range []string{"JAVA_HOME", "JAVA_OPTS", "RUN_ARGS"} {
			if v, ok := r.Values[name]; ok {
				vars[name] = v
			} else if r.Unknown[name] {
				delete(vars, name)
			}
		}
		if r.Assigned["JAVA_HOME"] {
			javaFrom = "JAVA_HOME in " + confPath
		}
	}
	if l == nil && !hasConf {
		return nil, ""
	}

	// スクリプトが組み立てる起動コマンド（変数は引用符なしで展開されるので、空白で語に分かれる）
	java := ""
	if h := vars["JAVA_HOME"]; strings.HasPrefix(h, "/") {
		if _, err := c.Opener.Resolve(c.Prefix + path.Clean(h) + "/bin/java"); err == nil {
			java = path.Clean(h) + "/bin/java"
		}
	}
	argv := []string{java}
	if java == "" {
		argv[0] = "/java" // 決まらない（PATH の java）。コマンドの形を確かめるための仮の名前
	}
	argv = append(argv, strings.Fields(vars["JAVA_OPTS"])...)
	argv = append(argv, "-jar", jar)
	argv = append(argv, strings.Fields(vars["RUN_ARGS"])...)
	if l != nil {
		argv = append(argv, l.args...)
	}
	cmd, ok := javacmd.Parse(argv)
	if !ok {
		return l, "JAVA_OPTS for the launch script of the executable JAR (" + confPath + ", or the environment) is not a list of Java options that is interpreted"
	}
	if l == nil {
		// 起動の定義がない: .conf が使われているかは分からない。使われた場合に結果が変わるなら、求めない
		if cmd.Risky != "" || cmd.Overrides || cmd.ProfilesSet {
			return nil, desc + " gives options (JAVA_OPTS or RUN_ARGS) that change the result if the JAR is started as a script, " +
				"and no launch definition was found that tells how the JAR is started"
		}
		return nil, ""
	}
	l.cmd = cmd
	l.workDir = path.Dir(jar)
	l.javaUnknown = java == ""
	if !l.javaUnknown {
		l.javaFrom = javaFrom
	}
	l.name += " (which starts the JAR itself"
	if hasConf {
		l.name += "; its launch script reads " + confPath
	}
	l.name += ")"
	return l, ""
}
