// Package javacmd は、Java アプリの起動コマンド（java ... -jar <JAR> ...）から、どの Java で、どの JAR を、どのプロファイルで
// 動かすかを読む。コマンドは実行しない。起動の定義（systemd のユニットなど）を語に分けたものを受け取る。
//
// 読むのは、実行ファイルのパス、JAR のパス、Spring のプロファイルの指定だけ。それ以外の指定は、TLS の設定が変わりうるものが
// 「あったかどうか」だけを返し、値は持たない（パスワードを引数で渡す運用がありうるため）。
package javacmd

import (
	"path"
	"strings"
)

// Command は、読み取った起動コマンド。
type Command struct {
	Java string // Java の実行ファイル（絶対パス）
	Jar  string // -jar の引数（絶対パスとは限らない）
	// Spring のプロファイルの指定（--spring.profiles.active、-Dspring.profiles.active）。ProfilesSet は、指定があったか
	Profiles    []string
	ProfilesSet bool
	// 空でなければ、TLS の実装や設定を変えうる Java の起動オプションがあった（その名前の先頭部分）
	Risky string
	// Spring の TLS の設定や、設定ファイルの場所を、起動時の指定で上書きしている
	Overrides bool
}

// Java の起動オプションのうち、TLS の実装や設定を変えうるもの。
var riskyOptions = []string{"-Djava.security", "-Djdk.tls", "-Djdk.security", "-Djavax.net", "-Dhttps.", "-Djava.library.path", "-Djava.ext.dirs",
	"-Xbootclasspath", "-javaagent", "-agentpath", "-agentlib", "--patch-module", "--module-path", "-Dcom.sun.net.ssl", "-Dloader.path", "-Dloader.main"}

// Spring の設定のうち、TLS の結果を変えうる項目（名前の先頭部分。正規化した形）。
var overrideKeys = []string{"server.ssl", "spring.ssl", "spring.config.location", "spring.config.additionallocation", "spring.config.import", "spring.config.name", "management.server.ssl"}

func canon(key string) string {
	key = strings.ToLower(key)
	return strings.NewReplacer("-", "", "_", "").Replace(key)
}

// property は、「名前=値」の指定を調べ、プロファイルの指定なら取り込み、TLS の設定の上書きなら記録する。
func (c *Command) property(arg string) {
	name, value, _ := strings.Cut(arg, "=")
	k := canon(name)
	if k == "spring.profiles.active" {
		c.Profiles, c.ProfilesSet = nil, true
		for _, p := range strings.Split(value, ",") {
			if p = strings.TrimSpace(p); p != "" && len(p) <= 64 && !strings.ContainsAny(p, "${} \t") {
				c.Profiles = append(c.Profiles, p)
			}
		}
		return
	}
	for _, o := range overrideKeys {
		if strings.HasPrefix(k, o) {
			c.Overrides = true
		}
	}
}

// Parse は、語に分けた起動コマンドを読む。「絶対パスの java ... -jar <.jar / .war> ...」の形でなければ ok = false。
func Parse(argv []string) (c Command, ok bool) {
	if len(argv) < 3 || !strings.HasPrefix(argv[0], "/") || path.Base(argv[0]) != "java" {
		return Command{}, false
	}
	c.Java = path.Clean(argv[0])
	i := 1
	for ; i < len(argv); i++ {
		a := argv[i]
		if a == "-jar" {
			break
		}
		if !strings.HasPrefix(a, "-") {
			return Command{}, false // -jar の前にクラス名などがある（java -jar の形ではない）
		}
		if a == "-cp" || a == "-classpath" || a == "--class-path" || a == "-p" || a == "--module-path" || a == "-m" || a == "--module" {
			return Command{}, false
		}
		for _, o := range riskyOptions {
			if strings.HasPrefix(a, o) && c.Risky == "" {
				c.Risky = o
			}
		}
		if rest, found := strings.CutPrefix(a, "-D"); found {
			c.property(rest)
		}
	}
	if i+1 >= len(argv) {
		return Command{}, false
	}
	jar := argv[i+1]
	lower := strings.ToLower(jar)
	if strings.ContainsAny(jar, "$`*?\x00\n") || !(strings.HasSuffix(lower, ".jar") || strings.HasSuffix(lower, ".war")) || len(jar) > 1024 {
		return Command{}, false
	}
	c.Jar = jar
	// JAR の後ろは、アプリへの引数。「--名前=値」は、-D の指定より優先される
	for _, a := range argv[i+2:] {
		if rest, found := strings.CutPrefix(a, "--"); found {
			c.property(rest)
		}
	}
	return c, true
}
