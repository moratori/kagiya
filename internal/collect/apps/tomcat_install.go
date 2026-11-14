package apps

import (
	"path"
	"strconv"
	"strings"

	"kagiya/internal/model"
	"kagiya/internal/parse/serverxml"
	"kagiya/internal/ruleset"
)

// このファイルは、Tomcat の「置かれ方」の読み取り: どのパッケージの版か、どの JDK で動くか、Tomcat Native が読み込まれるか、
// 起動時の環境（JAVA_HOME、Java の起動時の指定）。server.xml の中身の解釈は tomcat.go にある。

// tomcatInstall は、1 つの Tomcat について、Connector によらず決まること。
type tomcatInstall struct {
	app    ruleset.AppRule
	svc    model.Service
	config string // server.xml（接頭辞なし）
	base   string // CATALINA_BASE（相対パスの基準）

	pkg   model.Package
	table *ruleset.TomcatTable
	build ruleset.CipherBuild
	exact bool // 表が、導入されているパッケージ版そのものを測ったものか

	jdk    jdkContext // Tomcat を動かす JDK の表と設定
	jdkDir string

	native      tomcatNativeState
	apr, sslOff bool // AprLifecycleListener があるか、その SSLEngine が off か
}

// tomcatInstallation は、Tomcat の置かれ方を読む。どれかが分からなければ reason に理由が入る（その場合、どの Connector の値も求めない）。
func (c *Collector) tomcatInstallation(app ruleset.AppRule, svc model.Service, config string, f *serverxml.File) (in *tomcatInstall, reason string) {
	in = &tomcatInstall{app: app, svc: svc, config: config}
	if len(f.Problems) > 0 {
		reason = "server.xml is not fully read: " + f.Problems[0]
	}
	n := 0
	for _, p := range c.Builder.Packages() {
		if ruleset.MatchName(app.Packages, p.Name) {
			in.pkg = p
			n++
		}
	}
	switch {
	case reason != "":
	case n == 0:
		reason = "no package information for Tomcat; the Tomcat table to use is unknown"
	case n > 1:
		reason = "more than one Tomcat package is installed; which one this server.xml belongs to is not determined"
	default:
		var ok bool
		if in.table, in.build, in.exact, ok = c.Rules.TomcatTableFor(tomcatServer, in.pkg.Name, in.pkg.FullVersion()); !ok {
			reason = "no Tomcat table is recorded for " + in.pkg.Name + " " + in.pkg.FullVersion()
		}
	}
	// 配置。Debian 系は /etc/<名前>/server.xml で、CATALINA_BASE は /var/lib/<名前>。RHEL 系はどちらも /usr/share/tomcat
	name := path.Base(path.Dir(config))
	home := "/usr/share/" + name
	in.base = "/var/lib/" + name
	envFiles := []string{"/etc/default/" + name}
	javaHome := tomcatDebJavaHome
	if in.pkg.Manager == "rpm" {
		in.base = home
		envFiles = []string{tomcatRPMConf, tomcatRPMSysconfig}
		javaHome = ""
	}
	if reason == "" {
		javaHome, reason = c.tomcatEnvironment(envFiles, []string{in.base + "/bin/setenv.sh", home + "/bin/setenv.sh"}, javaHome)
	}
	if reason == "" {
		in.jdk, in.jdkDir, reason = c.tomcatJDK(svc, javaHome)
	}
	if reason == "" {
		in.native = c.tomcatNative(in.table)
	}
	for _, l := range f.Listeners {
		switch l.ClassName {
		case tomcatAPRListener:
			in.apr = true
			if v, ok := l.Attr["SSLEngine"]; ok && strings.EqualFold(strings.TrimSpace(v.Value), "off") {
				in.sslOff = true
			}
		case tomcatFFMListener:
			if reason == "" {
				reason = "server.xml has an OpenSSLLifecycleListener (OpenSSL through the Java foreign function interface), which has not been measured"
			}
		}
	}
	return in, reason
}

type tomcatNativeState struct {
	installed bool
	loadable  bool   // Tomcat の求める版以上で、読み込まれる
	pkg       string // 「名前 版」
	reason    string // 空でなければ、判断できない理由
}

// tomcatNative は、導入されている Tomcat Native が、この Tomcat に読み込まれるかを調べる（パッケージの版と、表の求める版を比べる）。
func (c *Collector) tomcatNative(tb *ruleset.TomcatTable) tomcatNativeState {
	var st tomcatNativeState
	for _, p := range c.Builder.Packages() {
		if !ruleset.MatchName(tomcatNativePackages, p.Name) {
			continue
		}
		if st.installed {
			return tomcatNativeState{reason: "more than one Tomcat Native package is installed; which one is loaded is not determined"}
		}
		st.installed, st.pkg = true, p.Name+" "+p.FullVersion()
		m := tomcatNativeVersion.FindStringSubmatch(p.Version)
		if m == nil {
			return tomcatNativeState{reason: "the version of the installed Tomcat Native (" + st.pkg + ") cannot be read"}
		}
		have := [3]int{}
		for i := range have {
			have[i], _ = strconv.Atoi(m[i+1])
		}
		found := false
		for _, r := range tb.NativeRequired {
			need := [3]int{}
			parts := strings.Split(r, ".")
			for i := range need {
				need[i], _ = strconv.Atoi(parts[i])
			}
			if need[0] != have[0] {
				continue
			}
			found = true
			st.loadable = have[1] > need[1] || (have[1] == need[1] && have[2] >= need[2])
		}
		if !found {
			return tomcatNativeState{reason: "the installed Tomcat Native (" + st.pkg + ") belongs to a series that has not been measured with this Tomcat version"}
		}
	}
	return st
}

// tomcatEnvironment は、起動時に読まれる環境ファイルから、JAVA_HOME と、Java の起動時の指定を調べる。
// 読むのは「名前=値」の行だけ。値を確定できない場合や、TLS の設定を変えうる指定がある場合は、reason に理由が入る。
func (c *Collector) tomcatEnvironment(files, scripts []string, javaHome string) (home, reason string) {
	for _, s := range scripts {
		if _, err := c.read(s); err == nil {
			return "", s + " exists (setenv.sh is a script and is not interpreted); it can change the JDK and the options Java is started with"
		}
	}
	for _, file := range files {
		data, err := c.read(file)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(data), "\n") {
			l = strings.TrimSpace(l)
			m := tomcatEnvLine.FindStringSubmatch(l)
			if m == nil {
				continue // コメント、空行、ほかの形の行
			}
			key, value := m[1], strings.TrimSpace(m[2])
			if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
				value = value[1 : len(value)-1]
			}
			switch {
			case key == "JAVA_HOME" || key == "JRE_HOME":
				if strings.ContainsAny(value, "$`\\\"' \t") || !strings.HasPrefix(value, "/") || len(value) > 1024 {
					return "", key + " in " + file + " is not a plain path; the JDK that runs Tomcat is not determined"
				}
				javaHome = value
			case tomcatOptionVars[key]:
				for _, o := range tomcatRiskyOptions {
					if strings.Contains(value, o) {
						return "", key + " in " + file + " has an option (" + o + "...) that can change the TLS settings of Java; its effect is not interpreted"
					}
				}
				if key == "LD_LIBRARY_PATH" {
					return "", key + " in " + file + " changes where libraries (Tomcat Native) are loaded from"
				}
			}
		}
	}
	if javaHome == "" {
		return "", "JAVA_HOME is not set in " + strings.Join(files, " or ") + "; the JDK that runs Tomcat is not determined"
	}
	return javaHome, ""
}

// tomcatJDK は、JAVA_HOME の指す JDK を探し、その対応表と設定を読む。
func (c *Collector) tomcatJDK(svc model.Service, javaHome string) (ctx jdkContext, dir, reason string) {
	var jdkApp ruleset.AppRule
	found := false
	for _, a := range c.Rules.Apps {
		if a.Grammar == "jdk" {
			jdkApp, found = a, true
		}
	}
	if !found {
		return ctx, "", "no rule for the JDK is loaded"
	}
	real, err := c.Opener.Resolve(c.Prefix + javaHome)
	if err != nil {
		return ctx, "", "JAVA_HOME (" + javaHome + ") cannot be followed to a JDK; the JDK that runs Tomcat is not determined"
	}
	real = strings.TrimPrefix(real, c.Prefix)
	// Java 9 以降は conf/security。Java 8 は jre/lib/security（JAVA_HOME が jre を指していれば lib/security）
	for _, cand := range [][2]string{{real, "/conf/security/java.security"}, {real, "/jre/lib/security/java.security"}, {path.Dir(real), "/jre/lib/security/java.security"}} {
		if cand[0] != real && path.Base(real) != "jre" {
			continue
		}
		if _, err := c.read(cand[0] + cand[1]); err != nil {
			continue
		}
		jdkApp.Direction = "inbound"
		ctx, reason = c.jdkRead(jdkApp, svc, cand[0], cand[0]+cand[1])
		if reason != "" {
			reason = "the JDK that runs Tomcat (" + cand[0] + "): " + reason
		}
		return ctx, cand[0], reason
	}
	return ctx, "", "no java.security is found under JAVA_HOME (" + javaHome + "); the JDK that runs Tomcat is not determined"
}
