package apps

import (
	"regexp"
	"strings"

	"kagiya/internal/model"
	"kagiya/internal/parse/jarfile"
	"kagiya/internal/parse/standalonexml"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

// このファイルは、WildFly の「置かれ方」の読み取り: どこに置かれているか、どの版か、どの設定ファイルで起動するか（systemd のユニット）、
// どの JDK で動くか。待ち受けごとの TLS の設定の解釈は、wildfly.go にある。

const (
	wildflyConfigDir    = "/standalone/configuration"
	wildflyConfigSuffix = wildflyConfigDir + "/standalone.xml"
	wildflyProductDir   = "/modules/system/layers/base/org/jboss/as/product/main"
	wildflyMaxHomes     = 16
	wildflyMaxManifest  = 64 << 10
	wildflyUnmeasured   = "wildfly" // 「測定が要る版」での種類と名前
)

var (
	wildflyVersionValue = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[A-Za-z0-9]{1,16}$`)
	wildflyConfigName   = regexp.MustCompile(`^standalone[A-Za-z0-9._-]{0,64}\.xml$`)
	wildflyJavaAssign   = regexp.MustCompile(`^(?:export\s+)?(JAVA_HOME|JAVA)=(.*)$`)
	wildflyProductJar   = regexp.MustCompile(`^wildfly-feature-pack-product-conf-[A-Za-z0-9._-]{1,64}\.jar$`)
	// 製品の JAR は、マニフェストだけが入った小さなもの
	wildflyJarLimits = jarfile.Limits{MaxArchiveSize: 1 << 20, MaxEntries: 256, MaxNameLen: 256, MaxEntrySize: wildflyMaxManifest, MaxRatio: 200}
)

// wildflyLaunch は、systemd のユニットから読んだ、WildFly の起動のしかた。
type wildflyLaunch struct {
	unit   unitInfo
	config string // 設定ファイルの名前（指定がなければ空）
	domain bool   // ドメインのモードで起動する
	reason string // 空でなければ、設定ファイルを決められない理由
}

// wildfly は、置かれている WildFly を探し、1 つずつ調べる。
func (c *Collector) wildfly(app ruleset.AppRule) {
	launches := c.wildflyLaunches(app)
	var homes []string
	seen := map[string]bool{}
	add := func(home string) {
		// 同じ場所を指す別の名前（/opt/wildfly → /opt/wildfly-42.0.0.Final のようなリンク）は、1 つにまとめる
		key := home
		if real, err := c.Opener.Resolve(c.Prefix + home); err == nil {
			key = real
		}
		if home == "" || seen[key] || len(homes) >= wildflyMaxHomes {
			return
		}
		seen[key] = true
		homes = append(homes, home)
	}
	var found []string
	for _, p := range app.ConfigFiles {
		for _, f := range c.globDeep(p) {
			if home := strings.TrimSuffix(f, wildflyConfigSuffix); home != f {
				found = append(found, home)
			}
		}
	}
	// ユニットが起動する場所を先に（リンクでまとめるとき、ユニットに書かれた名前を残す）
	for _, home := range found {
		if _, ok := launches[home]; ok {
			add(home)
		}
	}
	for _, home := range found {
		add(home)
	}
	for _, home := range homes {
		l, launched := launches[home]
		c.wildflyHome(app, home, l, launched)
	}
}

// wildflyLaunches は、WildFly を起動するユニットを、置き場所ごとに返す。
// 読めるのは、配布物に付いている形（<置き場所>/bin/launch.sh モード 設定ファイル 待ち受けアドレス）と、standalone.sh / domain.sh を直接起動する形。
func (c *Collector) wildflyLaunches(app ruleset.AppRule) map[string]wildflyLaunch {
	out := map[string]wildflyLaunch{}
	for _, u := range c.units(app) {
		args := c.unitArgs(u)
		if len(args) == 0 {
			continue
		}
		l := wildflyLaunch{unit: u}
		prog := args[0].text
		home := ""
		switch {
		case strings.HasSuffix(prog, "/bin/launch.sh"):
			home = strings.TrimSuffix(prog, "/bin/launch.sh")
			if len(args) > 1 && args[1].text == "domain" {
				l.domain = true
			}
			if len(args) > 2 {
				l.config = args[2].text
			}
		case strings.HasSuffix(prog, "/bin/standalone.sh"):
			home = strings.TrimSuffix(prog, "/bin/standalone.sh")
			for i := 1; i < len(args); i++ {
				a := args[i].text
				switch {
				case (a == "-c" || a == "--server-config") && i+1 < len(args):
					l.config = args[i+1].text
					i++
				case strings.HasPrefix(a, "-c="):
					l.config = strings.TrimPrefix(a, "-c=")
				case strings.HasPrefix(a, "--server-config="):
					l.config = strings.TrimPrefix(a, "--server-config=")
				}
			}
		case strings.HasSuffix(prog, "/bin/domain.sh"):
			home, l.domain = strings.TrimSuffix(prog, "/bin/domain.sh"), true
		default:
			continue
		}
		if !l.domain && l.config != "" && !wildflyConfigName.MatchString(l.config) {
			l.reason = "the configuration file named in " + u.path + " is not a plain file name in standalone/configuration; which file the server is started with is not determined"
		}
		if _, dup := out[home]; !dup && strings.HasPrefix(home, "/") {
			out[home] = l
		}
	}
	return out
}

// wildflyInstall は、1 つの WildFly について、待ち受けによらず決まること。
type wildflyInstall struct {
	app    ruleset.AppRule
	svc    model.Service
	home   string
	config string
	file   *standalonexml.File

	version string
	table   *ruleset.WildFlyTable
	legacy  bool // 古い形式（security-realm）のある版
	prov    *model.Provenance

	jdks    []string // WildFly を動かす JDK の候補
	why     string
	certain bool   // JDK が 1 つに決まっている
	reason  string // 空でなければ、値を求められない理由（どの待ち受けにも共通）
}

func (c *Collector) wildflyHome(app ruleset.AppRule, home string, l wildflyLaunch, launched bool) {
	svc := model.Service{ID: "svc:" + app.ID + ":" + home, App: app.ID, Activity: model.Activity{Level: "unknown"}}
	if launched {
		svc.Activity = c.activity(app, []unitInfo{l.unit}, false, model.Component{})
	}
	if launched && l.domain {
		c.Builder.AddService(svc)
		c.Builder.ServiceNote(svc.ID, "started in domain mode by "+l.unit.path+"; the configuration of domain mode (domain.xml, host.xml) is not read")
		return
	}
	config := home + wildflyConfigSuffix
	if launched && l.reason == "" && l.config != "" {
		config = home + wildflyConfigDir + "/" + l.config
	}
	svc.ConfigFiles = []string{c.Prefix + config}
	c.Builder.AddService(svc)
	data, err := c.read(config)
	if err != nil {
		c.Builder.ServiceNote(svc.ID, "the configuration file "+config+" cannot be read")
		return
	}
	f, err := standalonexml.Parse(data)
	if err != nil {
		c.Builder.Skip(safefs.Skip{Path: c.Prefix + config, Reason: "invalid-value", Detail: "standalone.xml"})
		return
	}
	in := &wildflyInstall{app: app, svc: svc, home: home, config: config, file: f}
	switch {
	case len(f.Problems) > 0:
		in.reason = "the configuration file is not fully read: " + f.Problems[0]
	case launched && l.reason != "":
		in.reason = l.reason
	}
	if in.reason == "" {
		in.version, in.reason = c.wildflyVersion(home)
	}
	if in.reason == "" {
		tb, v, ok := c.Rules.WildFlyFor(in.version)
		if !ok {
			c.Builder.NoteUnmeasured(model.Unmeasured{Kind: wildflyUnmeasured, Name: wildflyUnmeasured, Version: in.version, Status: "missing"})
			in.reason = "no WildFly table is recorded for WildFly " + in.version
		} else {
			in.table, in.legacy = tb, v.LegacyRealm
			in.prov = &model.Provenance{Image: tb.Source.Image, OS: tb.Source.OS, Package: wildflyUnmeasured, Version: in.version}
		}
	}
	if in.reason == "" {
		in.jdks, in.why, in.certain, in.reason = c.wildflyJDKs(home)
	}
	if !launched {
		in.why += ". No unit that starts this WildFly was read, so the configuration file is taken to be standalone.xml (the default)"
	}
	for _, lis := range f.Listeners {
		c.wildflyListener(in, lis)
	}
	for _, m := range f.Management {
		c.wildflyManagement(in, m)
	}
}

// wildflyVersion は、置かれている WildFly の版を読む。
// 30 までは、製品のマニフェスト（modules/.../org/jboss/as/product/main/dir/META-INF/MANIFEST.MF）、31 以降は、同じディレクトリにある
// 製品の JAR（wildfly-feature-pack-product-conf-<版>.jar）の中のマニフェストに、JBoss-Product-Release-Version として書かれている
// （検証ラボで、19.0.0.Final〜42.0.0.Final の 54 版の配布物で確かめた）。
func (c *Collector) wildflyVersion(home string) (version, reason string) {
	dir := home + wildflyProductDir
	manifest, err := c.read(dir + "/dir/META-INF/MANIFEST.MF")
	if err != nil {
		manifest = nil
		if real, err := c.Opener.Resolve(c.Prefix + dir); err == nil {
			ents, _ := c.Opener.ListNames(real)
			var jars []string
			for _, e := range ents {
				if !e.IsDir && wildflyProductJar.MatchString(e.Name) {
					jars = append(jars, e.Name)
				}
			}
			if len(jars) == 1 {
				manifest = c.wildflyJarManifest(real + "/" + jars[0])
			}
		}
	}
	if len(manifest) > wildflyMaxManifest {
		manifest = nil
	}
	mf := manifestValues(manifest, "JBoss-Product-Release-Name", "JBoss-Product-Release-Version")
	version = mf["JBoss-Product-Release-Version"]
	switch {
	case version == "":
		return "", "the version of this WildFly cannot be read (no product manifest under " + dir + ")"
	case !strings.HasPrefix(mf["JBoss-Product-Release-Name"], "WildFly"):
		return "", "this installation is not WildFly (its product manifest names another product); it is not handled"
	case !wildflyVersionValue.MatchString(version):
		return "", "the version of this WildFly cannot be read (the product manifest has a value in an unexpected form)"
	}
	return version, ""
}

func (c *Collector) wildflyJarManifest(path string) []byte {
	f, err := c.Opener.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	a, err := jarfile.Open(f, f.Size(), wildflyJarLimits)
	if err != nil {
		return nil
	}
	data, err := a.Read("META-INF/MANIFEST.MF")
	if err != nil {
		return nil
	}
	return data
}

// wildflyJDKs は、WildFly を動かす JDK の候補を返す。
//
// standalone.sh は、bin/standalone.conf を取り込んでから、JAVA_HOME の指す Java（なければ PATH の java）で起動する。
// standalone.conf はシェルのスクリプトなので、解釈はしない。行頭に書かれた「JAVA_HOME=絶対パス」が 1 つだけあれば、その JDK とする。
// それ以外（指定がない、条件の中にある、複数ある、JAVA を直接指定している）は、どの JDK かを決めず、見つかった JDK すべてを候補にする
// （呼び出し側は、すべての JDK で同じになる項目だけを確定とする）。
func (c *Collector) wildflyJDKs(home string) (homes []string, why string, certain bool, reason string) {
	conf := home + "/bin/standalone.conf"
	javaHome, unclear := "", false
	if data, err := c.read(conf); err == nil {
		for _, raw := range strings.Split(string(data), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || line[0] == '#' {
				continue
			}
			for _, o := range tomcatRiskyOptions {
				if strings.Contains(line, o) {
					return nil, "", false, conf + " has an option (" + o + "...) that can change the TLS settings of Java; its effect is not interpreted"
				}
			}
			m := wildflyJavaAssign.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			value := strings.TrimSpace(m[2])
			if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
				value = value[1 : len(value)-1]
			}
			plain := strings.HasPrefix(value, "/") && len(value) <= 1024 && !strings.ContainsAny(value, "$`\\\"' \t;&|()<>")
			if m[1] == "JAVA_HOME" && raw == strings.TrimRight(raw, " \t\r") && !strings.HasPrefix(raw, " ") && !strings.HasPrefix(raw, "\t") && plain && javaHome == "" {
				javaHome = value
			} else {
				unclear = true
			}
		}
	}
	if javaHome != "" && !unclear {
		return []string{javaHome}, "the JDK is the one that JAVA_HOME in " + conf + " names (" + javaHome + ")", true, ""
	}
	homes = c.jdkHomes()
	if len(homes) == 0 {
		return nil, "", false, "no JDK is found on this host; which JDK runs WildFly is not determined"
	}
	why = "standalone.sh uses the Java that JAVA_HOME names, or else the java on PATH, and which JDK that is, is not determined"
	if unclear {
		why = conf + " sets JAVA_HOME or JAVA in a way that is not interpreted, so which JDK runs WildFly is not determined"
	}
	why += ". The values are those that are the same with every JDK found on this host (" + strings.Join(homes, ", ") + "). A JDK in a place that is not searched is not considered"
	return homes, why, false, ""
}
