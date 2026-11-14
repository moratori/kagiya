//go:build unix

package apps

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kagiya/internal/inventory"
	"kagiya/internal/logx"
	"kagiya/internal/model"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

// 以下の期待値は、検証ラボで Spring Boot 2.7.0〜4.1.2 の全パッチ版（117 版）のアプリをビルドして Ubuntu 24.04 の OpenJDK 21 で起動し、
// JAR の中の設定を変えた場面ごとにハンドシェイクで数え上げた結果と、参照モデルが一致することを確かめたうえで、参照モデルから求めたもの。

const (
	sbJar    = "/opt/portal/app.jar"
	sbScope  = "port 8443"
	sbSvc    = "svc:spring-boot:" + sbJar
	sbBase   = "server.port=8443\n"
	sbKS     = "server.ssl.key-store=/etc/portal/server.p12\nserver.ssl.key-store-password=s3cret-boot\nserver.ssl.key-store-type=PKCS12\n"
	sbUnit   = "/etc/systemd/system/portal.service"
	sbJava21 = "/usr/lib/jvm/java-21-openjdk-arm64"
)

// sbArchive は、Spring Boot の実行できる JAR をまねたものを作る（同梱ライブラリは名前だけ）。
func sbArchive(t *testing.T, bootVersion string, libs []string, classes map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	add := func(name, content string) {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte(content))
	}
	add("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nMain-Class: org.springframework.boot.loader.launch.JarLauncher\r\nStart-Class: lab.App\r\n"+
		"Spring-Boot-Version: "+bootVersion+"\r\nSpring-Boot-Classes: BOOT-INF/classes/\r\nSpring-Boot-Lib: BOOT-INF/lib/\r\n")
	for name, content := range classes {
		add("BOOT-INF/classes/"+name, content)
	}
	for _, l := range libs {
		add("BOOT-INF/lib/"+l, "")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

var sbTomcat = []string{"spring-boot-3.5.16.jar", "tomcat-embed-core-10.1.55.jar", "tomcat-embed-el-10.1.55.jar"}

type sbHost struct {
	boot    string            // Spring Boot の版（既定 3.5.16）
	libs    []string          // 同梱ライブラリ（既定は Tomcat 10.1.55）
	config  map[string]string // JAR の中の設定ファイル
	unit    string            // ExecStart の値（空なら、起動の定義を置かない）
	unitEnv string            // ユニットの [Service] に足す行
	files   map[string]string // そのほかのファイル
	jdks    []model.Package   // 導入されている JDK（既定は Ubuntu の 21）
	// supervisord のサービスを「起動するよう設定された」状態にする
	enableSupervisor bool
	// JAR の先頭に起動スクリプトを付ける（Spring Boot の「そのまま実行できる JAR」）
	script bool
}

func sbCollect(t *testing.T, h sbHost) (string, *model.Inventory) {
	t.Helper()
	return sbCollectWith(t, h, nil)
}

// sbCollectWith は、調べる前に、prepare でホストの状態に手を加える。
func sbCollectWith(t *testing.T, h sbHost, prepare func(prefix string)) (string, *model.Inventory) {
	t.Helper()
	prefix, _ := filepath.EvalSymlinks(t.TempDir())
	if h.boot == "" {
		h.boot = "3.5.16"
	}
	if h.libs == nil {
		h.libs = sbTomcat
	}
	if h.jdks == nil {
		h.jdks = []model.Package{pkgJava21Ubu}
	}
	write := func(name string, data []byte) {
		if err := os.MkdirAll(filepath.Dir(prefix+name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(prefix+name, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	jar := sbArchive(t, h.boot, h.libs, h.config)
	if h.script {
		jar = append([]byte("#!/bin/bash\n# the launch script of Spring Boot would be here\nexit 0\n"), jar...)
	}
	write(sbJar, jar)
	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	b := inventory.NewBuilder(rs, logx.New(io.Discard, time.Now))
	for _, p := range h.jdks {
		b.AddPackage(p)
		home := sbJava21
		if p.Name == "openjdk-25-jre-headless" {
			home = jdkDeb25Home
		}
		write(home+"/conf/security/java.security", []byte("security.provider.1=SUN\n"+jdkUpstreamDisabled))
		write(home+"/bin/java", []byte("#!java"))
	}
	link(t, prefix, "../lib/jvm/java-21-openjdk-arm64/bin/java", "/usr/bin/java")
	if h.unit != "" {
		write(sbUnit, []byte("[Unit]\nDescription=portal\n[Service]\n"+h.unitEnv+"ExecStart="+h.unit+"\n[Install]\nWantedBy=multi-user.target\n"))
		link(t, prefix, sbUnit, "/etc/systemd/system/multi-user.target.wants/portal.service")
	}
	for name, content := range h.files {
		write(name, []byte(content))
	}
	if h.enableSupervisor {
		link(t, prefix, "/usr/lib/systemd/system/supervisor.service", "/etc/systemd/system/multi-user.target.wants/supervisor.service")
	}
	if prepare != nil {
		prepare(prefix)
	}
	c := &Collector{Prefix: prefix, Opener: &safefs.Opener{OnSkip: b.Skip}, Builder: b, Rules: rs}
	c.CollectJavaApps([]string{prefix + sbJar})
	return prefix, b.Inventory()
}

func sbEff(t *testing.T, inv *model.Inventory, param string) model.EffectiveValue {
	t.Helper()
	return eff(t, inv, sbSvc, param, sbScope)
}

func sbUnresolved(t *testing.T, inv *model.Inventory, want string) {
	t.Helper()
	for _, p := range []string{"tls.protocols", "tls.ciphers", "tls.ciphersuites-tls13"} {
		e := sbEff(t, inv, p)
		if e.Status != "unresolved" || !strings.Contains(e.Reason, want) {
			t.Errorf("%s: status=%s reason=%q, want unresolved with %q", p, e.Status, e.Reason, want)
		}
	}
}

const sbStart = "/usr/bin/java -Xmx512m -jar " + sbJar

// systemd のユニットから起動される Spring Boot のアプリ: JAR の中の設定、同梱の Tomcat の表、ユニットの Java から求める。
func TestSpringBootFromUnit(t *testing.T) {
	prefix, inv := sbCollect(t, sbHost{config: map[string]string{"application.properties": sbBase + sbKS}, unit: sbStart})
	var svc model.Service
	for _, s := range inv.Services {
		if s.ID == sbSvc {
			svc = s
		}
	}
	if svc.App != "spring-boot" || len(svc.ConfigFiles) != 1 || svc.ConfigFiles[0] != prefix+sbJar || svc.Activity.Level != "enabled" {
		t.Errorf("service = %+v", svc)
	}
	if p := sbEff(t, inv, "tls.protocols"); p.Status != "resolved" || strings.Join(p.Values, ",") != "TLSv1.3,TLSv1.2" || p.Direction != "inbound" {
		t.Errorf("protocols = %+v", p)
	}
	// キーストアの中は読まないので、証明書の種類では絞り込まない（確度を下げる）
	e := sbEff(t, inv, "tls.ciphers")
	checkSuites(t, e, 27, tcAny12, "medium")
	notes := strings.Join(e.Notes, " ")
	for _, want := range []string{"3.5.16", "10.1.55", sbJava21, "portal.service", "outside the JAR"} {
		if !strings.Contains(notes, want) {
			t.Errorf("the notes must mention %q: %v", want, e.Notes)
		}
	}
	if s := e.Steps[0]; s.Layer != "app-default" || s.Source == nil || s.Source.Package != "tomcat-embed-core" || s.Source.Version != "10.1.55" {
		t.Errorf("first step = %+v", s)
	}
	checkSuites(t, sbEff(t, inv, "tls.ciphersuites-tls13"), 3, jdkTLS13, "high")
	if g := sbEff(t, inv, "tls.groups"); g.Status != "resolved" || sortedJoin(g.Values) != jdkGroups {
		t.Errorf("groups = %+v", g)
	}
	// キーストアの場所を、JAR の中の設定ファイルの位置とともに記録する。パスワードは、どこにも出さない
	ks := find(inv, "tls.keystore")
	if len(ks) != 1 || ks[0].Service != sbSvc || ks[0].ReferencedPaths[0] != prefix+"/etc/portal/server.p12" ||
		ks[0].Location.Path != prefix+sbJar+"!/BOOT-INF/classes/application.properties" || ks[0].Location.Line != 2 {
		t.Errorf("keystore setting = %+v", ks)
	}
	out, _ := json.Marshal(inv)
	if strings.Contains(string(out), "s3cret") {
		t.Error("a password from the application configuration appears in the result")
	}
}

// 設定に書かれたプロトコルと暗号が効く。ciphers を書くと、TLS 1.3 のスイートもその指定に従う（実測）。
func TestSpringBootConfigured(t *testing.T) {
	conf := sbBase + sbKS + "server.ssl.enabled-protocols=TLSv1.2,TLSv1.3\n" +
		"server.ssl.ciphers=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256\n"
	_, inv := sbCollect(t, sbHost{config: map[string]string{"application.properties": conf}, unit: sbStart})
	e := sbEff(t, inv, "tls.ciphers")
	if e.Status != "resolved" || strings.Join(e.Values, ",") != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" || e.Steps[0].Layer != "app-config" || e.Steps[0].Setting == "" {
		t.Errorf("ciphers = %+v", e)
	}
	if e := sbEff(t, inv, "tls.ciphersuites-tls13"); e.Status != "resolved" || strings.Join(e.Values, ",") != "TLS_AES_256_GCM_SHA384" {
		t.Errorf("TLS 1.3 suites = %+v", e)
	}
	// YAML でも同じ。プロトコルを TLS 1.2 だけにすれば、TLS 1.3 のスイートは空
	yml := "server:\n  port: 8443\n  ssl:\n    key-store: /etc/portal/server.p12\n    key-store-password: s3cret-boot\n    enabled-protocols: TLSv1.2\n"
	_, inv = sbCollect(t, sbHost{config: map[string]string{"application.yml": yml}, unit: sbStart})
	if p := sbEff(t, inv, "tls.protocols"); strings.Join(p.Values, ",") != "TLSv1.2" {
		t.Errorf("protocols = %+v", p)
	}
	checkSuites(t, sbEff(t, inv, "tls.ciphers"), 27, tcAny12, "medium")
	if e := sbEff(t, inv, "tls.ciphersuites-tls13"); e.Status != "resolved" || len(e.Values) != 0 {
		t.Errorf("TLS 1.3 suites = %+v", e)
	}
	// 起動時の指定で有効にしたプロファイルの設定が効く
	_, inv = sbCollect(t, sbHost{config: map[string]string{"application.properties": sbBase + sbKS, "application-prod.properties": "server.ssl.enabled-protocols=TLSv1.3\n"},
		unit: sbStart + " --spring.profiles.active=prod"})
	if p := sbEff(t, inv, "tls.protocols"); strings.Join(p.Values, ",") != "TLSv1.3" {
		t.Errorf("profile from the command line: %+v", p)
	}
	_, inv = sbCollect(t, sbHost{config: map[string]string{"application.properties": sbBase + sbKS, "application-prod.properties": "server.ssl.enabled-protocols=TLSv1.3\n"},
		unit: sbStart, unitEnv: "Environment=SPRING_PROFILES_ACTIVE=prod\n"})
	if p := sbEff(t, inv, "tls.protocols"); strings.Join(p.Values, ",") != "TLSv1.3" {
		t.Errorf("profile from the environment: %+v", p)
	}
}

// 起動の定義が読めない JAR: 導入されているすべての JDK で結果が同じ項目だけ確定とし、違う項目は「不明」にして JDK ごとの結果を並べる。
func TestSpringBootWithoutLaunchDefinition(t *testing.T) {
	conf := map[string]string{"application.properties": sbBase + sbKS}
	// JDK が 1 つ: その JDK の結果で確定（探していない場所の JDK で動いている可能性は残るので、確度は下げる）
	_, inv := sbCollect(t, sbHost{config: conf})
	e := sbEff(t, inv, "tls.ciphers")
	checkSuites(t, e, 27, tcAny12, "medium")
	if !strings.Contains(strings.Join(e.Notes, " "), "every JDK") {
		t.Errorf("notes = %v", e.Notes)
	}
	checkSuites(t, sbEff(t, inv, "tls.ciphersuites-tls13"), 3, jdkTLS13, "medium")
	for _, s := range inv.Services {
		if s.ID == sbSvc && s.Activity.Level == "enabled" {
			t.Errorf("without a launch definition the application is not known to be enabled: %+v", s.Activity)
		}
	}
	// JDK が 2 つ（21 と 25）: 暗号スイートは同じなので確定。鍵交換のグループは違う（25 は X25519MLKEM768 を受け入れる）ので「不明」
	_, inv = sbCollect(t, sbHost{config: conf, jdks: []model.Package{pkgJava21Ubu, pkgDeb25}})
	checkSuites(t, sbEff(t, inv, "tls.ciphers"), 27, tcAny12, "medium")
	g := sbEff(t, inv, "tls.groups")
	if g.Status != "unresolved" || !strings.Contains(g.Reason, sbJava21) || !strings.Contains(g.Reason, jdkDeb25Home) {
		t.Errorf("groups = %+v", g)
	}
	// JDK が見つからない
	_, inv = sbCollect(t, sbHost{config: conf, jdks: []model.Package{}})
	sbUnresolved(t, inv, "JDK")
}

// TLS を待ち受けない設定では、値を記録しない（サービスとしては記録する）。
func TestSpringBootWithoutTLS(t *testing.T) {
	for name, conf := range map[string]string{
		"no key store": sbBase,
		"disabled":     sbBase + sbKS + "server.ssl.enabled=false\n",
	} {
		_, inv := sbCollect(t, sbHost{config: map[string]string{"application.properties": conf}, unit: sbStart})
		found := false
		for _, s := range inv.Services {
			found = found || s.ID == sbSvc
		}
		if !found {
			t.Errorf("%s: the application must still be recorded", name)
		}
		for _, e := range inv.EffectiveValues {
			if e.Service == sbSvc {
				t.Errorf("%s: unexpected value %s %s", name, e.Parameter, e.Status)
			}
		}
	}
	// SSL バンドルの設定がない版（2.7 系、3.0 系）では、バンドルを書いても TLS を待ち受けない（実測）
	bundle := sbBase + "server.ssl.bundle=web\nspring.ssl.bundle.jks.web.keystore.location=/etc/portal/server.p12\nspring.ssl.bundle.jks.web.keystore.password=s3cret-boot\n"
	_, inv := sbCollect(t, sbHost{boot: "2.7.18", libs: []string{"spring-boot-2.7.18.jar", "tomcat-embed-core-9.0.83.jar"},
		config: map[string]string{"application.properties": bundle}, unit: sbStart})
	for _, e := range inv.EffectiveValues {
		if e.Service == sbSvc {
			t.Errorf("bundle on 2.7.18: unexpected value %s %s", e.Parameter, e.Status)
		}
	}
}

// SSL バンドルの設定（3.1 以降）: バンドルの options の指定が効く。
func TestSpringBootBundle(t *testing.T) {
	bundle := sbBase + "server.ssl.bundle=web\nspring.ssl.bundle.jks.web.keystore.location=/etc/portal/server.p12\nspring.ssl.bundle.jks.web.keystore.password=s3cret-boot\n" +
		"spring.ssl.bundle.jks.web.options.ciphers=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_AES_128_GCM_SHA256\nspring.ssl.bundle.jks.web.options.enabled-protocols=TLSv1.2,TLSv1.3\n"
	prefix, inv := sbCollect(t, sbHost{config: map[string]string{"application.properties": bundle}, unit: sbStart})
	if e := sbEff(t, inv, "tls.ciphers"); e.Status != "resolved" || strings.Join(e.Values, ",") != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
		t.Errorf("ciphers = %+v", e)
	}
	if e := sbEff(t, inv, "tls.ciphersuites-tls13"); strings.Join(e.Values, ",") != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("TLS 1.3 suites = %+v", e)
	}
	if ks := find(inv, "tls.keystore"); len(ks) != 1 || ks[0].ReferencedPaths[0] != prefix+"/etc/portal/server.p12" {
		t.Errorf("keystore setting = %+v", ks)
	}
	// 3.4.0 は、測ったバンドルの設定では起動しなかった。値を求めない
	_, inv = sbCollect(t, sbHost{boot: "3.4.0", libs: []string{"spring-boot-3.4.0.jar", "tomcat-embed-core-10.1.33.jar"},
		config: map[string]string{"application.properties": bundle}, unit: sbStart})
	sbUnresolved(t, inv, "bundle")
}

// 求めない場合。理由を残す。
func TestSpringBootUnresolved(t *testing.T) {
	plain := map[string]string{"application.properties": sbBase + sbKS}
	for name, c := range map[string]struct {
		host sbHost
		want string
	}{
		"unmeasured version":  {sbHost{boot: "3.5.99", config: plain, unit: sbStart}, "3.5.99"},
		"unmeasured tomcat":   {sbHost{libs: []string{"spring-boot-3.5.16.jar", "tomcat-embed-core-10.1.999.jar"}, config: plain, unit: sbStart}, "10.1.999"},
		"jetty":               {sbHost{libs: []string{"spring-boot-3.5.16.jar", "jetty-server-12.0.16.jar"}, config: plain, unit: sbStart}, "Tomcat"},
		"risky option":        {sbHost{config: plain, unit: "/usr/bin/java -Djava.security.properties=/etc/x -jar " + sbJar}, "-Djava.security"},
		"override":            {sbHost{config: plain, unit: sbStart + " --server.ssl.ciphers=TLS_AES_128_GCM_SHA256"}, "command line"},
		"env override":        {sbHost{config: plain, unit: sbStart, unitEnv: "Environment=SERVER_SSL_ENABLED_PROTOCOLS=TLSv1.3\n"}, "environment"},
		"placeholder":         {sbHost{config: map[string]string{"application.properties": sbBase + sbKS + "server.ssl.ciphers=${TLS_CIPHERS}\n"}, unit: sbStart}, "server.ssl.ciphers"},
		"external config":     {sbHost{config: plain, unit: sbStart, files: map[string]string{"/opt/portal/application.properties": "server.ssl.enabled-protocols=TLSv1.3\n"}}, "outside the JAR"},
		"external config dir": {sbHost{config: plain, unit: sbStart, files: map[string]string{"/opt/portal/config/application.yml": "server:\n  port: 1\n"}}, "outside the JAR"},
		"script":              {sbHost{config: plain, unit: "/opt/portal/start.sh"}, ""},
	} {
		_, inv := sbCollect(t, c.host)
		if name == "script" {
			// 起動スクリプトは解釈しない。起動の定義が読めない JAR として扱う（JDK が 1 つなので確定する）
			checkSuites(t, sbEff(t, inv, "tls.ciphers"), 27, tcAny12, "medium")
			continue
		}
		t.Run(name, func(t *testing.T) { sbUnresolved(t, inv, c.want) })
	}
}

// Spring Boot の JAR でないもの、壊れた JAR は、対象にしない。
func TestSpringBootIgnoresOtherArchives(t *testing.T) {
	prefix, _ := filepath.EvalSymlinks(t.TempDir())
	os.MkdirAll(prefix+"/opt/x", 0o755)
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, _ := w.Create("META-INF/MANIFEST.MF")
	f.Write([]byte("Manifest-Version: 1.0\r\n"))
	w.Close()
	os.WriteFile(prefix+"/opt/x/plain.jar", buf.Bytes(), 0o644)
	os.WriteFile(prefix+"/opt/x/broken.jar", []byte("not a zip"), 0o644)
	rs, _ := ruleset.Builtin()
	b := inventory.NewBuilder(rs, logx.New(io.Discard, time.Now))
	c := &Collector{Prefix: prefix, Opener: &safefs.Opener{OnSkip: b.Skip}, Builder: b, Rules: rs}
	c.CollectJavaApps([]string{prefix + "/opt/x/plain.jar", prefix + "/opt/x/broken.jar"})
	if inv := b.Inventory(); len(inv.Services) != 0 || len(inv.EffectiveValues) != 0 {
		t.Errorf("services = %+v", inv.Services)
	}
}

// supervisord から起動される Spring Boot のアプリ: プログラムの定義（command）の Java から JDK を決める。
// 読み方は、実物の supervisord（Ubuntu 24.04 の supervisor 4.2.5）で確かめた。
func TestSpringBootFromSupervisor(t *testing.T) {
	conf := map[string]string{"application.properties": sbBase + sbKS, "application-prod.properties": "server.ssl.enabled-protocols=TLSv1.3\n"}
	const file = "/etc/supervisor/conf.d/portal.conf"
	program := func(body string) map[string]string {
		return map[string]string{file: "[program:portal]\n" + body}
	}
	_, inv := sbCollect(t, sbHost{config: conf, files: program("command=/usr/bin/java -Xmx256m -jar " + sbJar + " ; the portal\ndirectory=/opt/portal\n"), enableSupervisor: true})
	e := sbEff(t, inv, "tls.ciphersuites-tls13")
	checkSuites(t, e, 3, jdkTLS13, "high")
	notes := strings.Join(e.Notes, " ")
	if !strings.Contains(notes, "supervisord") || !strings.Contains(notes, "portal") || !strings.Contains(notes, sbJava21) {
		t.Errorf("notes = %v", e.Notes)
	}
	for _, s := range inv.Services {
		if s.ID == sbSvc && s.Activity.Level != "enabled" {
			t.Errorf("activity = %+v", s.Activity)
		}
	}
	// supervisord が起動するよう設定されていない、またはプログラムが autostart=false なら、「起動するよう設定されている」とは言えない
	for name, h := range map[string]sbHost{
		"supervisor not enabled": {config: conf, files: program("command=/usr/bin/java -jar " + sbJar + "\n")},
		"autostart off":          {config: conf, files: program("command=/usr/bin/java -jar " + sbJar + "\nautostart=false\n"), enableSupervisor: true},
	} {
		_, inv := sbCollect(t, h)
		for _, s := range inv.Services {
			if s.ID == sbSvc && s.Activity.Level == "enabled" {
				t.Errorf("%s: activity = %+v", name, s.Activity)
			}
		}
		checkSuites(t, sbEff(t, inv, "tls.ciphersuites-tls13"), 3, jdkTLS13, "high")
	}
	// プロファイルは、environment の指定を読む
	_, inv = sbCollect(t, sbHost{config: conf, files: program("command=/usr/bin/java -jar " + sbJar + "\nenvironment=SPRING_PROFILES_ACTIVE=\"prod\",APP_HOME=\"/opt/portal\"\n"), enableSupervisor: true})
	if p := sbEff(t, inv, "tls.protocols"); strings.Join(p.Values, ",") != "TLSv1.3" {
		t.Errorf("profile from the environment: %+v", p)
	}
	// TLS の設定を上書きする環境変数、置き換え（%(...)s）で値が分からないプロファイルの指定があれば、求めない
	_, inv = sbCollect(t, sbHost{config: conf, files: program("command=/usr/bin/java -jar " + sbJar + "\nenvironment=SERVER_SSL_CIPHERS=TLS_AES_128_GCM_SHA256\n")})
	sbUnresolved(t, inv, "environment")
	_, inv = sbCollect(t, sbHost{config: conf, files: program("command=/usr/bin/java -jar " + sbJar + "\nenvironment=SPRING_PROFILES_ACTIVE=%(ENV_PROFILE)s\n")})
	sbUnresolved(t, inv, "SPRING_PROFILES_ACTIVE")
	// command に置き換えがあると、どの JAR を起動するのか決まらない。起動の定義が読めない JAR として扱う
	_, inv = sbCollect(t, sbHost{config: conf, files: program("command=/usr/bin/java -jar %(ENV_APP_JAR)s\n")})
	e = sbEff(t, inv, "tls.ciphersuites-tls13")
	checkSuites(t, e, 3, jdkTLS13, "medium")
	if !strings.Contains(strings.Join(e.Notes, " "), "every JDK") {
		t.Errorf("notes = %v", e.Notes)
	}
}

// 以下は、Spring Boot の「そのまま実行できる JAR」（JAR の先頭に起動スクリプトを付けたもの。ビルドの設定で executable を有効にすると作られる）。
// 検証ラボで、Spring Boot 2.7.18 と 3.5.16 でビルドした JAR から起動スクリプトを取り出して読んだ（どちらも同じ内容。4.1.2 では、
// 同じ設定でもスクリプトは付かなかった）。スクリプトは、JAR の隣の <JAR の名前>.conf を取り込み、JAVA_HOME の Java（なければ PATH の java）で、
// 「java $JAVA_OPTS -jar <JAR> $RUN_ARGS <引数>」を起動する。

const (
	sbConf     = "/opt/portal/app.conf"
	sbConfJava = "JAVA_HOME=" + sbJava21 + "\n"
)

// ユニットが JAR そのものを起動する場合: Java は、.conf の JAVA_HOME から決まる。
func TestSpringBootExecutableJar(t *testing.T) {
	conf := map[string]string{"application.properties": sbBase + sbKS, "application-prod.properties": "server.ssl.enabled-protocols=TLSv1.3\n"}
	_, inv := sbCollect(t, sbHost{config: conf, script: true, unit: sbJar,
		files: map[string]string{sbConf: "# portal\n" + sbConfJava + "JAVA_OPTS=\"-Xmx512m -Dfile.encoding=UTF-8\"\nLOG_FOLDER=/var/log/portal\nKEY_PASSWORD=s3cret-conf\n"}})
	e := sbEff(t, inv, "tls.ciphersuites-tls13")
	checkSuites(t, e, 3, jdkTLS13, "high")
	notes := strings.Join(e.Notes, " ")
	for _, want := range []string{"portal.service", "JAVA_HOME", sbConf, sbJava21} {
		if !strings.Contains(notes, want) {
			t.Errorf("the notes must mention %q: %v", want, e.Notes)
		}
	}
	for _, s := range inv.Services {
		if s.ID == sbSvc && s.Activity.Level != "enabled" {
			t.Errorf("activity = %+v", s.Activity)
		}
	}
	out, _ := json.Marshal(inv)
	if strings.Contains(string(out), "s3cret") {
		t.Error("a value from the .conf file appears in the result")
	}

	// JAVA_HOME は、ユニットの環境変数からも決まる（.conf があれば、.conf の値が後から代入されるので優先）
	_, inv = sbCollect(t, sbHost{config: conf, script: true, unit: sbJar, unitEnv: "Environment=JAVA_HOME=" + sbJava21 + "\n"})
	e = sbEff(t, inv, "tls.ciphersuites-tls13")
	checkSuites(t, e, 3, jdkTLS13, "high")
	if n := strings.Join(e.Notes, " "); !strings.Contains(n, "JAVA_HOME") || !strings.Contains(n, "portal.service") {
		t.Errorf("notes = %v", e.Notes)
	}
	_, inv = sbCollect(t, sbHost{config: conf, script: true, unit: sbJar, unitEnv: "Environment=JAVA_HOME=" + jdkDeb25Home + "\n",
		jdks: []model.Package{pkgJava21Ubu, pkgDeb25}, files: map[string]string{sbConf: sbConfJava}})
	if g := sbEff(t, inv, "tls.groups"); g.Status != "resolved" || sortedJoin(g.Values) != jdkGroups {
		t.Errorf("the JAVA_HOME in the .conf file must win over the unit's: %+v", g)
	}

	// JAVA_HOME がどこにもない（または、その下に java がない）場合は、PATH の java が使われる。JAVA_HOME の値を読み切れない場合も含めて、どの JDK かは決めず、
	// 起動の定義がない場合と同じく、すべての JDK で同じになる値だけを確定とする
	for name, h := range map[string]sbHost{
		"no JAVA_HOME":             {config: conf, script: true, unit: sbJar},
		"JAVA_HOME without a java": {config: conf, script: true, unit: sbJar, files: map[string]string{sbConf: "JAVA_HOME=/opt/missing-jdk\n"}},
		"JAVA_HOME not plain":      {config: conf, script: true, unit: sbJar, files: map[string]string{sbConf: "JAVA_HOME=$(dirname /usr/bin)\n"}},
	} {
		_, inv := sbCollect(t, h)
		e := sbEff(t, inv, "tls.ciphersuites-tls13")
		checkSuites(t, e, 3, jdkTLS13, "medium")
		if n := strings.Join(e.Notes, " "); !strings.Contains(n, "PATH") || !strings.Contains(n, "every JDK") {
			t.Errorf("%s: notes = %v", name, e.Notes)
		}
		for _, s := range inv.Services {
			if s.ID == sbSvc && s.Activity.Level != "enabled" {
				t.Errorf("%s: activity = %+v", name, s.Activity)
			}
		}
	}

	// RUN_ARGS と、ユニットの引数は、アプリの引数になる（プロファイルの指定を読む）。JAVA_OPTS の -D も同じ
	for name, h := range map[string]sbHost{
		"RUN_ARGS":  {config: conf, script: true, unit: sbJar, files: map[string]string{sbConf: sbConfJava + "RUN_ARGS='--spring.profiles.active=prod'\n"}},
		"unit args": {config: conf, script: true, unit: sbJar + " --spring.profiles.active=prod", files: map[string]string{sbConf: sbConfJava}},
		"JAVA_OPTS": {config: conf, script: true, unit: sbJar, files: map[string]string{sbConf: sbConfJava + "JAVA_OPTS=-Dspring.profiles.active=prod\n"}},
		"unit env":  {config: conf, script: true, unit: sbJar, unitEnv: "Environment=RUN_ARGS=--spring.profiles.active=prod\n", files: map[string]string{sbConf: sbConfJava}},
	} {
		_, inv := sbCollect(t, h)
		if p := sbEff(t, inv, "tls.protocols"); p.Status != "resolved" || strings.Join(p.Values, ",") != "TLSv1.3" {
			t.Errorf("%s: protocols = %+v", name, p)
		}
	}

	// supervisord のプログラムが JAR そのものを起動する場合も同じ
	_, inv = sbCollect(t, sbHost{config: conf, script: true, enableSupervisor: true, files: map[string]string{
		"/etc/supervisor/conf.d/portal.conf": "[program:portal]\ncommand=" + sbJar + "\nenvironment=JAVA_HOME=\"" + sbJava21 + "\"\n"}})
	e = sbEff(t, inv, "tls.ciphersuites-tls13")
	checkSuites(t, e, 3, jdkTLS13, "high")
	if n := strings.Join(e.Notes, " "); !strings.Contains(n, "supervisord") || !strings.Contains(n, "JAVA_HOME") {
		t.Errorf("notes = %v", e.Notes)
	}
}

// .conf や環境変数で、結果が変わりうる指定がある場合、内容を読み切れない場合は、値を求めない。
func TestSpringBootExecutableJarUnresolved(t *testing.T) {
	conf := map[string]string{"application.properties": sbBase + sbKS}
	for name, tc := range map[string]struct {
		h    sbHost
		want string
	}{
		"RUN_ARGS overrides TLS settings": {sbHost{unit: sbJar, files: map[string]string{sbConf: sbConfJava + "RUN_ARGS=--server.ssl.ciphers=TLS_AES_128_GCM_SHA256\n"}}, "override"},
		"JAVA_OPTS changes Java's TLS":    {sbHost{unit: sbJar, files: map[string]string{sbConf: sbConfJava + "JAVA_OPTS=-Djava.security.properties=/etc/portal/sec\n"}}, "-Djava.security"},
		"JAVA_OPTS is not a plain value":  {sbHost{unit: sbJar, files: map[string]string{sbConf: sbConfJava + "JAVA_OPTS=\"$JAVA_OPTS -Xmx1g\"\n"}}, "JAVA_OPTS"},
		"shell commands in the .conf":     {sbHost{unit: sbJar, files: map[string]string{sbConf: sbConfJava + "source /etc/default/portal\n"}}, "line 2"},
		"TLS settings in the .conf":       {sbHost{unit: sbJar, files: map[string]string{sbConf: sbConfJava + "export SERVER_SSL_ENABLED_PROTOCOLS=TLSv1.3\n"}}, "SERVER_SSL_ENABLED_PROTOCOLS"},
		"JAVA_OPTS in the unit":           {sbHost{unit: sbJar, unitEnv: "Environment=JAVA_OPTS=-Djdk.tls.disabledAlgorithms=TLSv1.3\n", files: map[string]string{sbConf: sbConfJava}}, "-Djdk.tls"},
		"the .conf is somewhere else":     {sbHost{unit: sbJar, unitEnv: "Environment=CONF_FOLDER=/etc/portal\n", files: map[string]string{"/etc/portal/app.conf": "RUN_ARGS=--spring.config.location=/etc/portal/\n"}}, "/etc/portal/app.conf"},
		"another JAR is named":            {sbHost{unit: sbJar, unitEnv: "Environment=JARFILE=/opt/other/other.jar\n"}, "JARFILE"},
		"JAVA_OPTS is not java options":   {sbHost{unit: sbJar, files: map[string]string{sbConf: sbConfJava + "JAVA_OPTS=\"-cp /opt/x.jar\"\n"}}, "JAVA_OPTS"},
	} {
		tc.h.config, tc.h.script = conf, true
		_, inv := sbCollect(t, tc.h)
		for _, p := range []string{"tls.protocols", "tls.ciphers", "tls.ciphersuites-tls13"} {
			if e := sbEff(t, inv, p); e.Status != "unresolved" || !strings.Contains(e.Reason, tc.want) {
				t.Errorf("%s: %s: status=%s reason=%q, want unresolved with %q", name, p, e.Status, e.Reason, tc.want)
			}
		}
		// 引数や起動オプションの値は、結果に出さない（パスワードを引数で渡す運用がありうるため）
		out, _ := json.Marshal(inv)
		for _, v := range []string{"--server.ssl.ciphers=", "/etc/portal/sec", "disabledAlgorithms=TLSv1.3"} {
			if strings.Contains(string(out), v) {
				t.Errorf("%s: the value of an option (%s) appears in the result", name, v)
			}
		}
	}
}

// 起動の定義がない（または java -jar で起動する）場合の、実行できる JAR と .conf の扱い。
func TestSpringBootExecutableJarWithoutDirectLaunch(t *testing.T) {
	conf := map[string]string{"application.properties": sbBase + sbKS}
	risky := sbConfJava + "RUN_ARGS=--server.ssl.ciphers=TLS_AES_128_GCM_SHA256\n"
	// 起動の定義がない: スクリプトとして起動されているかは分からない。.conf に結果を変える指定がなければ、ない場合と同じ（JAVA_HOME は使わない）
	_, inv := sbCollect(t, sbHost{config: conf, script: true, files: map[string]string{sbConf: sbConfJava + "JAVA_OPTS=-Xmx1g\n"}})
	e := sbEff(t, inv, "tls.ciphersuites-tls13")
	checkSuites(t, e, 3, jdkTLS13, "medium")
	if !strings.Contains(strings.Join(e.Notes, " "), "every JDK") {
		t.Errorf("notes = %v", e.Notes)
	}
	// 結果を変える指定があれば、求めない
	_, inv = sbCollect(t, sbHost{config: conf, script: true, files: map[string]string{sbConf: risky}})
	sbUnresolved(t, inv, sbConf)
	_, inv = sbCollect(t, sbHost{config: conf, script: true, files: map[string]string{sbConf: "if true; then\n"}})
	sbUnresolved(t, inv, sbConf)
	// java -jar で起動する定義がある場合、スクリプトも .conf も使われない
	_, inv = sbCollect(t, sbHost{config: conf, script: true, unit: sbStart, files: map[string]string{sbConf: risky}})
	checkSuites(t, sbEff(t, inv, "tls.ciphersuites-tls13"), 3, jdkTLS13, "high")
	// 先頭にスクリプトのない JAR は、そのままでは起動できない。JAR そのものを起動する定義は使わず、.conf も読まない
	_, inv = sbCollect(t, sbHost{config: conf, unit: sbJar, files: map[string]string{sbConf: risky}})
	e = sbEff(t, inv, "tls.ciphersuites-tls13")
	checkSuites(t, e, 3, jdkTLS13, "medium")
	if !strings.Contains(strings.Join(e.Notes, " "), "every JDK") {
		t.Errorf("notes = %v", e.Notes)
	}
	// リンクを通して起動する場合は、リンクの隣の .conf も取り込まれる。そこまでは追わず、求めない
	prefixed := sbHost{config: conf, script: true, unit: "/opt/links/portal.jar"}
	_, inv = sbCollectWith(t, prefixed, func(prefix string) { link(t, prefix, "../portal/app.jar", "/opt/links/portal.jar") })
	sbUnresolved(t, inv, "symbolic link")
	if n := len(inv.Services); n != 1 {
		t.Errorf("the JAR must be recorded once, under its real path: %d services", n)
	}
}
