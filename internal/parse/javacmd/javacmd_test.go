package javacmd

import (
	"strings"
	"testing"
)

// 「java ... -jar <JAR> ...」の形の起動コマンドから、Java の実行ファイル、JAR、プロファイルの指定を読む。
func TestParse(t *testing.T) {
	c, ok := Parse([]string{"/usr/bin/java", "-Xmx512m", "-Dspring.profiles.active=prod,tls", "-jar", "/opt/app/app.jar", "--server.port=8443", "--spring.profiles.active=web"})
	if !ok || c.Java != "/usr/bin/java" || c.Jar != "/opt/app/app.jar" {
		t.Fatalf("command = %+v ok=%v", c, ok)
	}
	// 起動時の引数（--）は、-D の指定より優先される（Spring Boot の優先順）
	if strings.Join(c.Profiles, ",") != "web" || !c.ProfilesSet {
		t.Errorf("profiles = %v", c.Profiles)
	}
	if c.Risky != "" || c.Overrides {
		t.Errorf("risky=%q overrides=%v", c.Risky, c.Overrides)
	}
	c, _ = Parse([]string{"/usr/lib/jvm/java-21/bin/java", "-Dspring.profiles.active=prod,tls", "-jar", "app.jar"})
	if strings.Join(c.Profiles, ",") != "prod,tls" || c.Jar != "app.jar" {
		t.Errorf("command = %+v", c)
	}
}

// 起動時の指定で、TLS の設定が変わりうるもの: Java の起動オプション（-Djava.security... など）と、Spring の設定の上書き。
// 値は持たない（どの指定があったかの名前だけ）。
func TestRiskyAndOverrides(t *testing.T) {
	c, ok := Parse([]string{"/usr/bin/java", "-Djava.security.properties=/etc/app/sec", "-jar", "/opt/app/app.jar"})
	if !ok || !strings.Contains(c.Risky, "-Djava.security") || strings.Contains(c.Risky, "/etc/app/sec") {
		t.Errorf("risky = %q", c.Risky)
	}
	for _, arg := range []string{"--server.ssl.ciphers=TLS_AES_128_GCM_SHA256", "--server.ssl.key-store-password=s3cret", "--spring.config.location=/etc/app/", "--spring.config.additional-location=file:/x/", "--spring.ssl.bundle.jks.web.keystore.location=/x"} {
		c, _ := Parse([]string{"/usr/bin/java", "-jar", "/opt/app/app.jar", arg})
		if !c.Overrides {
			t.Errorf("%s: must be reported as an override", arg)
		}
	}
	for _, opt := range []string{"-Dserver.ssl.enabled-protocols=TLSv1.3", "-Dspring.config.location=/etc/app/", "-Dserver.ssl.keyStorePassword=s3cret"} {
		c, _ := Parse([]string{"/usr/bin/java", opt, "-jar", "/opt/app/app.jar"})
		if !c.Overrides {
			t.Errorf("%s: must be reported as an override", opt)
		}
	}
	// 関係のない指定は妨げにならない
	c, _ = Parse([]string{"/usr/bin/java", "-Xms1g", "-Dfile.encoding=UTF-8", "-Dlogging.level.root=INFO", "-jar", "/opt/app/app.jar", "--server.port=9443", "--logging.file.name=/var/log/app.log"})
	if c.Risky != "" || c.Overrides {
		t.Errorf("unrelated options: %+v", c)
	}
}

// java -jar の形でないものは、対象にしない。
func TestNotJavaJar(t *testing.T) {
	for _, argv := range [][]string{
		nil,
		{"/opt/app/start.sh"},
		{"/usr/bin/java", "-cp", "/opt/app/lib/*", "com.example.Main"},
		{"/usr/bin/java", "-jar"},
		{"/usr/bin/python3", "-jar", "x.jar"},
		{"java", "-jar", "/opt/app/app.jar"},        // 実行ファイルが絶対パスでない（PATH しだいで、どの Java か決まらない）
		{"/usr/bin/java", "-jar", "/opt/app/app"},   // JAR でない
		{"/usr/bin/java", "-jar", "${APP_JAR}"},     // 置き換えられなかった変数
		{"/bin/sh", "-c", "java -jar /opt/app.jar"}, // シェルを通す形は解釈しない
	} {
		if c, ok := Parse(argv); ok {
			t.Errorf("%v: must not be accepted: %+v", argv, c)
		}
	}
	// 実行ファイルの名前が java であればよい（JDK のディレクトリの下など）
	if _, ok := Parse([]string{"/opt/jdk-21/bin/java", "-jar", "/opt/app/app.war"}); !ok {
		t.Error("a java binary under any directory, and a .war, must be accepted")
	}
}
