//go:build unix

package apps

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"kagiya/internal/model"
	"kagiya/internal/ruleset"
)

// 検証ラボの測定結果（lab/out/tlsapp/wildfly/。場面ごとの standalone.xml と、実際に受け入れたものの数え上げ）があれば、
// 全部の版・全部の場面で、kagiya の求めた値と突き合わせる:
//
//	KAGIYA_WILDFLY_LAB=$PWD/lab/out/tlsapp/wildfly go test ./internal/collect/apps -run TestWildFlyAgainstLab -v
//
// 比べるのは、プロトコル、TLS 1.2 以下の暗号スイート（測定で使った証明書の種類で使えるもの）、TLS 1.3 の暗号スイート。
// kagiya が「不明」とした場面（測っていない書き方として、値を求めないもの）は、食い違いには数えず、別に数える。
// サーバーが起動しなかった場面（数え上げの記録がない）では、kagiya が値を出していないことを確かめる。
func TestWildFlyAgainstLab(t *testing.T) {
	root := os.Getenv("KAGIYA_WILDFLY_LAB")
	if root == "" {
		t.Skip("KAGIYA_WILDFLY_LAB is not set")
	}
	wfAgainstLab(t, root, "8443", wfScope)
}

// 管理用の待ち受け（lab/out/tlsapp/wildfly-mgmt/。TLS のポートは 9993）の測定結果との突き合わせ:
//
//	KAGIYA_WILDFLY_MGMT_LAB=$PWD/lab/out/tlsapp/wildfly-mgmt go test ./internal/collect/apps -run TestWildFlyManagementAgainstLab -v
//
// サーバーは起動したが、TLS のポートが開かなかった場面（TLS 用のソケットを指定していない設定）では、kagiya が、管理用の待ち受けについて
// 何も出していないこと（値も「不明」も）を確かめる。
func TestWildFlyManagementAgainstLab(t *testing.T) {
	root := os.Getenv("KAGIYA_WILDFLY_MGMT_LAB")
	if root == "" {
		t.Skip("KAGIYA_WILDFLY_MGMT_LAB is not set")
	}
	wfAgainstLab(t, root, "9993", wfMgmtScope)
}

func wfAgainstLab(t *testing.T, root, port, scope string) {
	rs, err := ruleset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	// TLS での番号 → Java での名前（Tomcat の表にある対応）
	byID := map[string]string{}
	for _, tb := range rs.TomcatTables {
		for _, s := range tb.Suites {
			id := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(s.ID, "0x", ""), ",", ""))
			for _, j := range s.JSSE {
				if strings.HasPrefix(j, "TLS_") {
					byID[id] = j
				}
			}
		}
	}
	dirs, _ := filepath.Glob(filepath.Join(root, "ubuntu2404-wf*"))
	sort.Strings(dirs)
	match, declined, mismatch, versions, notStarted, noTLS := 0, 0, 0, 0, 0, 0
	for _, dir := range dirs {
		version := strings.SplitN(filepath.Base(dir), "-wf", 2)[1]
		scenes, _ := filepath.Glob(filepath.Join(dir, "*.standalone.xml"))
		if len(scenes) == 0 {
			continue
		}
		versions++
		for _, xmlPath := range scenes {
			scene := strings.TrimSuffix(filepath.Base(xmlPath), ".standalone.xml")
			measured, err := os.ReadFile(filepath.Join(dir, scene+"."+port+".one.tsv"))
			start, err2 := os.ReadFile(filepath.Join(dir, scene+".start.txt"))
			xml, err3 := os.ReadFile(xmlPath)
			if err2 != nil || err3 != nil {
				continue
			}
			// 数え上げの記録がないのは、その設定でサーバーが起動しなかった（待ち受けが開かなかった）場面
			started := err == nil
			pkg := pkgJava17Ubu
			if strings.Contains(string(start), "java-11-openjdk") {
				pkg = pkgJava11Ubu
			} else if !strings.Contains(string(start), "java-17-openjdk") {
				t.Errorf("%s %s: the JDK of the measurement is not known", version, scene)
				continue
			}
			want := map[string][]string{}
			for _, line := range strings.Split(strings.TrimSpace(string(measured)), "\n") {
				f := strings.Fields(line)
				if len(f) != 2 {
					continue
				}
				name := byID[strings.ToLower(strings.TrimPrefix(f[1], "0x"))]
				if name == "" {
					t.Fatalf("%s %s: unknown suite %s", version, scene, f[1])
				}
				want[f[0]] = append(want[f[0]], name)
			}
			var wantProtocols []string
			for p, name := range map[string]string{"tls1_3": "TLSv1.3", "tls1_2": "TLSv1.2", "tls1_1": "TLSv1.1", "tls1": "TLSv1"} {
				if len(want[p]) > 0 {
					wantProtocols = append(wantProtocols, name)
				}
			}
			kind := "RSA"
			if strings.HasSuffix(scene, "e-eccert") {
				kind = "EC"
			}
			_, inv := collect(t, "", wfHost(t, version, string(xml), nil, pkg))
			var e12, e13, ep model.EffectiveValue
			inScope := 0
			for _, e := range inv.EffectiveValues {
				if e.Scope != scope {
					continue
				}
				inScope++
				switch e.Parameter {
				case "tls.ciphers":
					e12 = e
				case "tls.ciphersuites-tls13":
					e13 = e
				case "tls.protocols":
					ep = e
				}
			}
			// サーバーは問題なく起動し、管理用の HTTP のポート（9990）は開いたが、測るポートだけが開かなかった場面は、TLS で待ち受けない設定
			ports, _ := os.ReadFile(filepath.Join(dir, scene+".ports.txt"))
			tlsOff := !started && strings.Contains(string(start), "WFLYSRV0025") && strings.Contains(string(ports), "9990")
			switch {
			case tlsOff && inScope == 0:
				noTLS++
			case tlsOff:
				mismatch++
				t.Errorf("%s %s: the server started without listening on %s, but something is reported for %q: protocols=%v %s", version, scene, port, scope, ep.Values, ep.Reason)
			case !started && e12.Status == "unresolved" && e13.Status == "unresolved" && ep.Status == "unresolved":
				notStarted++ // 起動しない設定では、kagiya も値を出さない
			case !started:
				mismatch++
				t.Errorf("%s %s: the server did not start with this configuration, but values are resolved: protocols=%v", version, scene, ep.Values)
			case e12.Status == "unresolved" && strings.Contains(e12.Reason, "measured"):
				declined++
				t.Logf("%s %s: not resolved by design: %s", version, scene, e12.Reason)
			case e12.Status != "resolved" || e13.Status != "resolved" || ep.Status != "resolved":
				mismatch++
				t.Errorf("%s %s: not resolved: %s", version, scene, e12.Reason)
			case sortedJoin(wfKind(e12.Values, kind)) != sortedJoin(want["tls1_2"]) || sortedJoin(e13.Values) != sortedJoin(want["tls1_3"]) || sortedJoin(ep.Values) != sortedJoin(wantProtocols):
				mismatch++
				if mismatch <= 20 {
					t.Errorf("%s %s:\n  kagiya   protocols=%v tls12=%s tls13=%s\n  measured protocols=%v tls12=%s tls13=%s", version, scene,
						ep.Values, sortedJoin(wfKind(e12.Values, kind)), sortedJoin(e13.Values), wantProtocols, sortedJoin(want["tls1_2"]), sortedJoin(want["tls1_3"]))
				}
			default:
				match++
			}
		}
	}
	if match == 0 {
		t.Error("nothing was compared")
	}
	t.Logf("%d versions: %d scenes match, %d not resolved by design, %d did not start (and are not resolved), %d do not listen with TLS (and nothing is reported), %d differ",
		versions, match, declined, notStarted, noTLS, mismatch)
}
