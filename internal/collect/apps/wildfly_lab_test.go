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
func TestWildFlyAgainstLab(t *testing.T) {
	root := os.Getenv("KAGIYA_WILDFLY_LAB")
	if root == "" {
		t.Skip("KAGIYA_WILDFLY_LAB is not set")
	}
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
	match, declined, mismatch, versions := 0, 0, 0, 0
	for _, dir := range dirs {
		version := strings.SplitN(filepath.Base(dir), "-wf", 2)[1]
		scenes, _ := filepath.Glob(filepath.Join(dir, "*.standalone.xml"))
		if len(scenes) == 0 {
			continue
		}
		versions++
		for _, xmlPath := range scenes {
			scene := strings.TrimSuffix(filepath.Base(xmlPath), ".standalone.xml")
			measured, err := os.ReadFile(filepath.Join(dir, scene+".8443.one.tsv"))
			start, err2 := os.ReadFile(filepath.Join(dir, scene+".start.txt"))
			xml, err3 := os.ReadFile(xmlPath)
			if err != nil || err2 != nil || err3 != nil {
				continue
			}
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
			if scene == "e-eccert" {
				kind = "EC"
			}
			_, inv := collect(t, "", wfHost(t, version, string(xml), nil, pkg))
			var e12, e13, ep model.EffectiveValue
			for _, e := range inv.EffectiveValues {
				if e.Scope != wfScope {
					continue
				}
				switch e.Parameter {
				case "tls.ciphers":
					e12 = e
				case "tls.ciphersuites-tls13":
					e13 = e
				case "tls.protocols":
					ep = e
				}
			}
			switch {
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
	t.Logf("%d versions: %d scenes match, %d not resolved by design, %d differ", versions, match, declined, mismatch)
}
