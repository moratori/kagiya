// このファイルは、ルールの出典に書く「どう調べたか」（docs/confidence.md の 5 章）。

package ruleset

import (
	"errors"
	"fmt"
)

// 開発者が、ルールの項目の事実を調べた方法。
const (
	MethodEnumeratedByHandshake         = "enumerated-by-handshake"
	MethodReportedBySoftware            = "reported-by-software"
	MethodReadFromDistributedFiles      = "read-from-distributed-files"
	MethodReadFromUpstreamSourceCode    = "read-from-upstream-source-code"
	MethodReadFromUpstreamDocumentation = "read-from-upstream-documentation"
)

// Evidence は、開発者が、ルールの項目をどう調べたか。
type Evidence struct {
	Method              string `yaml:"method"`
	VerifiedByHandshake *bool  `yaml:"verified-by-handshake"`
}

// Verified は、開発者が、その版そのものの数え上げで裏付けたかを返す。書かれていなければ、裏付けはないものとして扱う。
func (e Evidence) Verified() bool { return e.VerifiedByHandshake != nil && *e.VerifiedByHandshake }

// EvidenceFor は、項目 1 つについての記載を返す。項目ごとの記載（items）があればそれ、なければ出典全体の記載。
func (s Source) EvidenceFor(item string) Evidence {
	if e, ok := s.Items[item]; ok {
		return e
	}
	return s.Evidence
}

var methods = map[string]bool{
	MethodEnumeratedByHandshake: true, MethodReportedBySoftware: true, MethodReadFromDistributedFiles: true,
	MethodReadFromUpstreamSourceCode: true, MethodReadFromUpstreamDocumentation: true,
}

// check は、記載の形を検証する。調べた方法と、裏付けの有無は、両方を書く。
// 数え上げで調べた項目は、数え上げそのもので得た事実なので、裏付けは必ず true。
func (e Evidence) check() error {
	switch {
	case !methods[e.Method]:
		return errors.New("method must be one of the five names (enumerated-by-handshake, reported-by-software, read-from-distributed-files, read-from-upstream-source-code, read-from-upstream-documentation)")
	case e.VerifiedByHandshake == nil:
		return errors.New("verified-by-handshake is required with method")
	case e.Method == MethodEnumeratedByHandshake && !*e.VerifiedByHandshake:
		return errors.New("verified-by-handshake must be true when method is enumerated-by-handshake")
	}
	return nil
}

// checkEvidence は、出典の「どう調べたか」の記載を検証する。
// 何も書かれていない出典は、読み込みでは受け付ける（裏付けのないものとして扱う）。内蔵のルールに記載があることは、テストで確かめる。
func (s Source) checkEvidence() error {
	if s.Method == "" && s.VerifiedByHandshake == nil {
		if len(s.Items) > 0 {
			return errors.New("items needs method and verified-by-handshake of the source")
		}
		return nil
	}
	if err := s.Evidence.check(); err != nil {
		return err
	}
	if len(s.Items) > 64 {
		return errors.New("too many items")
	}
	for name, e := range s.Items {
		if !idPattern.MatchString(name) {
			return fmt.Errorf("invalid item name %q", name)
		}
		if err := e.check(); err != nil {
			return fmt.Errorf("item %s: %w", name, err)
		}
	}
	return nil
}

// SourceAt は、出典と、それがどのルールのものか。
type SourceAt struct {
	Where  string
	Source Source
}

// AllSources は、読み込んだルールの出典を、すべて返す。
func (rs *RuleSet) AllSources() []SourceAt {
	var out []SourceAt
	add := func(where string, sources ...Source) {
		for _, s := range sources {
			out = append(out, SourceAt{where, s})
		}
	}
	builds := func(where string, list []CipherBuild) {
		for _, b := range list {
			add(where, b.Source)
		}
	}
	for _, x := range rs.Stores {
		add("os/stores", x.Sources...)
	}
	for _, x := range rs.Packages {
		add("os/packages", x.Sources...)
	}
	for _, x := range rs.Apps {
		add("apps/"+x.ID, x.Sources...)
	}
	for _, x := range rs.Libraries {
		add("libraries/"+x.ID, x.Sources...)
		if x.PQC != nil {
			add("libraries/"+x.ID+" (pqc)", x.PQC.Sources...)
		}
	}
	for _, x := range rs.JavaLibraries {
		add("libraries/"+x.ID, x.Sources...)
		if x.PQC != nil {
			add("libraries/"+x.ID+" (pqc)", x.PQC.Sources...)
		}
	}
	for _, x := range rs.Defaults {
		add("defaults/"+x.App, x.Source)
	}
	for _, x := range rs.CipherTables {
		builds("ciphers/"+x.Library, x.Builds)
	}
	for _, x := range rs.GroupTables {
		builds("groups/"+x.Library, x.Builds)
	}
	for _, x := range rs.JDKTables {
		builds("java/openjdk", x.Builds)
	}
	for _, x := range rs.TomcatTables {
		builds("java/tomcat", x.Builds)
	}
	for _, x := range rs.EmbeddedTomcatTables {
		add("java/tomcat-embedded", x.Source)
	}
	for _, x := range rs.SpringBootTables {
		add("java/springboot", x.Source)
	}
	for _, x := range rs.WildFlyTables {
		add("java/wildfly", x.Source)
	}
	return out
}
