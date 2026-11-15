// このファイルは、パッケージの版の文字列の読み取りと、測っていない版を補う決まり（docs/confidence.md の 6.2 節）。
// 補う決まりは、暗号スイート・グループ・JDK・Tomcat の表（findBuild）と、アプリの既定値（AppDefaultsFor）で共通。

package ruleset

import (
	"regexp"
	"strings"
)

// ディストリの系列。RHEL 系は、ふつうのパッケージ（.el9）のほかに、モジュールで配られるパッケージの形がある
// （RHEL が作ったものは「module+el9」、AlmaLinux が作ったものは「module_el9」）。区切りの文字ごと取り出すので、
// この 3 つは別の系列として扱われる（配布元の違うモジュールの表を、互いに当てはめない）。
var distroTagPattern = regexp.MustCompile(`[.+_]el[0-9]+|ubuntu|deb[0-9]+`)

// upstreamOf は、パッケージ版から上流の版を取り出す（エポックと、リリース以降を落とす）。
func upstreamOf(version string) string {
	if i := strings.IndexByte(version, ':'); i >= 0 {
		version = version[i+1:]
	}
	if i := strings.IndexByte(version, '-'); i >= 0 {
		version = version[:i]
	}
	return version
}

// distroTag は、パッケージ版からディストリの系列（.el9、+el9、_el9、ubuntu、deb13 など）を取り出す。分からなければ空。
func distroTag(version string) string {
	if i := strings.IndexByte(version, '-'); i >= 0 {
		return distroTagPattern.FindString(version[i:])
	}
	return ""
}

// canInterpolate は、測った版 measured の表で、導入されている版 installed を補えるかを返す。
// 補えるのは、開発元の版とディストリの系列が同じ（作り直しの番号だけが違う）場合だけ。系列を読み取れない版は補わない。
// パッケージ名が同じことは、呼び出し側が確かめる。
func canInterpolate(installed, measured string) bool {
	tag := distroTag(installed)
	return tag != "" && distroTag(measured) == tag && upstreamOf(measured) == upstreamOf(installed)
}

// findBuild は、パッケージ版ごとの実測の表（暗号スイート、鍵交換のグループ、JDK、Tomcat）から、導入されている版に対応するものを探す。
// 実測した版そのものがあれば exact = true。なければ、パッケージ名・上流の版・ディストリの系列が同じ実測版で補間する（canInterpolate）。
// 表の上流の版は、表に載っている版の文字列の上流の版と同じ（checkBuilds が、読み込みのときに確かめている）。
func findBuild(library, pkg, version string, n int, at func(i int) (library string, builds []CipherBuild)) (index int, build CipherBuild, exact, ok bool) {
	if version == "" {
		return 0, CipherBuild{}, false, false
	}
	for i := 0; i < n; i++ {
		lib, builds := at(i)
		if lib != library {
			continue
		}
		for _, b := range builds {
			if b.Package == pkg && b.Version == version {
				return i, b, true, true
			}
		}
	}
	for i := 0; i < n; i++ {
		lib, builds := at(i)
		if lib != library {
			continue
		}
		for _, b := range builds {
			if b.Package == pkg && canInterpolate(version, b.Version) {
				return i, b, false, true
			}
		}
	}
	return 0, CipherBuild{}, false, false
}
