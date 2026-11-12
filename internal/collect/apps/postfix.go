package apps

import (
	"errors"
	"regexp"
	"strconv"
	"strings"

	"kagiya/internal/model"
	"kagiya/internal/parse/postfixconf"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

// このファイルは Postfix（受信側の smtpd）の設定の読み取り。
//
// Postfix の決まり方（検証ラボで、8 つのディストリの postfix を実際に起動して確かめたもの）:
//
//   - 全体の設定は main.cf。master.cf のサービスごとに、「-o 名前=値」で上書きできる。
//   - TLS を使うのは、smtpd_tls_security_level が may（STARTTLS は任意）か encrypt（必須）のとき。
//     最初から TLS で待ち受けるサービス（smtpd_tls_wrappermode = yes）は、必須として扱われる。
//   - 暗号は「等級」で指定する。任意のときは smtpd_tls_ciphers、必須のときは smtpd_tls_mandatory_ciphers の等級を使い、
//     等級に対応する暗号文字列（tls_<等級>_cipherlist）に、除外の指定（smtpd_tls_exclude_ciphers。必須のときは
//     smtpd_tls_mandatory_exclude_ciphers も）を「:!名前」として足したものが、OpenSSL に渡る。
//   - Postfix は OpenSSL のセキュリティレベルを 0 にする。システムの openssl.cnf の暗号文字列とレベルは効かない。
//   - 鍵交換のグループは Postfix 自身が決める（tls_eecdh_auto_curves と tls_ffdhe_auto_groups）。
//   - TLS 1.3 のスイートは Postfix が設定しないので、システムの設定、なければライブラリの既定になる。

// postfixFixed は、どの版でも同じ既定値（8 つの版の postconf -d で確かめた。既定値表を作るスクリプトが、違う版を見つけたら止まる）。
var postfixFixed = map[string]string{
	"smtpd_tls_security_level":            "",
	"smtpd_use_tls":                       "no",
	"smtpd_enforce_tls":                   "no",
	"smtpd_tls_wrappermode":               "no",
	"smtpd_tls_exclude_ciphers":           "",
	"smtpd_tls_mandatory_exclude_ciphers": "",
	"smtpd_tls_cert_file":                 "",
	"smtpd_tls_eccert_file":               "",
	"smtpd_tls_dcert_file":                "",
	"smtpd_tls_chain_files":               "",
	"smtpd_tls_dh1024_param_file":         "",
}

// postfixTable は、版ごとの既定値表（rules/defaults/postfix.yaml）から引く既定値。項目名 → 表のキー。
var postfixTable = map[string]string{
	"smtpd_tls_ciphers":           "tls.cipher-grade",
	"smtpd_tls_mandatory_ciphers": "tls.mandatory-cipher-grade",
	"tls_high_cipherlist":         "tls.cipherlist.high",
	"tls_medium_cipherlist":       "tls.cipherlist.medium",
	"tls_low_cipherlist":          "tls.cipherlist.low",
	"tls_export_cipherlist":       "tls.cipherlist.export",
	"tls_null_cipherlist":         "tls.cipherlist.null",
	"tls_eecdh_auto_curves":       "tls.eecdh-curves",
	"tls_ffdhe_auto_groups":       "tls.ffdhe-groups",
	"smtpd_tls_eecdh_grade":       "tls.eecdh-grade-default",
	"tls_eecdh_strong_curve":      "tls.eecdh-strong-curve",
	"tls_eecdh_ultra_curve":       "tls.eecdh-ultra-curve",
}

var (
	postfixListSep = regexp.MustCompile(`[, \t]+`)
	postfixToken   = regexp.MustCompile(`^[A-Za-z0-9_+-]{1,64}$`)
)

// postfixService は、1 つのサービスから見た設定（サービスごとの上書き > main.cf > 既定値）。
type postfixService struct {
	override map[string]postfixconf.Param
	main     map[string]postfixconf.Param
	defs     map[string][]string
	confDir  string
}

// explicit は、設定に書かれている記載を返す（サービスごとの上書きが優先）。
func (p *postfixService) explicit(name string) (postfixconf.Param, bool) {
	if v, ok := p.override[name]; ok {
		return v, true
	}
	v, ok := p.main[name]
	return v, ok
}

// raw は、展開する前の値を返す。値の分からない名前は ok = false。
func (p *postfixService) raw(name string) (string, bool) {
	if v, ok := p.explicit(name); ok {
		return v.Value, true
	}
	if name == "config_directory" {
		return p.confDir, true
	}
	if v, ok := postfixFixed[name]; ok {
		return v, true
	}
	if key, ok := postfixTable[name]; ok {
		if v, found := p.defs[key]; found {
			// 表では、空白で区切られた値を「:」でつないである（等級の暗号文字列は、もとから「:」区切り）
			s := strings.Join(v, ",")
			if key == "tls.eecdh-curves" || key == "tls.ffdhe-groups" {
				s = strings.ReplaceAll(s, ":", " ")
			}
			return s, true
		}
		if key == "tls.ffdhe-groups" || strings.HasPrefix(key, "tls.cipherlist.") {
			return "", p.defs != nil // この版にはない項目（空の既定）
		}
	}
	return "", false
}

// value は、項目の値を展開して返す。求められなければ、理由を返す。
func (p *postfixService) value(name string) (string, string) {
	v, ok := p.raw(name)
	if !ok {
		return "", "the default value of " + name + " is not recorded for this version"
	}
	out, err := postfixconf.Expand(v, p.raw)
	switch {
	case err == nil:
		return strings.TrimSpace(out), ""
	case errors.Is(err, postfixconf.ErrUnknownName):
		// エラーの文の末尾に名前が入っている（名前は英数字と「_」だけ）
		msg := err.Error()
		return "", "the value of " + name + " refers to " + msg[strings.LastIndexByte(msg, '\n')+1:] + ", whose value is not known"
	case errors.Is(err, postfixconf.ErrLoop):
		return "", "the value of " + name + " refers to itself"
	}
	return "", "the value of " + name + " uses a form of parameter expansion that is not interpreted"
}

func (c *Collector) postfix(app ruleset.AppRule, svc model.Service, config string) {
	if config == "" {
		return
	}
	data, err := c.read(config)
	if err != nil {
		return
	}
	confDir := dirOf(config)
	params, problems := postfixconf.ParseMain(config, data)
	for _, pr := range problems {
		c.Builder.Skip(safefs.Skip{Path: c.Prefix + config, Reason: "config-problem", Detail: pr})
	}
	main := map[string]postfixconf.Param{}
	for _, p := range params {
		main[p.Name] = p // 同じ項目は、後に書かれたものが効く
	}
	defs, _, _, _ := c.appDefaults(app)
	global := &postfixService{main: main, defs: defs, confDir: confDir}
	for _, p := range params {
		if main[p.Name] == p {
			c.postfixRecord(app, svc, global, p, "", confDir)
		}
	}

	masterFile := confDir + "/master.cf"
	var services []postfixconf.Service
	if mdata, err := c.read(masterFile); err == nil {
		var mproblems []string
		services, mproblems = postfixconf.ParseMaster(masterFile, mdata)
		for _, pr := range mproblems {
			c.Builder.Skip(safefs.Skip{Path: c.Prefix + masterFile, Reason: "config-problem", Detail: pr})
		}
	} else {
		c.Builder.Skip(safefs.Skip{Path: c.Prefix + masterFile, Reason: "config-problem", Detail: "not readable"})
	}

	var scopes []tlsScope
	n := 0
	for _, s := range services {
		if s.Type != "inet" || s.Command != "smtpd" {
			continue // 待ち受けて TLS を話すのは、種類が inet で、プログラムが smtpd のサービス
		}
		n++
		scope := "service " + s.Name + " inet"
		if !scopeText.MatchString(scope) {
			scope = "service#" + strconv.Itoa(n) + " inet"
		}
		p := &postfixService{override: map[string]postfixconf.Param{}, main: main, defs: defs, confDir: confDir}
		for _, o := range s.Overrides {
			p.override[o.Name] = o // 同じ項目は、後に書かれたものが効く
		}
		for _, o := range s.Overrides {
			if p.override[o.Name] == o {
				c.postfixRecord(app, svc, p, o, scope, confDir)
			}
		}
		if sc, ok := c.postfixScope(app, p, scope); ok {
			scopes = append(scopes, sc)
		}
	}
	c.opensslServerEffective(app, svc, scopes)
}

// postfixRecord は、設定に書かれた 1 項目を記録する。ほかの項目を参照している値は、展開できた場合にだけ展開して記録する。
func (c *Collector) postfixRecord(app ruleset.AppRule, svc model.Service, p *postfixService, param postfixconf.Param, scope, confDir string) {
	rule, ok := app.Directive(param.Name)
	if !ok {
		return
	}
	value := param.Value
	if strings.Contains(value, "$") {
		if v, reason := p.value(param.Name); reason == "" {
			value = v
		}
	}
	if value == "" || (rule.Type == "path" && value == "none") {
		return // 空の指定と、「証明書なし」の指定（ファイルではない）
	}
	if rule.Type == "words" {
		value = strings.Join(postfixListSep.Split(value, -1), " ") // カンマ区切りと空白区切りのどちらも使われる
	}
	c.record(app, svc, rule, value, param.File, param.Line, scope, confDir)
}

// postfixScope は、1 つのサービスについて、実効値の計算に渡す情報をまとめる。TLS を使わないサービスは ok = false。
func (c *Collector) postfixScope(app ruleset.AppRule, p *postfixService, scope string) (tlsScope, bool) {
	sc := tlsScope{name: scope}
	// 利用の水準。古い書き方（smtpd_use_tls、smtpd_enforce_tls）は、水準の指定がないときにだけ効く
	level, reason := p.value("smtpd_tls_security_level")
	wrapper, wreason := p.value("smtpd_tls_wrappermode")
	if reason == "" && level == "" {
		if v, _ := p.value("smtpd_enforce_tls"); v == "yes" {
			level = "encrypt"
		} else if v, _ := p.value("smtpd_use_tls"); v == "yes" {
			level = "may"
		}
	}
	block := func(r string) (tlsScope, bool) {
		sc.blocker, sc.groupsBlocker = r, r
		return sc, true
	}
	switch {
	case reason != "":
		return block(reason)
	case wreason != "":
		return block(wreason)
	case wrapper == "yes":
		// 最初から TLS の待ち受け。水準の指定によらず、必須として扱われる
	case level == "" || level == "none":
		return sc, false
	case level != "may" && level != "encrypt":
		return block("the TLS security level (smtpd_tls_security_level) is not one of none, may, encrypt")
	}
	mandatory := wrapper == "yes" || level == "encrypt"

	// 証明書。「none」は証明書なし（認証なしのスイートだけになる）。指定がなければ、TLS は有効にならない
	cert, reason := p.value("smtpd_tls_cert_file")
	if reason != "" {
		return block(reason)
	}
	chain, _ := p.value("smtpd_tls_chain_files")
	sc.certsOK = chain == "" // 鍵と証明書をまとめたファイルの並び（smtpd_tls_chain_files）は、どの証明書が使われるかを追わない
	if cert == "none" {
		sc.noCert = chain == ""
	} else {
		for _, name := range []string{"smtpd_tls_cert_file", "smtpd_tls_eccert_file", "smtpd_tls_dcert_file"} {
			v, reason := p.value(name)
			switch {
			case reason != "" || (v != "" && (!strings.HasPrefix(v, "/") || strings.ContainsAny(v, "$*?[ \t"))):
				sc.certsOK = false
			case v != "":
				sc.certs = append(sc.certs, v)
			}
		}
		if len(sc.certs) == 0 && sc.certsOK {
			return sc, false // 証明書の指定がない: TLS は提供されない
		}
	}
	if v, reason := p.value("smtpd_tls_dh1024_param_file"); reason == "" && v != "" {
		sc.dhParam = true
	}

	// 暗号: 等級 → 等級に対応する暗号文字列 → 除外の指定を足す
	gradeParam := "smtpd_tls_ciphers"
	excludeParams := []string{"smtpd_tls_exclude_ciphers"}
	if mandatory {
		gradeParam = "smtpd_tls_mandatory_ciphers"
		excludeParams = append(excludeParams, "smtpd_tls_mandatory_exclude_ciphers")
	}
	sc.blocker = func() string {
		if p.defs == nil {
			return "" // 既定値表がない版。共通の処理が、理由を付けて「不明」にする
		}
		grade, reason := p.value(gradeParam)
		if reason != "" {
			return reason
		}
		listParam := "tls_" + grade + "_cipherlist"
		if _, known := postfixTable[listParam]; !known {
			return "the cipher grade (" + gradeParam + ") is not one of high, medium, low, export, null"
		}
		rule, reason := p.value(listParam)
		if reason != "" {
			return reason
		}
		if rule == "" {
			return "the cipher list of this grade (" + listParam + ") is empty in this version"
		}
		configured := []string{gradeParam, listParam}
		for _, name := range excludeParams {
			v, reason := p.value(name)
			if reason != "" {
				return reason
			}
			for _, tok := range postfixListSep.Split(v, -1) {
				if tok == "" {
					continue
				}
				if !postfixToken.MatchString(tok) {
					return "the excluded ciphers (" + name + ") are not interpreted"
				}
				rule += ":!" + tok
			}
			configured = append(configured, name)
		}
		if !validCipherString(rule) {
			return "the cipher list of this grade (" + listParam + ") is not interpreted"
		}
		// 関わる項目のどれかが設定に書かれていれば、その記載を根拠として示す。どれも書かれていなければ、アプリの既定
		for _, name := range configured {
			if e, ok := p.explicit(name); ok {
				if d, found := app.Directive(name); found {
					sc.cipher, sc.cipherParam, sc.cipherFile, sc.cipherLine = rule, d.Parameter, e.File, e.Line
				}
				break
			}
		}
		return ""
	}()

	// 鍵交換のグループ
	sc.groupsBlocker = func() string {
		if p.defs == nil {
			return ""
		}
		grade, reason := p.value("smtpd_tls_eecdh_grade")
		if reason != "" {
			return reason
		}
		set := func(spec, name string) {
			e, _ := p.explicit(name)
			d, _ := app.Directive(name)
			sc.setGroups(spec, e.File, e.Line, name)
			sc.groupsParam = d.Parameter
		}
		honored := strings.Join(p.defs["tls.eecdh-grade"], ",")
		_, gradeSet := p.explicit("smtpd_tls_eecdh_grade")
		if grade != "auto" {
			switch {
			case honored == "ignored":
				// この版では、等級の指定は効かない（下の、曲線の並びの指定に進む）
			case honored != "honored" || (grade != "strong" && grade != "ultra"):
				return "the effect of the EECDH grade (smtpd_tls_eecdh_grade) is not recorded for this version"
			default:
				curve, reason := p.value("tls_eecdh_" + grade + "_curve")
				if reason != "" || !postfixToken.MatchString(curve) {
					return "the curve of the EECDH grade (smtpd_tls_eecdh_grade) is not known"
				}
				if gradeSet {
					set(curve, "smtpd_tls_eecdh_grade")
					return ""
				}
				return "the default EECDH grade of this version uses a single curve; the accepted groups are not resolved"
			}
		}
		for _, name := range []string{"tls_eecdh_auto_curves", "tls_ffdhe_auto_groups"} {
			if _, ok := p.explicit(name); !ok {
				continue
			}
			// どちらかが設定に書かれている: 両方の値（書かれていないほうは既定）をつないだものが、グループの並びになる
			var all []string
			for _, part := range []string{"tls_eecdh_auto_curves", "tls_ffdhe_auto_groups"} {
				v, reason := p.value(part)
				if reason != "" {
					return reason
				}
				for _, tok := range postfixListSep.Split(v, -1) {
					if tok != "" {
						all = append(all, tok)
					}
				}
			}
			set(strings.Join(all, ":"), name)
			break
		}
		return sc.groupsBlocker
	}()
	return sc, true
}
