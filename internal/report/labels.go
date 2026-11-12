// このファイルは、レポートに出す文言（判定や状態の表示名、マウスを載せると出る説明、項目名）。

package report

import (
	"strconv"

	"kagiya/internal/model"
)

var quantumBadge = map[string]badge{
	"vulnerable":   {"量子計算機に弱い", "bad", "現行の公開鍵暗号（RSA、楕円曲線、DH など）。暗号解読に使える水準の量子計算機ができると破られるため、耐量子の方式への移行の対象です"},
	"hybrid":       {"ハイブリッド", "good", "現行の方式と耐量子の方式を組み合わせた鍵交換。どちらか一方が破られても安全性が保たれるように作られています"},
	"resistant":    {"耐量子", "good", "量子計算機でも破れないと考えられている方式（耐量子の公開鍵暗号、または十分な長さの共通鍵暗号・ハッシュ関数）"},
	"reduced":      {"量子計算機で強度が下がる", "warn", "共通鍵暗号・ハッシュ関数のうち、量子計算機で強度が下がり、CRYPTREC の耐量子計算機暗号リストに載っていない長さのもの（AES-128、SHA-256 など）。NIST は置き換えを求めていません"},
	"not-targeted": {"対象外", "none", "参照した文書に、耐量子の観点での記載がない共通鍵暗号・MAC など"},
	"unknown":      {"判定できない", "unk", "この情報だけでは判定できないもの（参照した文書に記載がない方式、または決まり方が別の設定によるもの）"},
}

var classicalBadge = map[string]badge{
	"weak":    {"危殆化", "bad", "現在の計算機でも安全とは言えないもの。すでに解読の恐れがある方式や、必要な強度（112 ビット）に満たない鍵長・方式です"},
	"legacy":  {"非推奨", "warn", "いますぐ危険ではないが、公的な文書で推奨されなくなった方式や、強度が 112 ビットで移行の期限（2030 年）が示されているもの"},
	"ok":      {"指摘なし", "none", "参照した文書に照らして、現在の計算機に対する問題は見つかっていないもの（量子計算機に対する評価は別の列です）"},
	"unknown": {"判定できない", "unk", "参照した文書に記載がなく、判定できないもの"},
}

var activityTip = map[string]string{
	"running":    "プロセスが動いていることを確認できたもの",
	"enabled":    "OS の起動時に立ち上がるよう設定されているサービス（実際に動いているかは確認していません）",
	"referenced": "サービスの設定ファイルから参照されているもの",
	"installed":  "導入されているが、起動するよう設定されていないもの（手動で起動されている可能性はあります）",
	"unknown":    "このツールが読んだ設定からは、使われ方が分からないもの",
}

// 読み飛ばしの理由の表示名。
var skipLabel = map[string]string{
	"permission-denied":    "権限がなく読めなかった",
	"network-fs":           "ネットワーク越しのファイルシステム（読まない）",
	"unknown-fs":           "種別が分からないファイルシステム（読まない）",
	"excluded":             "除外の指定（結果の出力先など）",
	"not-found":            "指定された場所がなかった",
	"invalid-root":         "探索の起点として使えなかった",
	"parse-error":          "形式を解釈できなかった",
	"config-problem":       "設定ファイルの一部を読めなかった",
	"invalid-value":        "設定値として妥当でなかった",
	"not-interpreted":      "値を確定できなかった設定（変数を含むなど）",
	"unrecognized-setting": "記録の対象外の設定項目",
}

var activityLabel = map[string]string{
	"running": "稼働中", "enabled": "有効", "referenced": "参照あり", "installed": "導入のみ", "unknown": "不明",
}

var parameterLabel = map[string]string{
	"tls.ciphers":                       "暗号スイート（TLS 1.2 以下）",
	"tls.ciphersuites-tls13":            "暗号スイート（TLS 1.3）",
	"tls.protocols":                     "プロトコル",
	"tls.listen":                        "待ち受け",
	"tls.enabled":                       "TLS の有効化",
	"tls.groups":                        "鍵交換のグループ",
	"tls.prefer-server-ciphers":         "サーバー側の優先順を使う",
	"tls.certificate":                   "証明書",
	"tls.private-key":                   "秘密鍵",
	"tls.certificate-chain":             "証明書チェーン",
	"tls.dh-params":                     "DH パラメータ",
	"tls.trusted-certificates":          "信頼する証明書",
	"tls.client-ca":                     "クライアント証明書の CA",
	"tls.openssl-conf-cmd":              "OpenSSL の設定を直接変える指定",
	"tls.starttls-level":                "TLS の利用の水準（STARTTLS）",
	"tls.enabled-legacy":                "TLS の有効化（古い書き方）",
	"tls.required-legacy":               "TLS の必須化（古い書き方）",
	"tls.wrapper-mode":                  "最初から TLS で待ち受ける",
	"tls.cipher-grade":                  "暗号の等級",
	"tls.mandatory-cipher-grade":        "暗号の等級（TLS が必須のとき）",
	"tls.exclude-ciphers":               "除外する暗号",
	"tls.mandatory-exclude-ciphers":     "除外する暗号（TLS が必須のとき）",
	"tls.mandatory-protocols":           "プロトコル（TLS が必須のとき）",
	"tls.ffdhe-groups":                  "鍵交換のグループ（有限体 DH）",
	"tls.eecdh-grade":                   "楕円曲線の等級（古い書き方）",
	"ssh.kex-algorithms":                "鍵交換",
	"ssh.gssapi-kex-algorithms":         "GSSAPI の鍵交換",
	"ssh.host-key-algorithms":           "ホスト鍵の署名方式",
	"ssh.pubkey-accepted-algorithms":    "公開鍵認証で受け付ける署名方式",
	"ssh.hostbased-accepted-algorithms": "ホストベース認証で受け付ける署名方式",
	"ssh.ca-signature-algorithms":       "証明書の署名で受け付ける方式",
	"ssh.ciphers":                       "暗号",
	"ssh.macs":                          "MAC",
	"ssh.required-rsa-size":             "RSA 鍵長の下限",
	"ssh.protocol":                      "プロトコルの版",
	"ssh.host-key":                      "ホスト鍵",
}

func location(path string, line int) string {
	if path == "" {
		return ""
	}
	if line > 0 {
		return path + ":" + strconv.Itoa(line)
	}
	return path
}

func label(parameter string) string {
	if l, ok := parameterLabel[parameter]; ok {
		return l
	}
	return parameter
}

func evidenceText(e model.Evidence) string {
	kind := map[string]string{
		"unit-enabled": "起動するよう設定されている", "unit-masked": "起動しないよう設定されている", "unit-present": "起動の定義がある（有効化はされていない）",
		"binary-present": "プログラムが導入されている", "config-reference": "設定から参照されている",
	}[e.Kind]
	if kind == "" {
		kind = e.Kind
	}
	s := kind
	if e.Detail != "" {
		s += "（" + label(e.Detail) + "）"
	}
	if loc := location(e.Path, e.Line); loc != "" {
		s += " " + loc
	}
	return s
}
