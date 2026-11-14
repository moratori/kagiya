package model

// 結果 JSON に現れる決まった値（語彙）。値そのものはスキーマの一部なので、変えるときはスキーマの版も上げること。

// 実効値の状態（EffectiveValue.Status）。
const (
	StatusResolved   = "resolved"   // 求められた
	StatusUnresolved = "unresolved" // 求められなかった（理由を Reason に残す）
)

// 証明書・鍵などの出現（Occurrence.Confidence）の確度。ファイルを実際に読んで見つけたものは、高。
// 実効値（EffectiveValue.Confidence）の確度は、別の尺度で、internal/confidence だけが決める（docs/confidence.md）。
const (
	ConfidenceHigh = "high"
)

// 実効値の読み方についての説明（EffectiveValue.Qualifiers）。確度を下げる理由にはしない（docs/confidence.md の 6.5〜6.7 節）。
const (
	// 証明書の種類が分からないので、RSA の証明書の場合と EC の証明書の場合に受け入れるものを、合わせて挙げた
	QualifierAnyCertificateKind = "any-certificate-kind"
	// 動かす JDK を 1 つに決められず、見つけた JDK のどれで動いていても同じ値だった
	QualifierAnyJDKFound = "any-jdk-found"
	// 受け入れるものが 1 つもない設定
	QualifierNothingAccepted = "nothing-accepted"
)

// 利用の確からしさ（Activity.Level）。
const (
	ActivityRunning    = "running"    // 稼働中のプロセスが使っている
	ActivityEnabled    = "enabled"    // 起動するよう設定されたサービスが使う
	ActivityReferenced = "referenced" // 設定から参照されている
	ActivityInstalled  = "installed"  // 導入されているだけ
	ActivityUnknown    = "unknown"    // 判断材料がない
)

// IsActive は、起動するよう設定されている（稼働中を含む）段階かを返す。
func IsActive(level string) bool { return level == ActivityRunning || level == ActivityEnabled }

// アプリをまたいで揃えている設定項目の名前のうち、コードから名指しで使うもの。
const (
	ParamTLSCiphers      = "tls.ciphers"            // 暗号スイート（TLS 1.2 以下）
	ParamTLSCiphersuites = "tls.ciphersuites-tls13" // 暗号スイート（TLS 1.3）
	ParamTLSProtocols    = "tls.protocols"
	// OS 設定: システムの openssl.cnf に書かれているが、値を記録しなかった項目（値は項目の名前）。
	// 後の処理が「指定なし」として扱わないための印
	OSSettingOpenSSLUnread = "openssl.system_default.unread"

	ParamTLSGroups        = "tls.groups"                // 鍵交換のグループ（楕円曲線、有限体 DH、耐量子のハイブリッド）
	ParamTLSDHEWithout    = "tls.dhe-without-params"    // 既定の表: DH パラメータなしで DHE を使えるか
	ParamTLSCertSelection = "tls.certificate-selection" // 既定の表: 同じ名前の証明書を複数使えるか
)

// 評価の値（Verdict.Quantum、Verdict.Classical）と、規則の役割。
const (
	QuantumVulnerable  = "vulnerable"
	QuantumHybrid      = "hybrid"
	QuantumResistant   = "resistant"
	QuantumReduced     = "reduced"
	QuantumNotTargeted = "not-targeted"
	QuantumUnknown     = "unknown"

	ClassicalWeak    = "weak"
	ClassicalLegacy  = "legacy"
	ClassicalOK      = "ok"
	ClassicalUnknown = "unknown"

	RoleKeyEstablishment = "key-establishment"
)

// FullVersion は、パッケージの版を、既定値表・対応表と突き合わせる形（rpm は「版-リリース」、dpkg は Version の全体）で返す。
func (p Package) FullVersion() string { return joinVersion(p.Version, p.Release) }

// FullVersion は、パッケージの版を「版-リリース」の形で返す。
func (p PackageRef) FullVersion() string { return joinVersion(p.Version, p.Release) }

func joinVersion(version, release string) string {
	if release != "" {
		return version + "-" + release
	}
	return version
}
