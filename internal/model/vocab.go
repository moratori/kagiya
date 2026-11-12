package model

// 結果 JSON に現れる決まった値（語彙）。値そのものはスキーマの一部なので、変えるときはスキーマの版も上げること。

// 実効値の状態（EffectiveValue.Status）。
const (
	StatusResolved   = "resolved"   // 求められた
	StatusUnresolved = "unresolved" // 求められなかった（理由を Reason に残す）
)

// 確度（EffectiveValue.Confidence、Occurrence.Confidence）。
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium" // 近い版の実測を当てはめた、または絞り込みの一部をしていない
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
	ParamTLSCiphers       = "tls.ciphers"            // 暗号スイート（TLS 1.2 以下）
	ParamTLSCiphersuites  = "tls.ciphersuites-tls13" // 暗号スイート（TLS 1.3）
	ParamTLSProtocols     = "tls.protocols"
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
