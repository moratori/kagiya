// Package model は結果 JSON（kagiya-inventory）のデータモデル。
// Phase 3 完了までは v0 とし、互換性を保証しない。
package model

import "kagiya/internal/platform"

const Schema = "kagiya-inventory/v0"

type Inventory struct {
	Schema      string       `json:"schema"`
	Meta        Meta         `json:"meta"`
	Assets      []Asset      `json:"assets"`
	Occurrences []Occurrence `json:"occurrences"`
	// 見つかったパッケージ管理データベースと、そこから読んだ暗号関連のパッケージ（版の特定に使う）
	PackageDatabases []PackageDatabase `json:"package_databases"`
	Packages         []Package         `json:"packages"`
	// OS 全体の暗号設定（暗号ポリシー、ライブラリのシステム既定の設定など）
	OSSettings []OSSetting `json:"os_settings"`
	// サービス（アプリケーションのインスタンス）と、その設定値
	Services []Service `json:"services"`
	Settings []Setting `json:"settings"`
	// 実効値: 設定の記載と既定値から求めた、実際に効く値
	EffectiveValues []EffectiveValue `json:"effective_values"`
	// 見つかったアプリケーションと暗号ライブラリ、およびそのリンク関係
	Components []Component `json:"components"`
	// 評価: スキャン時点の評価ポリシーによる判定（参考値。レポートの生成時には、その時点のポリシーで判定し直す）
	Assessment *Assessment `json:"assessment,omitempty"`
	Skipped    []Skipped   `json:"skipped"`
	Coverage   Coverage    `json:"coverage"`
}

// Component はアプリケーションのバイナリ、または暗号ライブラリ。
type Component struct {
	ID      string            `json:"id"`
	Kind    string            `json:"kind"` // application | library
	Name    string            `json:"name"` // ルール上の ID（nginx、openssl など）
	Path    string            `json:"path"` // リンクを辿った先の実際のパス
	Version *ComponentVersion `json:"version,omitempty"`
	Package *PackageRef       `json:"package,omitempty"`
	Links   []Link            `json:"links,omitempty"`
	Notes   []string          `json:"notes,omitempty"`
}

type ComponentVersion struct {
	Value  string `json:"value"`
	Source string `json:"source"` // binary-string: ファイルに埋め込まれた版文字列
}

// PackageRef は、そのコンポーネントを含むと考えられるパッケージ（ディストリによる改変を識別するための版）。
type PackageRef struct {
	Name    string `json:"name"`
	Epoch   int    `json:"epoch,omitempty"`
	Version string `json:"version"`
	Release string `json:"release,omitempty"`
}

// Link はアプリケーションから暗号ライブラリへのリンク。
type Link struct {
	SOName     string `json:"soname"`
	Via        string `json:"via"`                 // needed: 本体が直接リンク / module: 実行時に読み込まれるモジュール経由
	Module     string `json:"module,omitempty"`    // via=module のときのモジュールのパス
	Path       string `json:"path,omitempty"`      // 解決した実際のパス
	Component  string `json:"component,omitempty"` // ライブラリのコンポーネント ID
	ResolvedBy string `json:"resolved_by"`         // rpath | runpath | ld.so.cache | default-path | unresolved
}

type PackageDatabase struct {
	Manager  string `json:"manager"` // rpm | dpkg
	Format   string `json:"format"`  // bdb | sqlite | status
	Path     string `json:"path"`
	Packages int    `json:"packages"`           // 導入済みパッケージの総数
	Unparsed int    `json:"unparsed,omitempty"` // 読めなかった件数（更新途中などで整合しなかったもの）
	WAL      bool   `json:"wal,omitempty"`      // 先行書き込みログの内容を反映して読んだ
}

// Package は導入済みパッケージ。記録するのはルール（os/packages.yaml）で役割が定義されたものだけ。
type Package struct {
	Manager string `json:"manager"`
	Name    string `json:"name"`
	Epoch   int    `json:"epoch,omitempty"`
	Version string `json:"version"`
	Release string `json:"release,omitempty"` // rpm のリリース（ディストリによる改変を識別する部分）
	Arch    string `json:"arch,omitempty"`
	Source  string `json:"source,omitempty"`
	Role    string `json:"role"`
}

type Meta struct {
	ScanID     string            `json:"scan_id"`
	StartedAt  string            `json:"started_at"`
	FinishedAt string            `json:"finished_at"`
	Completed  bool              `json:"completed"`
	Incomplete string            `json:"incomplete_reason,omitempty"`
	Tool       Tool              `json:"tool"`
	Rules      Rules             `json:"rules"`
	Host       Host              `json:"host"`
	Labels     map[string]string `json:"labels,omitempty"`
	Invocation Invocation        `json:"invocation"`
	Privilege  Privilege         `json:"privilege"`
	Hardening  platform.Status   `json:"hardening"`
	Warnings   []string          `json:"warnings,omitempty"`
}

type Tool struct {
	Version string `json:"version"`
}

type Rules struct {
	Source  string `json:"source"` // builtin | external
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type Host struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	// ディストリの名前と版（Linux の /etc/os-release から）。読めなければ nil
	Distribution *Distribution `json:"distribution,omitempty"`
}

type Distribution struct {
	ID        string `json:"id,omitempty"`         // rhel、ubuntu など
	VersionID string `json:"version_id,omitempty"` // 9.9、24.04 など
	Name      string `json:"name,omitempty"`       // 表示用の名前（PRETTY_NAME）
}

type Invocation struct {
	Roots    []string `json:"roots"`
	Excludes []string `json:"excludes,omitempty"`
}

type Privilege struct {
	Elevated bool `json:"elevated"`
}

type Asset struct {
	ID          string       `json:"id"`
	Type        string       `json:"type"` // algorithm | certificate | private-key | public-key | csr | keystore
	Algorithm   *Algorithm   `json:"algorithm,omitempty"`
	Certificate *Certificate `json:"certificate,omitempty"`
	Key         *Key         `json:"key,omitempty"`
	CSR         *CSR         `json:"csr,omitempty"`
	Keystore    *Keystore    `json:"keystore,omitempty"`
}

// Key は秘密鍵または公開鍵。形式や暗号化の有無はファイルごとに違い得るので、出現（Occurrence.Detail）側に持つ。
type Key struct {
	Algorithm               string `json:"algorithm,omitempty"`
	PublicFingerprintSHA256 string `json:"public_fingerprint_sha256,omitempty"` // SubjectPublicKeyInfo の SHA-256
	SSHFingerprint          string `json:"ssh_fingerprint,omitempty"`
}

type CSR struct {
	Subject            string    `json:"subject"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	PublicKey          PublicKey `json:"public_key"`
}

// Keystore はキーストア（PKCS#12、JKS、JCEKS）。パスワードなしで読める範囲の情報。
type Keystore struct {
	Format         string         `json:"format"`
	Integrity      *Integrity     `json:"integrity,omitempty"`
	Entries        map[string]int `json:"entries"`
	Sections       []Section      `json:"sections,omitempty"`        // PKCS#12 の区画ごとの暗号化
	KeyProtections []Protection   `json:"key_protections,omitempty"` // 秘密鍵エントリの保護方式
	Unreadable     bool           `json:"contents_unreadable"`       // 暗号化されていて確認できない部分がある
	PartiallyRead  bool           `json:"partially_read,omitempty"`
}

type Integrity struct {
	Algorithm  string `json:"algorithm"`
	Iterations int    `json:"iterations,omitempty"`
}

type Section struct {
	Encrypted  bool        `json:"encrypted"`
	Protection *Protection `json:"protection,omitempty"`
}

// Protection はパスワード等による保護の方式（アルゴリズムは資産への参照）。
type Protection struct {
	Scheme     string `json:"scheme,omitempty"`
	KDF        string `json:"kdf,omitempty"`
	PRF        string `json:"prf,omitempty"`
	Cipher     string `json:"cipher,omitempty"`
	Iterations int    `json:"iterations,omitempty"`
}

// Detail は出現ごとの付加情報。
type Detail struct {
	Format     string      `json:"format,omitempty"`
	Encrypted  *bool       `json:"encrypted,omitempty"`
	Protection *Protection `json:"protection,omitempty"`
}

type Algorithm struct {
	Family    string `json:"family,omitempty"`
	Primitive string `json:"primitive,omitempty"`
	KeyBits   int    `json:"key_bits,omitempty"`
	// 見つけたままの名前と命名体系。カタログが将来変わっても再正規化できるようにする。
	RawName string `json:"raw_name,omitempty"`
	Scheme  string `json:"scheme,omitempty"`
	Known   bool   `json:"known"`
}

type Certificate struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	Serial             string    `json:"serial"`
	NotBefore          string    `json:"not_before"`
	NotAfter           string    `json:"not_after"`
	IsCA               bool      `json:"is_ca"`
	SelfSigned         bool      `json:"self_signed"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	PublicKey          PublicKey `json:"public_key"`
	FingerprintSHA256  string    `json:"fingerprint_sha256"`
}

type PublicKey struct {
	Algorithm         string `json:"algorithm"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
}

type Occurrence struct {
	ID         string    `json:"id"`
	Asset      string    `json:"asset"`
	Collector  string    `json:"collector"`
	State      string    `json:"state"` // present: ファイルとして存在（用途は未特定）
	Confidence string    `json:"confidence"`
	Location   Location  `json:"location"`
	Store      string    `json:"store,omitempty"`    // 属する証明書ストア（ルールの os/stores.yaml の ID）
	Activity   *Activity `json:"activity,omitempty"` // 利用の確からしさ
	Detail     *Detail   `json:"detail,omitempty"`
}

type Location struct {
	Kind  string `json:"kind"`
	Path  string `json:"path"`
	Index int    `json:"index"` // 同一ファイル内での順番
	// キーストアや証明書束の中にある場合、その入れ物の形式（jks、pkcs12、pkcs7 など）
	Container string `json:"container,omitempty"`
}

type Skipped struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

type Coverage struct {
	FilesExamined    int            `json:"files_examined"`
	DirsExamined     int            `json:"dirs_examined"`
	SymlinksIgnored  int            `json:"symlinks_not_followed"`
	SpecialIgnored   int            `json:"special_files_not_opened"`
	BytesRead        int64          `json:"bytes_read"`
	SkippedByReason  map[string]int `json:"skipped_by_reason"`
	SkippedTruncated bool           `json:"skipped_list_truncated"`
}

// OSSetting は OS 全体の暗号設定の1項目。値は種類ごとの検証を通ったものだけを記録する。
type OSSetting struct {
	ID    string `json:"id"`
	Value string `json:"value"`
	Path  string `json:"path,omitempty"` // その値が書かれていたファイル
	Line  int    `json:"line,omitempty"`
}

// Activity は「利用の確からしさ」。値の根拠（basis / state）とは別の軸。
//
//	running: 稼働中のプロセスが使っている / enabled: 起動するよう設定されたサービスが使う /
//	referenced: 設定から参照されている / installed: 導入されているだけ / unknown: 判断材料がない
type Activity struct {
	Level    string     `json:"level"`
	Evidence []Evidence `json:"evidence,omitempty"`
}

// Evidence は、利用の確からしさを判断した根拠。
type Evidence struct {
	Kind    string `json:"kind"`           // unit-enabled | unit-masked | unit-present | binary-present | config-reference
	Path    string `json:"path,omitempty"` // 根拠となったファイル
	Line    int    `json:"line,omitempty"`
	Detail  string `json:"detail,omitempty"`  // ユニット名、設定項目名など
	Service string `json:"service,omitempty"` // 参照元のサービス
}

// Service はアプリケーションのインスタンス。
type Service struct {
	ID          string   `json:"id"`
	App         string   `json:"app"`
	Component   string   `json:"component,omitempty"` // バイナリのコンポーネント ID
	ConfigFiles []string `json:"config_files,omitempty"`
	Activity    Activity `json:"activity"`
	Notes       []string `json:"notes,omitempty"`
}

// Setting は設定値の1件。同じ項目が複数の場所にある場合は、それぞれを記録し、どれが有効かを示す。
type Setting struct {
	ID        string          `json:"id"`
	Service   string          `json:"service"`
	Parameter string          `json:"parameter"`
	Direction string          `json:"direction,omitempty"` // inbound（受信）| outbound（送信）
	Scope     string          `json:"scope,omitempty"`     // 条件付きの設定（sshd の Match など）。全体なら空
	Basis     string          `json:"basis"`               // configured: 明記されている / default: 記載がなくアプリの既定
	Layer     string          `json:"layer"`               // app-config | os-policy | app-default
	Source    string          `json:"source"`              // config-file | command-line | default
	Modifier  string          `json:"modifier,omitempty"`  // 既定の一覧への操作（+ 追加、- 削除、^ 先頭へ）
	Values    []string        `json:"values"`
	Effective bool            `json:"effective"` // 同じ項目の記載のうち、実際に効くもの
	Location  SettingLocation `json:"location"`

	// ReferencedPaths は、値がファイルを指す場合の実際のパス（利用の確からしさの判定に使う）。
	ReferencedPaths []string `json:"-"`
}

type SettingLocation struct {
	Path string `json:"path,omitempty"`
	Line int    `json:"line,omitempty"`
}

// EffectiveValue は、ある項目について実際に効く値（設定の記載と、パッケージ版ごとの既定値から求めたもの）。
// 求められなかった場合は Status が unresolved になり、理由を Reason に残す（推測で埋めない）。
// 「許可されている」値であり、実際の通信でどれが選ばれているかを示すものではない。
type EffectiveValue struct {
	ID         string           `json:"id"`
	Service    string           `json:"service"`
	Parameter  string           `json:"parameter"`
	Direction  string           `json:"direction,omitempty"`
	Scope      string           `json:"scope,omitempty"` // 設定の範囲（nginx の server、Apache の VirtualHost）。全体なら空
	Status     string           `json:"status"`          // resolved | unresolved
	Values     []string         `json:"values,omitempty"`
	Confidence string           `json:"confidence,omitempty"` // high | medium（補間した、または一部の絞り込みができなかった）
	Reason     string           `json:"reason,omitempty"`
	Notes      []string         `json:"notes,omitempty"` // 確度を下げた理由など
	Steps      []ResolutionStep `json:"steps,omitempty"` // どの層の値から、どう求めたか
}

// ResolutionStep は、実効値を求める過程の1段。
type ResolutionStep struct {
	Layer   string      `json:"layer"`             // app-default | os-policy | app-config | library
	Op      string      `json:"op"`                // default | override | append | remove | prepend | profile | expand | security-level | filter-certificates | filter-dh-parameters
	Setting string      `json:"setting,omitempty"` // 根拠になった設定値の ID
	Source  *Provenance `json:"source,omitempty"`  // 既定値の出典
}

// Provenance は、既定値を実物で確認した出典。
type Provenance struct {
	Image   string `json:"image"`
	OS      string `json:"os"`
	Package string `json:"package"`
	Version string `json:"version"`
}

// Verdict は、評価ポリシーによる判定。
//
//	Quantum   : vulnerable | hybrid | resistant | reduced | not-targeted | unknown
//	Classical : weak | legacy | ok | unknown
type Verdict struct {
	Quantum   string   `json:"quantum"`
	Classical string   `json:"classical"`
	Rules     []string `json:"rules,omitempty"` // 当たった規則の ID（根拠はポリシーの規則と出典を参照）
}

// Assessment は、結果全体の評価。
type Assessment struct {
	Policy        string `json:"policy"`
	PolicyVersion string `json:"policy_version"`
	// 資産（アルゴリズム、証明書、鍵）の ID → 判定
	Assets map[string]Verdict `json:"assets"`
	// 設定から求めた値（「種類:名前」。例 tls-suite:ECDHE-RSA-AES256-GCM-SHA384、ssh-kex:curve25519-sha256）→ 判定
	Values map[string]Verdict `json:"values"`
}
