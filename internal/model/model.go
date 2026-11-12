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
	Skipped     []Skipped    `json:"skipped"`
	Coverage    Coverage     `json:"coverage"`
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
	ID         string   `json:"id"`
	Asset      string   `json:"asset"`
	Collector  string   `json:"collector"`
	State      string   `json:"state"` // present: ファイルとして存在（用途は未特定）
	Confidence string   `json:"confidence"`
	Location   Location `json:"location"`
	Detail     *Detail  `json:"detail,omitempty"`
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
