package convert

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"kagiya/internal/assess"
	"kagiya/internal/model"
)

// このファイルは、結果を CBOM（CycloneDX 1.6 の JSON）に変換する。
//
// 項目の名前と取り得る値は、CycloneDX の公式のスキーマ（bom-1.6.schema.json）に従う。検証ラボで、実物の結果から作った文書を
// 公式のスキーマで検証している（docs/design.md）。
//
// 対応づけ:
//   - アルゴリズム、証明書、鍵 → 暗号資産（cryptographic-asset）。鍵や証明書の値そのものは出さない（指紋、鍵長、形式まで）
//   - サービスが受け入れる方式（範囲ごと） → プロトコルの資産。暗号スイートは cipherSuites、鍵交換のグループや SSH の方式は
//     アルゴリズムの資産への参照（cryptoRefArray）
//   - サービス、プログラム、暗号ライブラリ → application / library と、依存関係
//   - CycloneDX に対応する欄がない情報（判定、利用の確からしさ、特定できなかった理由など） → 名前が「kagiya:」で始まるプロパティ
//
// 変換は結果だけから決まる（変換した時刻や乱数を含めない）。

const cbomSpecVersion = "1.6"

type cdxBOM struct {
	BomFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	SerialNumber string          `json:"serialNumber"`
	Version      int             `json:"version"`
	Metadata     cdxMetadata     `json:"metadata"`
	Components   []cdxComponent  `json:"components"`
	Dependencies []cdxDependency `json:"dependencies,omitempty"`
}

type cdxMetadata struct {
	Timestamp  string         `json:"timestamp,omitempty"`
	Lifecycles []cdxLifecycle `json:"lifecycles"`
	Tools      cdxTools       `json:"tools"`
	Component  cdxComponent   `json:"component"`
	Properties []cdxProperty  `json:"properties,omitempty"`
}

type cdxLifecycle struct {
	Phase string `json:"phase"`
}

type cdxTools struct {
	Components []cdxComponent `json:"components"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxOccurrence struct {
	Location string `json:"location"`
}

type cdxEvidence struct {
	Occurrences []cdxOccurrence `json:"occurrences"`
}

type cdxComponent struct {
	Type       string        `json:"type"`
	BomRef     string        `json:"bom-ref,omitempty"`
	Name       string        `json:"name"`
	Version    string        `json:"version,omitempty"`
	Hashes     []cdxHash     `json:"hashes,omitempty"`
	Evidence   *cdxEvidence  `json:"evidence,omitempty"`
	Crypto     *cdxCrypto    `json:"cryptoProperties,omitempty"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

type cdxCrypto struct {
	AssetType   string          `json:"assetType"`
	Algorithm   *cdxAlgorithm   `json:"algorithmProperties,omitempty"`
	Certificate *cdxCertificate `json:"certificateProperties,omitempty"`
	Material    *cdxMaterial    `json:"relatedCryptoMaterialProperties,omitempty"`
	Protocol    *cdxProtocol    `json:"protocolProperties,omitempty"`
	OID         string          `json:"oid,omitempty"`
}

type cdxAlgorithm struct {
	Primitive              string `json:"primitive"`
	ParameterSetIdentifier string `json:"parameterSetIdentifier,omitempty"`
	Curve                  string `json:"curve,omitempty"`
	NistQuantumLevel       *int   `json:"nistQuantumSecurityLevel,omitempty"`
}

type cdxCertificate struct {
	SubjectName           string `json:"subjectName,omitempty"`
	IssuerName            string `json:"issuerName,omitempty"`
	NotValidBefore        string `json:"notValidBefore,omitempty"`
	NotValidAfter         string `json:"notValidAfter,omitempty"`
	SignatureAlgorithmRef string `json:"signatureAlgorithmRef,omitempty"`
	SubjectPublicKeyRef   string `json:"subjectPublicKeyRef,omitempty"`
	CertificateFormat     string `json:"certificateFormat,omitempty"`
}

// cdxMaterial は鍵などの暗号素材。スキーマには値そのものを入れる欄（value）があるが、このツールは決して出さない。
type cdxMaterial struct {
	Type         string        `json:"type"`
	ID           string        `json:"id,omitempty"`
	AlgorithmRef string        `json:"algorithmRef,omitempty"`
	Size         int           `json:"size,omitempty"`
	Format       string        `json:"format,omitempty"`
	SecuredBy    *cdxSecuredBy `json:"securedBy,omitempty"`
}

type cdxSecuredBy struct {
	Mechanism    string `json:"mechanism"`
	AlgorithmRef string `json:"algorithmRef,omitempty"`
}

type cdxProtocol struct {
	Type         string           `json:"type"`
	CipherSuites []cdxCipherSuite `json:"cipherSuites,omitempty"`
	CryptoRefs   []string         `json:"cryptoRefArray,omitempty"`
}

type cdxCipherSuite struct {
	Name string `json:"name"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

var (
	oidText = regexp.MustCompile(`^[0-9]+(\.[0-9]+)+$`)
	hexHash = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
)

type cbomBuilder struct {
	inv    *model.Inventory
	comps  []cdxComponent
	refs   map[string]bool             // 文書の中にある bom-ref
	algs   map[string]*model.Algorithm // アルゴリズムの資産
	occs   map[string][]model.Occurrence
	deps   map[string][]string
	depOrd []string
	// 記録済みの依存関係（from, on）。重複の確認を、並びの線形探索で行わない
	depSeen map[string]map[string]bool
	// 記録済みの「プロトコル → アルゴリズム」の参照
	cryptoSeen map[[2]string]bool
}

// WriteCBOM は、結果を CBOM（CycloneDX 1.6 の JSON）として書き出す。
func WriteCBOM(inv *model.Inventory, w io.Writer) error { return writeCBOM(inv, w, true) }

// WriteCBOMCompact は、WriteCBOM と同じ内容を、字下げなしで書き出す（HTML レポートへの埋め込み用）。
func WriteCBOMCompact(inv *model.Inventory, w io.Writer) error { return writeCBOM(inv, w, false) }

func writeCBOM(inv *model.Inventory, w io.Writer, indent bool) error {
	b := &cbomBuilder{inv: inv, refs: map[string]bool{}, algs: map[string]*model.Algorithm{}, occs: map[string][]model.Occurrence{}, deps: map[string][]string{}}
	for _, o := range inv.Occurrences {
		b.occs[o.Asset] = append(b.occs[o.Asset], o)
	}
	for i := range inv.Assets {
		if a := &inv.Assets[i]; a.Type == "algorithm" && a.Algorithm != nil {
			b.algs[a.ID] = a.Algorithm
			b.refs[a.ID] = true // ほかの資産から参照できるよう、先に登録する
		}
	}
	const hostRef = "host"
	b.refs[hostRef] = true
	b.algorithms()
	b.certificatesAndKeys()
	b.protocols()
	b.software(hostRef)

	m := inv.Meta
	doc := cdxBOM{BomFormat: "CycloneDX", SpecVersion: cbomSpecVersion, SerialNumber: serialNumber(m.ScanID), Version: 1, Components: b.comps}
	if doc.Components == nil {
		doc.Components = []cdxComponent{}
	}
	for _, ts := range []string{m.FinishedAt, m.StartedAt} {
		if validTime(ts) {
			doc.Metadata.Timestamp = ts
			break
		}
	}
	doc.Metadata.Lifecycles = []cdxLifecycle{{Phase: "operations"}}
	doc.Metadata.Tools.Components = []cdxComponent{{Type: "application", Name: "kagiya", Version: m.Tool.Version}}
	host := cdxComponent{Type: "device", BomRef: hostRef, Name: m.Host.Hostname}
	if host.Name == "" {
		host.Name = "unknown"
	}
	osName := m.Host.OS
	if m.Host.Distribution != nil && m.Host.Distribution.Name != "" {
		osName = m.Host.Distribution.Name
	}
	host.Properties = props("kagiya:os", osName, "kagiya:arch", m.Host.Arch)
	for _, k := range sortedKeys(m.Labels) {
		host.Properties = append(host.Properties, cdxProperty{Name: "kagiya:label:" + k, Value: m.Labels[k]})
	}
	doc.Metadata.Component = host
	policy := ""
	if a := inv.Assessment; a != nil {
		policy = strings.TrimSpace(a.Policy + " " + a.PolicyVersion)
	}
	completed := ""
	if m.ScanID != "" {
		completed = strconv.FormatBool(m.Completed)
	}
	doc.Metadata.Properties = props("kagiya:schema", inv.Schema, "kagiya:scan-id", m.ScanID, "kagiya:scan-completed", completed,
		"kagiya:incomplete-reason", m.Incomplete, "kagiya:rules-version", m.Rules.Version, "kagiya:rules-source", m.Rules.Source, "kagiya:policy", policy)
	for _, ref := range b.depOrd {
		doc.Dependencies = append(doc.Dependencies, cdxDependency{Ref: ref, DependsOn: b.deps[ref]})
	}

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if indent {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(doc)
}

// serialNumber は、スキャンの ID から決まる通し番号（UUID の形）。同じ結果からは同じ番号になる。
func serialNumber(scanID string) string {
	h := sha256.Sum256([]byte("kagiya-cbom\x00" + scanID))
	u := h[:16]
	u[6] = u[6]&0x0f | 0x80 // 版 8（独自の方法で作った値）
	u[8] = u[8]&0x3f | 0x80
	x := hex.EncodeToString(u)
	return "urn:uuid:" + x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32]
}

func validTime(s string) bool {
	_, err := time.Parse(time.RFC3339, s)
	return err == nil
}

// props は、「名前, 値, 名前, 値, …」からプロパティの並びを作る。値が空のものは省く。
func props(kv ...string) []cdxProperty {
	var out []cdxProperty
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			out = append(out, cdxProperty{Name: kv[i], Value: kv[i+1]})
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (b *cbomBuilder) add(c cdxComponent) {
	b.refs[c.BomRef] = true
	b.comps = append(b.comps, c)
}

// ref は、文書の中にある資産への参照だけを返す（なければ空。宙に浮いた参照は作らない）。
func (b *cbomBuilder) ref(id string) string {
	if id != "" && b.refs[id] {
		return id
	}
	return ""
}

func (b *cbomBuilder) depend(from string, on ...string) {
	for _, r := range on {
		if r == "" || !b.refs[r] || r == from {
			continue
		}
		if b.depSeen == nil {
			b.depSeen = map[string]map[string]bool{}
		}
		if b.depSeen[from][r] {
			continue
		}
		if b.depSeen[from] == nil {
			b.depSeen[from] = map[string]bool{}
		}
		b.depSeen[from][r] = true
		if _, ok := b.deps[from]; !ok {
			b.depOrd = append(b.depOrd, from)
		}
		b.deps[from] = append(b.deps[from], r)
	}
}

// verdictProps は、評価（スキャンした時点の評価ポリシーによる判定）をプロパティにする。
func verdictProps(v model.Verdict, ok bool) []cdxProperty {
	if !ok {
		return nil
	}
	return props("kagiya:quantum", v.Quantum, "kagiya:classical", v.Classical)
}

func (b *cbomBuilder) assetVerdict(id string) (model.Verdict, bool) {
	if b.inv.Assessment == nil {
		return model.Verdict{}, false
	}
	v, ok := b.inv.Assessment.Assets[id]
	return v, ok
}

// quantumLevel は、量子計算機に弱い方式に、耐量子の安全性の水準 0 を付ける（それ以外は、水準を主張しない）。
func quantumLevel(v model.Verdict, ok bool) *int {
	if ok && v.Quantum == model.QuantumVulnerable {
		zero := 0
		return &zero
	}
	return nil
}

// evidence は、資産が見つかった場所。
func (b *cbomBuilder) evidence(asset string) *cdxEvidence {
	var e cdxEvidence
	seen := map[string]bool{}
	for _, o := range b.occs[asset] {
		if p := o.Location.Path; p != "" && !seen[p] {
			seen[p] = true
			e.Occurrences = append(e.Occurrences, cdxOccurrence{Location: p})
		}
	}
	if len(e.Occurrences) == 0 {
		return nil
	}
	return &e
}

var activityRank = map[string]int{model.ActivityRunning: 5, model.ActivityEnabled: 4, model.ActivityReferenced: 3, model.ActivityInstalled: 2, model.ActivityUnknown: 1}

// occurrenceProps は、出現から分かること（証明書ストア、利用の確からしさ）をプロパティにする。
func (b *cbomBuilder) occurrenceProps(asset string) []cdxProperty {
	stores := map[string]bool{}
	best := ""
	for _, o := range b.occs[asset] {
		if o.Store != "" {
			stores[o.Store] = true
		}
		if o.Activity != nil && activityRank[o.Activity.Level] > activityRank[best] {
			best = o.Activity.Level
		}
	}
	return props("kagiya:activity", best, "kagiya:store", strings.Join(sortedKeys(stores), ","))
}

// primitive は、暗号カタログの種別を、CycloneDX の種別にする。
func primitive(a *model.Algorithm) string {
	if !a.Known {
		return "unknown"
	}
	switch a.Primitive {
	case "signature", "hash", "block-cipher", "stream-cipher", "mac", "kdf", "kem":
		return a.Primitive
	case "aead":
		return "ae"
	case "key-exchange":
		return "key-agree"
	case "rng":
		return "drbg"
	case "public-key":
		if a.Family == "RSA" {
			return "pke"
		}
		return "other" // 署名にも鍵共有にも使われる鍵（EC など）
	case "curve", "other":
		return "other"
	}
	return "unknown"
}

func (b *cbomBuilder) algorithms() {
	for _, as := range b.inv.Assets {
		a := as.Algorithm
		if as.Type != "algorithm" || a == nil {
			continue
		}
		name := strings.TrimPrefix(as.ID, "alg:")
		v, ok := b.assetVerdict(as.ID)
		ap := &cdxAlgorithm{Primitive: primitive(a), NistQuantumLevel: quantumLevel(v, ok)}
		if a.KeyBits > 0 {
			ap.ParameterSetIdentifier = strconv.Itoa(a.KeyBits)
		}
		if a.Primitive == "curve" {
			ap.Curve = name
		}
		c := cdxComponent{Type: "cryptographic-asset", BomRef: as.ID, Name: name, Crypto: &cdxCrypto{AssetType: "algorithm", Algorithm: ap}}
		if a.Scheme == "oid" && oidText.MatchString(a.RawName) {
			c.Crypto.OID = a.RawName
		}
		c.Properties = append(props("kagiya:family", a.Family, "kagiya:primitive", a.Primitive), verdictProps(v, ok)...)
		b.add(c)
	}
}

func short(fp string) string {
	if len(fp) > 16 {
		return fp[:16]
	}
	return fp
}

func (b *cbomBuilder) bits(alg string) int {
	if a := b.algs[alg]; a != nil {
		return a.KeyBits
	}
	return 0
}

func (b *cbomBuilder) certificatesAndKeys() {
	// 先に鍵の資産の ID を登録する（証明書から参照するため）
	for _, as := range b.inv.Assets {
		if (as.Type == "private-key" || as.Type == "public-key") && as.Key != nil {
			b.refs[as.ID] = true
		}
	}
	var derived []cdxComponent // 証明書から分かる公開鍵（鍵の資産としては見つかっていないもの）
	for _, as := range b.inv.Assets {
		v, ok := b.assetVerdict(as.ID)
		switch {
		case as.Type == "certificate" && as.Certificate != nil:
			ct := as.Certificate
			cp := &cdxCertificate{SubjectName: ct.Subject, IssuerName: ct.Issuer, SignatureAlgorithmRef: b.ref(ct.SignatureAlgorithm), CertificateFormat: "X.509"}
			if validTime(ct.NotBefore) {
				cp.NotValidBefore = ct.NotBefore
			}
			if validTime(ct.NotAfter) {
				cp.NotValidAfter = ct.NotAfter
			}
			if fp := ct.PublicKey.FingerprintSHA256; fp != "" {
				ref := "key:public:spki-sha256:" + fp
				if !b.refs[ref] {
					b.refs[ref] = true
					derived = append(derived, cdxComponent{Type: "cryptographic-asset", BomRef: ref, Name: "public-key " + short(fp),
						Crypto: &cdxCrypto{AssetType: "related-crypto-material", Material: &cdxMaterial{Type: "public-key", ID: fp,
							AlgorithmRef: b.ref(ct.PublicKey.Algorithm), Size: b.bits(ct.PublicKey.Algorithm)}},
						Properties: props("kagiya:derived-from", "certificate")})
				}
				cp.SubjectPublicKeyRef = ref
			}
			c := cdxComponent{Type: "cryptographic-asset", BomRef: as.ID, Name: ct.Subject, Evidence: b.evidence(as.ID),
				Crypto: &cdxCrypto{AssetType: "certificate", Certificate: cp}}
			if c.Name == "" {
				c.Name = "certificate " + short(ct.FingerprintSHA256)
			}
			if hexHash.MatchString(ct.FingerprintSHA256) {
				c.Hashes = []cdxHash{{Alg: "SHA-256", Content: strings.ToLower(ct.FingerprintSHA256)}}
			}
			c.Properties = append(props("kagiya:serial", ct.Serial, "kagiya:is-ca", strconv.FormatBool(ct.IsCA), "kagiya:self-signed", strconv.FormatBool(ct.SelfSigned)), verdictProps(v, ok)...)
			c.Properties = append(c.Properties, b.occurrenceProps(as.ID)...)
			b.add(c)
		case (as.Type == "private-key" || as.Type == "public-key") && as.Key != nil:
			k := as.Key
			m := &cdxMaterial{Type: as.Type, ID: k.PublicFingerprintSHA256, AlgorithmRef: b.ref(k.Algorithm), Size: b.bits(k.Algorithm)}
			encrypted := ""
			for _, o := range b.occs[as.ID] {
				d := o.Detail
				if d == nil {
					continue
				}
				if m.Format == "" {
					m.Format = d.Format
				}
				if d.Encrypted != nil {
					if encrypted == "" || *d.Encrypted {
						encrypted = strconv.FormatBool(*d.Encrypted)
					}
					if *d.Encrypted && m.SecuredBy == nil {
						m.SecuredBy = &cdxSecuredBy{Mechanism: "Software"}
						if d.Protection != nil {
							m.SecuredBy.AlgorithmRef = b.ref(d.Protection.Cipher)
						}
					}
				}
			}
			c := cdxComponent{Type: "cryptographic-asset", BomRef: as.ID, Name: as.Type + " " + short(k.PublicFingerprintSHA256), Evidence: b.evidence(as.ID),
				Crypto: &cdxCrypto{AssetType: "related-crypto-material", Material: m}}
			c.Properties = append(props("kagiya:ssh-fingerprint", k.SSHFingerprint, "kagiya:encrypted", encrypted), verdictProps(v, ok)...)
			c.Properties = append(c.Properties, b.occurrenceProps(as.ID)...)
			b.add(c)
		case as.Type == "csr" && as.CSR != nil:
			c := cdxComponent{Type: "cryptographic-asset", BomRef: as.ID, Name: "csr " + as.CSR.Subject, Evidence: b.evidence(as.ID),
				Crypto: &cdxCrypto{AssetType: "related-crypto-material", Material: &cdxMaterial{Type: "other", AlgorithmRef: b.ref(as.CSR.SignatureAlgorithm)}}}
			c.Properties = append(props("kagiya:asset-type", "csr"), b.occurrenceProps(as.ID)...)
			b.add(c)
		case as.Type == "keystore" && as.Keystore != nil:
			ks := as.Keystore
			c := cdxComponent{Type: "file", BomRef: as.ID, Name: as.ID, Evidence: b.evidence(as.ID)}
			if c.Evidence != nil {
				c.Name = c.Evidence.Occurrences[0].Location
			}
			c.Properties = props("kagiya:asset-type", "keystore", "kagiya:keystore-format", ks.Format, "kagiya:contents-unreadable", strconv.FormatBool(ks.Unreadable))
			for _, k := range sortedKeys(ks.Entries) {
				c.Properties = append(c.Properties, cdxProperty{Name: "kagiya:entries:" + k, Value: strconv.Itoa(ks.Entries[k])})
			}
			c.Properties = append(c.Properties, b.occurrenceProps(as.ID)...)
			b.add(c)
		}
	}
	for _, c := range derived {
		b.comps = append(b.comps, c)
	}
}

// namedPrimitive は、設定で名前を指定する方式（鍵交換のグループ、SSH の方式）の種別。
func namedPrimitive(scheme, name string, v model.Verdict) string {
	switch scheme {
	case "tls-group", "ssh-kex":
		switch v.Quantum {
		case model.QuantumHybrid:
			return "combiner" // 現行の方式と耐量子の方式の組み合わせ
		case "resistant":
			return "kem"
		}
		return "key-agree"
	case "ssh-cipher":
		n := strings.ToLower(name)
		switch {
		case strings.Contains(n, "gcm") || strings.Contains(n, "poly1305"):
			return "ae"
		case strings.Contains(n, "arcfour") || strings.Contains(n, "rc4"):
			return "stream-cipher"
		}
		return "block-cipher"
	case "ssh-mac":
		return "mac"
	case "ssh-key":
		return "signature"
	}
	return "other"
}

// protocols は、サービスが受け入れる方式を、範囲ごとのプロトコルの資産にする。
func (b *cbomBuilder) protocols() {
	apps := map[string]string{}
	for _, s := range b.inv.Services {
		apps[s.ID] = s.App
	}
	type group struct {
		ref  string
		comp cdxComponent
	}
	var order []string
	groups := map[string]*group{}
	var named []cdxComponent
	for _, e := range b.inv.EffectiveValues {
		key := e.Service + "\x00" + e.Scope
		g := groups[key]
		if g == nil {
			kind := "other"
			switch {
			case strings.HasPrefix(e.Parameter, "tls."):
				kind = "tls"
			case strings.HasPrefix(e.Parameter, "ssh."):
				kind = "ssh"
			}
			name := apps[e.Service]
			if name == "" {
				name = e.Service
			}
			if e.Scope != "" {
				name += ": " + e.Scope
			}
			g = &group{ref: "protocol:" + e.Service + ":" + e.Scope}
			g.comp = cdxComponent{Type: "cryptographic-asset", BomRef: g.ref, Name: name,
				Crypto:     &cdxCrypto{AssetType: "protocol", Protocol: &cdxProtocol{Type: kind}},
				Properties: props("kagiya:service", e.Service, "kagiya:scope", e.Scope, "kagiya:direction", e.Direction)}
			groups[key] = g
			order = append(order, key)
			b.refs[g.ref] = true
			b.depend(e.Service) // 依存関係の並びを、サービスの順にそろえる（中身は後で足す）
		}
		if e.Status != model.StatusResolved {
			g.comp.Properties = append(g.comp.Properties, cdxProperty{Name: "kagiya:unresolved:" + e.Parameter, Value: e.Reason})
			continue
		}
		g.comp.Properties = append(g.comp.Properties, props("kagiya:confidence:"+e.Parameter, e.Confidence)...)
		scheme := assess.SchemeFor(e.Parameter)
		p := g.comp.Crypto.Protocol
		switch scheme {
		case "", assess.SchemeTLSProtocol:
			// 数値や、版の名前の一覧。プロトコルの資産には載せない
		case assess.SchemeTLSSuite:
			for _, n := range e.Values {
				p.CipherSuites = append(p.CipherSuites, cdxCipherSuite{Name: n})
			}
		default:
			for _, n := range e.Values {
				ref := "name:" + scheme + ":" + n
				if !b.refs[ref] {
					b.refs[ref] = true
					var v model.Verdict
					ok := false
					if b.inv.Assessment != nil {
						v, ok = b.inv.Assessment.Values[scheme+":"+n]
					}
					named = append(named, cdxComponent{Type: "cryptographic-asset", BomRef: ref, Name: n,
						Crypto:     &cdxCrypto{AssetType: "algorithm", Algorithm: &cdxAlgorithm{Primitive: namedPrimitive(scheme, n, v), NistQuantumLevel: quantumLevel(v, ok)}},
						Properties: append(props("kagiya:scheme", scheme), verdictProps(v, ok)...)})
				}
				if b.cryptoSeen == nil {
					b.cryptoSeen = map[[2]string]bool{}
				}
				if key := [2]string{g.ref, ref}; !b.cryptoSeen[key] {
					b.cryptoSeen[key] = true
					p.CryptoRefs = append(p.CryptoRefs, ref)
				}
			}
		}
	}
	b.comps = append(b.comps, named...)
	for _, key := range order {
		g := groups[key]
		b.comps = append(b.comps, g.comp)
		b.depend(strings.SplitN(key, "\x00", 2)[0], g.ref)
	}
}

// software は、サービス、プログラム、暗号ライブラリと、その依存関係。
func (b *cbomBuilder) software(hostRef string) {
	byID := map[string]model.Component{}
	for _, c := range b.inv.Components {
		byID[c.ID] = c
		if c.Kind == "library" {
			b.refs[c.ID] = true
		}
	}
	for _, s := range b.inv.Services {
		b.refs[s.ID] = true
	}
	location := func(path string) *cdxEvidence {
		if path == "" {
			return nil
		}
		return &cdxEvidence{Occurrences: []cdxOccurrence{{Location: path}}}
	}
	version := func(c model.Component) string {
		if c.Version != nil {
			return c.Version.Value
		}
		return ""
	}
	pkg := func(c model.Component) string {
		if c.Package == nil {
			return ""
		}
		v := c.Package.Version
		if c.Package.Release != "" {
			v += "-" + c.Package.Release
		}
		return c.Package.Name + " " + v
	}
	links := func(c model.Component) []string {
		var out []string
		for _, l := range c.Links {
			out = append(out, l.Component)
		}
		return out
	}
	used := map[string]bool{}
	for _, s := range b.inv.Services {
		c := cdxComponent{Type: "application", BomRef: s.ID, Name: s.App, Properties: props("kagiya:activity", s.Activity.Level)}
		for _, f := range s.ConfigFiles {
			c.Properties = append(c.Properties, cdxProperty{Name: "kagiya:config-file", Value: f})
		}
		var deps []string
		if comp, ok := byID[s.Component]; ok && s.Component != "" {
			used[comp.ID] = true
			c.Version, c.Evidence = version(comp), location(comp.Path)
			c.Properties = append(c.Properties, props("kagiya:package", pkg(comp))...)
			deps = links(comp)
		}
		b.comps = append(b.comps, c)
		// ライブラリを先に、範囲ごとのプロトコルを後に並べる
		protocols := b.deps[s.ID]
		if _, ok := b.deps[s.ID]; ok {
			b.deps[s.ID] = nil
			delete(b.depSeen, s.ID) // 並べ直すので、記録済みの印も消す
		}
		b.depend(s.ID, deps...)
		b.depend(s.ID, protocols...)
		b.depend(hostRef, s.ID)
	}
	for _, comp := range b.inv.Components {
		if used[comp.ID] {
			continue
		}
		kind := "application"
		if comp.Kind == "library" {
			kind = "library"
		}
		b.add(cdxComponent{Type: kind, BomRef: comp.ID, Name: comp.Name, Version: version(comp), Evidence: location(comp.Path), Properties: props("kagiya:package", pkg(comp))})
		b.depend(comp.ID, links(comp)...)
	}
	// 中身のない依存関係の項目は出さない
	var kept []string
	for _, ref := range b.depOrd {
		if len(b.deps[ref]) > 0 {
			kept = append(kept, ref)
		}
	}
	b.depOrd = kept
}
