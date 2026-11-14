// Package inventory は、コレクタが見つけたものを資産と出現にまとめて結果（model.Inventory）を組み立てる。
package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"kagiya/internal/logx"
	"kagiya/internal/model"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

const maxSkippedInResult = 10_000

// カタログにない名前を記録するときに許す文字。秘密の値が名前として紛れ込むのを防ぐ（設計書 4.5）。
var safeName = regexp.MustCompile(`^[A-Za-z0-9@._+-]{1,64}$`)

type Builder struct {
	// 資産と出現の数の上限（0 なら既定の値）
	MaxAssets, MaxOccurrences int
	stop                      func() bool // 止める合図が出ているか（nil なら見ない）
	rs                        *ruleset.RuleSet
	log                       *logx.Logger

	assets       map[string]*model.Asset
	occurrences  []model.Occurrence
	pkgDBs       []model.PackageDatabase
	packages     []model.Package
	components   []*model.Component
	osSettings   []model.OSSetting
	services     []model.Service
	settings     []model.Setting
	effective    []model.EffectiveValue
	skipped      []model.Skipped
	skipByReason map[string]int
	skipTotal    int
	problemSkips int
}

func NewBuilder(rs *ruleset.RuleSet, log *logx.Logger) *Builder {
	return &Builder{rs: rs, log: log, assets: map[string]*model.Asset{}, skipByReason: map[string]int{}}
}

// Skip は読まなかった・読めなかった場所を記録する。
func (b *Builder) Skip(k safefs.Skip) {
	b.skipTotal++
	b.skipByReason[k.Reason]++
	// 除外指定、存在しない起点、記録対象外の設定項目は、問題としては数えない。
	if k.Reason != "excluded" && k.Reason != "not-found" && k.Reason != "unrecognized-setting" && k.Reason != "not-interpreted" {
		b.problemSkips++
	}
	b.log.Warn("skip", "path", k.Path, "reason", k.Reason, "detail", k.Detail)
	if len(b.skipped) < maxSkippedInResult {
		b.skipped = append(b.skipped, model.Skipped{Path: k.Path, Reason: k.Reason, Detail: k.Detail})
	}
}

// SkipTotal は記録したスキップの総数、ProblemSkips はそのうち除外指定など意図したもの以外の数。
func (b *Builder) SkipTotal() int    { return b.skipTotal }
func (b *Builder) ProblemSkips() int { return b.problemSkips }

// Asset は ID に対応する資産を返す。無ければ make で作って登録する。
func (b *Builder) Asset(id string, make func() model.Asset) *model.Asset {
	if a, ok := b.assets[id]; ok {
		return a
	}
	a := make()
	a.ID = id
	b.assets[id] = &a
	return &a
}

// Occur は資産の出現を記録する。ID は資産・コレクタ・場所から決まり、スキャンをまたいで安定する。
func (b *Builder) Occur(assetID, collector string, loc model.Location, detail *model.Detail) {
	h := sha256.Sum256([]byte(assetID + "\x00" + collector + "\x00" + loc.Path + "\x00" + loc.Container + "\x00" + strconv.Itoa(loc.Index)))
	b.occurrences = append(b.occurrences, model.Occurrence{
		ID: "occ:" + hex.EncodeToString(h[:12]), Asset: assetID, Collector: collector,
		State: "present", Confidence: model.ConfidenceHigh, Location: loc, Store: b.rs.StoreFor(loc.Path), Detail: detail,
	})
}

// LocationID は、内容から ID を作れない資産（暗号化された鍵など）のための、場所由来の ID 部分。
func LocationID(path string, index int) string {
	h := sha256.Sum256([]byte(path + "\x00" + strconv.Itoa(index)))
	return "loc:" + hex.EncodeToString(h[:12])
}

// AlgorithmByOID は OID をカタログで引き、アルゴリズム資産の ID を返す。
// カタログにない OID も捨てずに「未知」として記録する（OID は数字とドットだけなので秘密を含み得ない）。
func (b *Builder) AlgorithmByOID(oid string) string {
	return b.algorithm("oid", oid, 0)
}

// AlgorithmByName は命名体系（openssl、ssh、java など）と名前から引く。
func (b *Builder) AlgorithmByName(scheme, name string) string {
	return b.algorithm(scheme, name, 0)
}

// AlgorithmWithBits は鍵長で区別するアルゴリズム（RSA、DSA）用。資産 ID に鍵長が付く。
func (b *Builder) AlgorithmWithBits(oid string, bits int) string {
	return b.algorithm("oid", oid, bits)
}

func (b *Builder) algorithm(scheme, name string, bits int) string {
	if name == "" {
		return ""
	}
	if a, ok := b.rs.LookupAlias(scheme, name); ok {
		id := "alg:" + a.ID
		keyBits := a.KeyBits
		if bits > 0 {
			id += "-" + strconv.Itoa(bits)
			keyBits = bits
		}
		b.Asset(id, func() model.Asset {
			return model.Asset{Type: "algorithm", Algorithm: &model.Algorithm{
				Family: a.Family, Primitive: a.Primitive, KeyBits: keyBits, RawName: name, Scheme: scheme, Known: true}}
		})
		return id
	}
	if !safeName.MatchString(name) {
		// 名前として出せない値。存在だけを記録する。
		id := "alg:unknown:" + scheme + ":unprintable"
		b.Asset(id, func() model.Asset {
			return model.Asset{Type: "algorithm", Algorithm: &model.Algorithm{Scheme: scheme}}
		})
		return id
	}
	id := "alg:unknown:" + scheme + ":" + name
	b.Asset(id, func() model.Asset {
		return model.Asset{Type: "algorithm", Algorithm: &model.Algorithm{RawName: name, Scheme: scheme}}
	})
	return id
}

// AddPackageDatabase は見つかったパッケージ管理データベースを記録する。
func (b *Builder) AddPackageDatabase(db model.PackageDatabase) { b.pkgDBs = append(b.pkgDBs, db) }

// AddPackage は導入済みパッケージを記録する。
func (b *Builder) AddPackage(p model.Package) { b.packages = append(b.packages, p) }

// AddService はサービスを記録する。
func (b *Builder) AddService(s model.Service) { b.services = append(b.services, s) }

// Settings は記録済みの設定値を返す。
func (b *Builder) Settings() []model.Setting { return b.settings }

// AddEffective は実効値を記録する。
func (b *Builder) AddEffective(e model.EffectiveValue) {
	key := e.Service + "\x00" + e.Parameter + "\x00" + e.Direction
	if e.Scope != "" {
		key += "\x00" + e.Scope
	}
	h := sha256.Sum256([]byte(key))
	e.ID = "eff:" + hex.EncodeToString(h[:12])
	b.effective = append(b.effective, e)
}

// ServiceNote は、記録済みのサービスに注記を足す。
func (b *Builder) ServiceNote(id, note string) {
	for i := range b.services {
		if b.services[i].ID == id {
			b.services[i].Notes = append(b.services[i].Notes, note)
		}
	}
}

// AddSetting は設定値を記録する。ID はサービス・項目・場所から決まる。
func (b *Builder) AddSetting(s model.Setting) {
	h := sha256.Sum256([]byte(s.Service + "\x00" + s.Parameter + "\x00" + s.Scope + "\x00" + s.Source + "\x00" + s.Location.Path + "\x00" + strconv.Itoa(s.Location.Line) + "\x00" + strconv.Itoa(len(b.settings))))
	s.ID = "set:" + hex.EncodeToString(h[:12])
	b.settings = append(b.settings, s)
}

// FindComponent は、ID が指定の接頭辞で始まる最初のコンポーネントを返す。
func (b *Builder) FindComponent(prefix string) (model.Component, bool) {
	for _, c := range b.components {
		if strings.HasPrefix(c.ID, prefix) {
			return *c, true
		}
	}
	return model.Component{}, false
}

// assignActivity は、出現ごとに「利用の確からしさ」を決める。
// 有効なサービスの設定から参照されているファイルは、そのサービスと同じ段階になる。
func (b *Builder) assignActivity() {
	level := map[string]string{}
	for _, s := range b.services {
		level[s.ID] = s.Activity.Level
	}
	type ref struct {
		lvl string
		ev  model.Evidence
	}
	refs := map[string]ref{}
	rank := map[string]int{model.ActivityRunning: 4, model.ActivityEnabled: 3, model.ActivityReferenced: 2, model.ActivityInstalled: 1, model.ActivityUnknown: 0}
	for _, s := range b.settings {
		if !s.Effective {
			continue
		}
		lvl := model.ActivityReferenced
		if l := level[s.Service]; model.IsActive(l) {
			lvl = l
		}
		for _, p := range s.ReferencedPaths {
			if cur, ok := refs[p]; ok && rank[cur.lvl] >= rank[lvl] {
				continue
			}
			refs[p] = ref{lvl, model.Evidence{Kind: "config-reference", Path: s.Location.Path, Line: s.Location.Line, Detail: s.Parameter, Service: s.Service}}
		}
	}
	for i := range b.occurrences {
		o := &b.occurrences[i]
		switch r, ok := refs[o.Location.Path]; {
		case ok:
			o.Activity = &model.Activity{Level: r.lvl, Evidence: []model.Evidence{r.ev}}
		case o.Store != "":
			o.Activity = &model.Activity{Level: model.ActivityInstalled}
		default:
			o.Activity = &model.Activity{Level: "unknown"}
		}
	}
}

// OSSettings は記録済みの OS 全体の暗号設定を返す。
func (b *Builder) OSSettings() []model.OSSetting { return b.osSettings }

// AddOSSetting は OS 全体の暗号設定の1項目を記録する。
func (b *Builder) AddOSSetting(s model.OSSetting) { b.osSettings = append(b.osSettings, s) }

// Packages は記録済みのパッケージを返す。
func (b *Builder) Packages() []model.Package { return b.packages }

// Component は ID に対応するコンポーネントを返す。無ければ make で作って登録する。
func (b *Builder) Component(id string, make func() model.Component) *model.Component {
	for _, c := range b.components {
		if c.ID == id {
			return c
		}
	}
	c := make()
	c.ID = id
	b.components = append(b.components, &c)
	return &c
}

// Inventory は集めた内容を結果の形にする（Meta と走査統計は呼び出し側が埋める）。
func (b *Builder) Inventory() *model.Inventory {
	b.assignActivity()
	inv := &model.Inventory{Schema: model.Schema, Assets: []model.Asset{}, Occurrences: b.occurrences, Skipped: b.skipped}
	inv.Services, inv.Settings = b.services, b.settings
	if inv.Services == nil {
		inv.Services = []model.Service{}
	}
	if inv.Settings == nil {
		inv.Settings = []model.Setting{}
	}
	inv.EffectiveValues = b.effective
	if inv.EffectiveValues == nil {
		inv.EffectiveValues = []model.EffectiveValue{}
	}
	for _, a := range b.assets {
		inv.Assets = append(inv.Assets, *a)
	}
	sort.Slice(inv.Assets, func(i, j int) bool { return inv.Assets[i].ID < inv.Assets[j].ID })
	if inv.Occurrences == nil {
		inv.Occurrences = []model.Occurrence{}
	}
	inv.PackageDatabases, inv.Packages = b.pkgDBs, b.packages
	if inv.PackageDatabases == nil {
		inv.PackageDatabases = []model.PackageDatabase{}
	}
	if inv.Packages == nil {
		inv.Packages = []model.Package{}
	}
	inv.OSSettings = b.osSettings
	if inv.OSSettings == nil {
		inv.OSSettings = []model.OSSetting{}
	}
	inv.Components = []model.Component{}
	for _, c := range b.components {
		inv.Components = append(inv.Components, *c)
	}
	sort.SliceStable(inv.Components, func(i, j int) bool { return inv.Components[i].ID < inv.Components[j].ID })
	sort.SliceStable(inv.Packages, func(i, j int) bool { return inv.Packages[i].Name < inv.Packages[j].Name })
	if inv.Skipped == nil {
		inv.Skipped = []model.Skipped{}
	}
	inv.Coverage.SkippedByReason = b.skipByReason
	inv.Coverage.SkippedTruncated = b.skipTotal > len(b.skipped)
	return inv
}

// Guard は、1 つのファイル（やアプリ）の処理 f を実行する。f の中で panic が起きても、そこで止めて、スキャンは続ける
// （敵対的な入力でパーサが止まっても、ほかのファイルの結果を失わないため。設計書 4.7）。
// path は処理の対象（なければ空）、doing は何をしていたかの説明。panic の値は入力の断片を含みうるので記録せず、
// 実行時エラー（範囲外の参照など。入力の内容は含まない）の場合だけ、その種類を残す。
//
// 止める合図が出た後は、f を始めない（処理の区切りで止めるので、途中まで読んだ中途半端な結果は残らない）。
func (b *Builder) Guard(path, doing string, f func()) {
	if b.Stopped() {
		return
	}
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		kind := "a panic"
		if e, ok := r.(runtime.Error); ok {
			kind = e.Error()
		}
		b.Skip(safefs.Skip{Path: path, Reason: "internal-error", Detail: "stopped while " + doing + ": " + kind})
	}()
	f()
}

// SetStop は、止める合図（中断、時間制限）が出ているかを返す関数を決める。
func (b *Builder) SetStop(stopped func() bool) { b.stop = stopped }

// Stopped は、止める合図が出ているかを返す。
func (b *Builder) Stopped() bool { return b.stop != nil && b.stop() }

// maxLoggedSkipsPerReason は、読み飛ばしを 1 件ずつログに書く数の、理由ごとの上限。
const maxLoggedSkipsPerReason = 1000

// SetYield は、処理の区切りごとに呼ぶ関数（流量制限の休止）を決める。
func (b *Builder) SetYield(yield func()) {}

// Overflowed は、資産や出現の数が上限を超えて、記録を打ち切ったかを返す。
func (b *Builder) Overflowed() bool { return false }
