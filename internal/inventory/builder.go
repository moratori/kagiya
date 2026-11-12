// Package inventory は、コレクタが見つけたものを資産と出現にまとめて結果（model.Inventory）を組み立てる。
package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strconv"

	"kagiya/internal/logx"
	"kagiya/internal/model"
	"kagiya/internal/ruleset"
	"kagiya/internal/safefs"
)

const maxSkippedInResult = 10_000

// カタログにない名前を記録するときに許す文字。秘密の値が名前として紛れ込むのを防ぐ（設計書 4.5）。
var safeName = regexp.MustCompile(`^[A-Za-z0-9@._+-]{1,64}$`)

type Builder struct {
	rs  *ruleset.RuleSet
	log *logx.Logger

	assets       map[string]*model.Asset
	occurrences  []model.Occurrence
	pkgDBs       []model.PackageDatabase
	packages     []model.Package
	components   []*model.Component
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
	if k.Reason != "excluded" && k.Reason != "not-found" {
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
		State: "present", Confidence: "high", Location: loc, Store: b.rs.StoreFor(loc.Path), Detail: detail,
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
	inv := &model.Inventory{Schema: model.Schema, Assets: []model.Asset{}, Occurrences: b.occurrences, Skipped: b.skipped}
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
