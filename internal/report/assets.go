// このファイルは、証明書と鍵、証明書ストア、OS とライブラリ、読み飛ばしたものの組み立て。

package report

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"kagiya/internal/model"
)

func shortAlg(id string) string { return strings.TrimPrefix(id, "alg:") }

// 期限の状態（スキャンした時点を基準にする）。
const (
	expiryExpired  = "expired"
	expiryExpiring = "expiring"
)

// verdict は、資産の判定を返す（判定に使われた規則を、出典の一覧に載せるために覚えておく）。
func (b *builder) verdict(assetID string) (model.Verdict, bool) {
	vd, ok := b.a.Assets[assetID]
	if !ok {
		return model.Verdict{}, false
	}
	for _, id := range vd.Rules {
		b.used[id] = true
	}
	return vd, true
}

func (b *builder) assetRow(o model.Occurrence) (assetRow, bool) {
	as, ok := b.assets[o.Asset]
	if !ok {
		return assetRow{}, false
	}
	row := assetRow{Path: o.Location.Path}
	if o.Location.Container != "" {
		row.Path += "（" + o.Location.Container + " の中）"
	}
	if o.Activity != nil {
		row.Activity = activityLabel[o.Activity.Level]
		for _, e := range o.Activity.Evidence {
			row.Evidence = append(row.Evidence, evidenceText(e))
		}
	}
	switch {
	case as.Type == "certificate" && as.Certificate != nil:
		c := as.Certificate
		row.Kind, row.Name = "証明書", c.Subject
		if c.IsCA {
			row.Kind = "CA 証明書"
		}
		row.Algorithm = "鍵 " + shortAlg(c.PublicKey.Algorithm) + "、署名 " + shortAlg(c.SignatureAlgorithm)
		row.Expiry = c.NotAfter
		if t, err := time.Parse(time.RFC3339, c.NotAfter); err == nil && !b.scanTime.IsZero() {
			switch {
			case t.Before(b.scanTime):
				row.ExpiryState, row.ExpiryTag = expiryExpired, badge{"期限切れ", "bad", "スキャンした時点で、有効期限を過ぎていた証明書"}
			case t.Before(b.scanTime.AddDate(0, 0, expiringDays)):
				row.ExpiryState, row.ExpiryTag = expiryExpiring, badge{strconv.Itoa(expiringDays) + " 日以内に期限", "warn", "スキャンした時点から数えて、まもなく有効期限が来る証明書"}
			}
		}
	case (as.Type == "private-key" || as.Type == "public-key") && as.Key != nil:
		row.Kind = map[string]string{"private-key": "秘密鍵", "public-key": "公開鍵"}[as.Type]
		row.Name = shortAlg(as.Key.Algorithm)
		if row.Name == "" {
			row.Name = "（アルゴリズムを確認できない）"
		}
		if o.Detail != nil && o.Detail.Encrypted != nil && *o.Detail.Encrypted {
			row.Name += "（暗号化されている）"
		}
	case as.Type == "csr" && as.CSR != nil:
		row.Kind, row.Name = "証明書署名要求", as.CSR.Subject
		row.Algorithm = "鍵 " + shortAlg(as.CSR.PublicKey.Algorithm) + "、署名 " + shortAlg(as.CSR.SignatureAlgorithm)
	case as.Type == "keystore" && as.Keystore != nil:
		row.Kind, row.Name = "キーストア", as.Keystore.Format
		if as.Keystore.Unreadable {
			row.Name += "（暗号化されていて、中身の一部を確認できない）"
		}
	default:
		return assetRow{}, false
	}
	if vd, ok := b.verdict(as.ID); ok {
		row.Verdict = vd
		row.Quantum, row.Classical = quantumBadge[vd.Quantum], classicalBadge[vd.Classical]
	}
	return row, true
}

func (b *builder) files(v *view) {
	stores := map[string]map[string]*storeGroup{}
	counts := map[string]int{}
	for _, o := range b.inv.Occurrences {
		row, ok := b.assetRow(o)
		if !ok {
			continue
		}
		as := b.assets[o.Asset]
		if o.Store != "" {
			// 証明書ストアの中身は、署名の方式ごとにまとめる
			sig := "（証明書以外）"
			if as.Certificate != nil {
				sig = shortAlg(as.Certificate.SignatureAlgorithm)
			}
			if stores[o.Store] == nil {
				stores[o.Store] = map[string]*storeGroup{}
			}
			g := stores[o.Store][sig]
			if g == nil {
				g = &storeGroup{Signature: sig}
				if as.Certificate != nil {
					if vd, ok := b.a.Assets[as.Certificate.SignatureAlgorithm]; ok {
						g.Quantum, g.Classical = quantumBadge[vd.Quantum], classicalBadge[vd.Classical]
						for _, id := range vd.Rules {
							b.used[id] = true
						}
					}
				}
				stores[o.Store][sig] = g
			}
			g.Count++
			g.Rows = append(g.Rows, row)
			counts[o.Store]++
			continue
		}
		level := ""
		if o.Activity != nil {
			level = o.Activity.Level
		}
		if as.Type == "private-key" && (level == "" || level == model.ActivityUnknown || level == model.ActivityInstalled) {
			v.Unconfirmed = append(v.Unconfirmed, row)
			v.Summary.Unconfirmed++
		}
		v.Files = append(v.Files, row)
		if row.Verdict.Quantum == model.QuantumVulnerable {
			v.Summary.FileQuantum++
		}
		switch row.Verdict.Classical {
		case model.ClassicalWeak:
			v.Summary.FileWeak++
		case model.ClassicalLegacy:
			v.Summary.FileLegacy++
		}
		switch row.ExpiryState {
		case expiryExpired:
			v.Summary.Expired++
		case expiryExpiring:
			v.Summary.Expiring++
		}
	}
	byPath := func(rows []assetRow) {
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].Path != rows[j].Path {
				return rows[i].Path < rows[j].Path
			}
			return rows[i].Name < rows[j].Name
		})
	}
	byPath(v.Files)
	byPath(v.Unconfirmed)
	var names []string
	for name := range stores {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		sv := storeView{Name: name, Count: counts[name]}
		for _, g := range stores[name] {
			sort.SliceStable(g.Rows, func(i, j int) bool { return g.Rows[i].Name < g.Rows[j].Name })
			sv.Groups = append(sv.Groups, *g)
		}
		sort.SliceStable(sv.Groups, func(i, j int) bool {
			if sv.Groups[i].Count != sv.Groups[j].Count {
				return sv.Groups[i].Count > sv.Groups[j].Count
			}
			return sv.Groups[i].Signature < sv.Groups[j].Signature
		})
		v.Stores = append(v.Stores, sv)
	}
}

func (b *builder) misc(v *view) {
	for _, s := range b.inv.OSSettings {
		v.OSSettings = append(v.OSSettings, kv{s.ID, s.Value, location(s.Path, s.Line)})
	}
	for _, p := range b.inv.Packages {
		v.Packages = append(v.Packages, kv{p.Name, p.FullVersion(), p.Manager})
	}
	for _, c := range b.inv.Components {
		val := c.Path
		if c.Version != nil {
			val += "（版 " + c.Version.Value + "）"
		}
		var links []string
		for _, l := range c.Links {
			if l.Path != "" {
				links = append(links, l.SOName+" → "+l.Path)
			}
		}
		v.Components = append(v.Components, kv{c.Name, val, strings.Join(links, "、")})
	}
	for _, s := range b.inv.Skipped {
		name := skipLabel[s.Reason]
		if name == "" {
			name = s.Reason
		}
		v.Skipped = append(v.Skipped, kv{s.Path, name, s.Detail})
	}
	var reasons []string
	for r := range b.inv.Coverage.SkippedByReason {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	for _, r := range reasons {
		n := b.inv.Coverage.SkippedByReason[r]
		name := skipLabel[r]
		if name == "" {
			name = r
		}
		v.SkippedBy = append(v.SkippedBy, kv{name, strconv.Itoa(n), r})
		switch r {
		case "permission-denied":
			v.Summary.Permission += n
		case "excluded":
		default:
			v.Summary.OtherSkips += n
		}
	}
	v.Summary.Files, v.Summary.Dirs = b.inv.Coverage.FilesExamined, b.inv.Coverage.DirsExamined
	v.SkippedCut = b.inv.Coverage.SkippedTruncated
}
