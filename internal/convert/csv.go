// Package convert は結果 JSON を他の形式（CSV、CBOM）に変換する。情報量は落ちてよい。
package convert

import (
	"encoding/csv"
	"io"
	"sort"
	"strconv"
	"strings"

	"kagiya/internal/model"
)

var csvHeader = []string{
	"hostname", "scan_started_at", "labels",
	"asset_type", "asset_id", "algorithm", "key_bits",
	"subject", "issuer", "not_after", "signature_algorithm", "fingerprint_sha256",
	"format", "encrypted", "protection_cipher", "protection_iterations",
	"state", "confidence", "collector", "store", "path", "container", "index",
}

// WriteCSV は出現1件を1行として書き出す。bom が真なら UTF-8 の BOM を付ける（Excel での文字化け対策）。
func WriteCSV(inv *model.Inventory, w io.Writer, bom bool) error {
	if bom {
		if _, err := w.Write([]byte("\xef\xbb\xbf")); err != nil {
			return err
		}
	}
	cw := csv.NewWriter(w)
	cw.UseCRLF = true
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	assets := make(map[string]*model.Asset, len(inv.Assets))
	for i := range inv.Assets {
		assets[inv.Assets[i].ID] = &inv.Assets[i]
	}
	labels := labelString(inv.Meta.Labels)
	alg := func(ref string) string { return strings.TrimPrefix(ref, "alg:") }
	bits := func(ref string) string {
		if a, ok := assets[ref]; ok && a.Algorithm != nil && a.Algorithm.KeyBits > 0 {
			return strconv.Itoa(a.Algorithm.KeyBits)
		}
		return ""
	}
	for _, o := range inv.Occurrences {
		row := map[string]string{
			"hostname": inv.Meta.Host.Hostname, "scan_started_at": inv.Meta.StartedAt, "labels": labels,
			"asset_id": o.Asset, "state": o.State, "confidence": o.Confidence, "collector": o.Collector,
			"store": o.Store, "path": o.Location.Path, "container": o.Location.Container, "index": strconv.Itoa(o.Location.Index),
		}
		if a, ok := assets[o.Asset]; ok {
			row["asset_type"] = a.Type
			keyAlg := ""
			switch {
			case a.Certificate != nil:
				c := a.Certificate
				keyAlg = c.PublicKey.Algorithm
				row["subject"], row["issuer"], row["not_after"] = c.Subject, c.Issuer, c.NotAfter
				row["signature_algorithm"], row["fingerprint_sha256"] = alg(c.SignatureAlgorithm), c.FingerprintSHA256
			case a.CSR != nil:
				keyAlg = a.CSR.PublicKey.Algorithm
				row["subject"], row["signature_algorithm"] = a.CSR.Subject, alg(a.CSR.SignatureAlgorithm)
				row["fingerprint_sha256"] = a.CSR.PublicKey.FingerprintSHA256
			case a.Key != nil:
				keyAlg = a.Key.Algorithm
				row["fingerprint_sha256"] = a.Key.PublicFingerprintSHA256
			case a.Algorithm != nil:
				keyAlg = a.ID
			}
			row["algorithm"], row["key_bits"] = alg(keyAlg), bits(keyAlg)
		}
		if d := o.Detail; d != nil {
			row["format"] = d.Format
			if d.Encrypted != nil {
				row["encrypted"] = strconv.FormatBool(*d.Encrypted)
			}
			if p := d.Protection; p != nil {
				row["protection_cipher"] = alg(p.Cipher)
				if p.Iterations > 0 {
					row["protection_iterations"] = strconv.Itoa(p.Iterations)
				}
			}
		}
		rec := make([]string, len(csvHeader))
		for i, h := range csvHeader {
			rec[i] = neutralise(row[h])
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// neutralise は、表計算ソフトが数式として解釈する文字で始まるセルの先頭にアポストロフィを付ける。
// ファイルパスや証明書の Subject はスキャン対象側が自由に決められるため。
func neutralise(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func labelString(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + labels[k]
	}
	return strings.Join(parts, "; ")
}
