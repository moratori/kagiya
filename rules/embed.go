// Package rules はバイナリに内包する既定の検出ルール（データのみ）。
package rules

import "embed"

//go:embed manifest.yaml catalog os apps libraries defaults ciphers policies groups
var FS embed.FS
