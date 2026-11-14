package keystore

import (
	"strconv"
	"testing"
	"time"

	"kagiya/internal/parse/keymat"
)

// 独立したレビュー（2026-11-14）の指摘 P-1。保護方式の重複の確認が線形探索で、件数にも上限がなかったので、
// 方式を 1 つずつ変えた鍵エントリを大量に並べたキーストアで、二乗の時間がかかった。
func TestKeyProtectionsAreBounded(t *testing.T) {
	var s Store
	start := time.Now()
	for i := 0; i < 300000; i++ {
		s.addKeyProtection(keymat.Encryption{SchemeOID: "1.2.3." + strconv.Itoa(i)})
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("adding 300,000 distinct protections took %v", d)
	}
	if len(s.KeyProtections) != maxKeyProtections || !s.Truncated {
		t.Errorf("protections = %d truncated = %v, want %d and true", len(s.KeyProtections), s.Truncated, maxKeyProtections)
	}
	// 重複は 1 つにまとめる。上限の内なら、打ち切りにはならない
	var u Store
	for i := 0; i < 1000; i++ {
		u.addKeyProtection(keymat.Encryption{SchemeOID: "1.2.840.113549.1.5.13", Iterations: 2048})
		u.addKeyProtection(keymat.Encryption{Name: "AES-256-CBC"})
	}
	if len(u.KeyProtections) != 2 || u.Truncated {
		t.Errorf("protections = %+v truncated = %v", u.KeyProtections, u.Truncated)
	}
}
