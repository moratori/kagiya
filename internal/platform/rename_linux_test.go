//go:build linux

package platform

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// 実際のカーネルで、上書きしない改名（renameat2）が働くこと。
func TestRenameNoReplace(t *testing.T) {
	d := t.TempDir()
	a, b, c := filepath.Join(d, "a"), filepath.Join(d, "b"), filepath.Join(d, "c")
	os.WriteFile(a, []byte("first"), 0o600)
	if err := RenameNoReplace(a, b); err != nil {
		t.Fatalf("rename to a new name: %v", err)
	}
	if _, err := os.Stat(a); !errors.Is(err, fs.ErrNotExist) {
		t.Error("the source must be gone after the rename")
	}
	os.WriteFile(c, []byte("second"), 0o600)
	if err := RenameNoReplace(c, b); !errors.Is(err, fs.ErrExist) {
		t.Errorf("rename onto an existing file: err = %v, want fs.ErrExist", err)
	}
	if got, _ := os.ReadFile(b); string(got) != "first" {
		t.Errorf("existing file was replaced: %q", got)
	}
	if got, _ := os.ReadFile(c); string(got) != "second" {
		t.Errorf("source must remain after a refused rename: %q", got)
	}
}
