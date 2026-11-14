package platform

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Landlock（Linux 5.13 以降）で、書き込める場所を出力先だけに限る（独立したレビューの指摘 A-8。利用者と確認して、使える環境では使うと決めた）。
// 一度かけた制限は外せないので、子プロセスで確かめる。Landlock のないカーネルでは、確かめられない（読み飛ばす）。
func TestRestrictWrites(t *testing.T) {
	if spec := os.Getenv("KAGIYA_LANDLOCK_CHILD"); spec != "" {
		landlockChild(spec)
		return
	}
	base, _ := filepath.EvalSymlinks(t.TempDir())
	allowed, other := filepath.Join(base, "out"), filepath.Join(base, "other")
	for _, d := range []string{allowed, other} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(other, "existing.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestRestrictWrites$")
	cmd.Env = append(os.Environ(), "KAGIYA_LANDLOCK_CHILD="+allowed+":"+other)
	raw, _ := cmd.CombinedOutput()
	out := string(raw)
	if strings.Contains(out, "status=unsupported") {
		t.Skip("Landlock is not available on this kernel")
	}
	for _, want := range []string{
		"status=applied",
		"inside-create=ok", "inside-link=ok", "inside-remove=ok", // 出力に使う操作は、出力先の中ではできる
		"outside-create=denied", "outside-append=denied", "outside-remove=denied", "outside-mkdir=denied",
		"outside-read=ok",            // 読み取りは制限しない
		"other-thread-create=denied", // 制限は、すべてのスレッドにかかる
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in the child's output:\n%s", want, out)
		}
	}
}

func landlockChild(spec string) {
	allowed, other, _ := strings.Cut(spec, ":")
	status, note := RestrictWrites([]string{allowed})
	fmt.Printf("status=%s note=%s\n", status, note)
	report := func(name string, err error) {
		if err == nil {
			fmt.Printf("%s=ok\n", name)
		} else {
			fmt.Printf("%s=denied (%v)\n", name, err)
		}
	}
	create := func(p string) error {
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			f.Close()
		}
		return err
	}
	in := filepath.Join(allowed, "a.partial")
	report("inside-create", create(in))
	report("inside-link", os.Link(in, filepath.Join(allowed, "a.json")))
	report("inside-remove", os.Remove(in))
	report("outside-create", create(filepath.Join(other, "b.txt")))
	f, err := os.OpenFile(filepath.Join(other, "existing.txt"), os.O_WRONLY|os.O_APPEND, 0)
	if err == nil {
		f.Close()
	}
	report("outside-append", err)
	report("outside-remove", os.Remove(filepath.Join(other, "existing.txt")))
	report("outside-mkdir", os.Mkdir(filepath.Join(other, "d"), 0o700))
	_, err = os.ReadFile(filepath.Join(other, "existing.txt"))
	report("outside-read", err)
	done := make(chan error)
	go func() {
		runtime.LockOSThread()
		done <- create(filepath.Join(other, "c.txt"))
	}()
	report("other-thread-create", <-done)
	os.Exit(0)
}
