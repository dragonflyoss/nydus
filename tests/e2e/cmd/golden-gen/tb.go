package main

import (
	"log"
	"os"
	"runtime"
	"sync"
)

// tb implements env.TB outside `go test`, so golden-gen can run the
// corpus, fixture and oracle code. Like testing.T, FailNow ends the calling
// goroutine, so the body must run through run.
type tb struct {
	root string

	mu       sync.Mutex
	failed   bool
	cleanups []func()
}

// newTB returns a tb whose temporary directories live under root.
func newTB(root string) *tb {
	return &tb{root: root}
}

func (t *tb) Helper()      {}
func (t *tb) Name() string { return "golden-gen" }

func (t *tb) Logf(format string, args ...any) {
	log.Printf(format, args...)
}

func (t *tb) Errorf(format string, args ...any) {
	log.Printf("ERROR: "+format, args...)
	t.mu.Lock()
	t.failed = true
	t.mu.Unlock()
}

func (t *tb) Fatalf(format string, args ...any) {
	t.Errorf(format, args...)
	t.FailNow()
}

func (t *tb) FailNow() {
	t.mu.Lock()
	t.failed = true
	t.mu.Unlock()
	runtime.Goexit()
}

func (t *tb) Failed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.failed
}

func (t *tb) TempDir() string {
	dir, err := os.MkdirTemp(t.root, "tmp-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func (t *tb) Cleanup(fn func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cleanups = append(t.cleanups, fn)
}

// run calls body on its own goroutine, so FailNow can end it, then runs the
// cleanups last to first. It reports whether nothing failed.
func (t *tb) run(body func(t *tb)) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer t.runCleanups()
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic: %v", r)
			}
		}()
		body(t)
	}()
	<-done
	return !t.Failed()
}

func (t *tb) runCleanups() {
	for {
		t.mu.Lock()
		n := len(t.cleanups)
		if n == 0 {
			t.mu.Unlock()
			return
		}
		fn := t.cleanups[n-1]
		t.cleanups = t.cleanups[:n-1]
		t.mu.Unlock()
		fn()
	}
}
