package env

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// KnownIssue runs body, a test of the correct behaviour that currently fails
// because of a tracked bug.
//
// With NYDUS_TEST_FAIL_KNOWN_ISSUES=1 (CI), body runs as an ordinary test:
// the bug fails and the correct behavior passes. Otherwise a failing body
// is reported as a skip whose message starts with
// "KNOWN ISSUE", so the suite stays green while the bug is open. A passing
// body fails the test: the bug is fixed and the marker has to go, otherwise
// a regression would hide behind it. A panicking body fails the test: a
// panic is a broken test, not the bug.
//
// Keep setup (images, mounts, daemons) outside body, so that only the
// assertions about the bug can count as a reproduction. body must not call
// t.Run or t.Parallel; it gets a TB, and every harness helper accepts one.
func KnownIssue(t *testing.T, issue string, body func(t TB)) {
	t.Helper()

	if os.Getenv("NYDUS_TEST_FAIL_KNOWN_ISSUES") == "1" {
		t.Logf("KNOWN ISSUE %s: enforcing correct behavior", issue)
		body(t)
		return
	}

	r := &recorder{t: t}
	done := make(chan struct{})
	var panicked any
	go func() {
		defer close(done)
		defer func() { panicked = recover() }()
		body(r)
	}()
	<-done

	if panicked != nil {
		t.Fatalf("known issue %s: body panicked: %v", issue, panicked)
	}

	if r.precondition != "" {
		Require(t, false, "%s", strings.TrimPrefix(r.precondition, "precondition: "))
		return
	}
	if r.Failed() {
		t.Skipf("KNOWN ISSUE %s reproduced:\n%s", issue, r.messages())
		return
	}
	t.Fatalf("known issue %s no longer reproduces: drop the KnownIssue marker", issue)
}

// recorder is the TB handed to a known-issue body. Failures are recorded
// instead of reported, and FailNow ends only the body's goroutine.
type recorder struct {
	t *testing.T

	mu           sync.Mutex
	failed       bool
	msgs         []string
	precondition string
}

// preconditionMiss ends the body without counting as a reproduction.
func (r *recorder) preconditionMiss(msg string) {
	r.mu.Lock()
	r.precondition = msg
	r.mu.Unlock()
	runtime.Goexit()
}

func (r *recorder) record(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failed = true
	if format != "" {
		r.msgs = append(r.msgs, fmt.Sprintf(format, args...))
	}
}

func (r *recorder) messages() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.msgs, "\n")
}

func (r *recorder) Helper()                         {}
func (r *recorder) Name() string                    { return r.t.Name() }
func (r *recorder) Logf(format string, args ...any) { r.t.Logf(format, args...) }
func (r *recorder) TempDir() string                 { return r.t.TempDir() }
func (r *recorder) Cleanup(fn func())               { r.t.Cleanup(fn) }

func (r *recorder) Errorf(format string, args ...any) { r.record(format, args...) }

func (r *recorder) Fatalf(format string, args ...any) {
	r.record(format, args...)
	runtime.Goexit()
}

func (r *recorder) FailNow() {
	r.record("")
	runtime.Goexit()
}

func (r *recorder) Failed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failed
}
