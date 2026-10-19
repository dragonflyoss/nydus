package util

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Daemon is a spawned nydus service daemon, such as nbd or fanotify, with
// its console log and log directory. Embed it in a test environment to
// share the start, stop, liveness and log scanning logic.
type Daemon struct {
	// ConsoleLog is the path of the console log the daemon's stdout and stderr are
	// written to.
	ConsoleLog string

	// LogDir is the directory the daemon writes its log files to.
	LogDir string

	// cmd is the running daemon, nil before Start and after Stop.
	cmd *exec.Cmd

	// exited is closed when the daemon has been reaped.
	exited chan struct{}
}

// Start runs cmd with its output written to the console log and reaps it in
// the background. Readiness polling and the stop stay with the caller, since
// a suite restarts its daemon from subtests whose end must not stop it.
func (d *Daemon) Start(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	logFile, err := os.Create(d.ConsoleLog)
	assert.NoError(t, err)
	defer func() { _ = logFile.Close() }()

	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if !assert.NoError(t, cmd.Start()) {
		t.FailNow()
	}

	d.cmd = cmd
	d.exited = make(chan struct{})
	go func() { _ = cmd.Wait(); close(d.exited) }()
}

// Stop sends the daemon SIGTERM and reaps it, killing it after 20s, and
// reports whether it exited on its own. It is safe to call when the daemon
// already exited or was never started.
func (d *Daemon) Stop() bool {
	if d.cmd == nil || d.cmd.Process == nil {
		return true
	}
	defer func() { d.cmd = nil }()

	// Wait on the one reaper goroutine Start spawned: a second Wait on the
	// same command races it and can return before the process has exited.
	_ = d.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-d.exited:
		return true
	case <-time.After(20 * time.Second):
		_ = d.cmd.Process.Kill()
		<-d.exited
		return false
	}
}

// Exited returns the channel closed once the daemon has been reaped.
func (d *Daemon) Exited() <-chan struct{} {
	return d.exited
}

// Alive reports whether the daemon was started and has not exited.
func (d *Daemon) Alive() bool {
	if d.cmd == nil {
		return false
	}

	select {
	case <-d.exited:
		return false
	default:
		return true
	}
}

// WaitReady polls ready for up to a minute and stops the test, with the
// daemon's logs, when the daemon exits first or the minute passes. The exit
// is checked outside the polling goroutine, where ending the test is legal.
func (d *Daemon) WaitReady(t *testing.T, ready func() bool) {
	t.Helper()
	exited := func() bool {
		select {
		case <-d.exited:
			return true
		default:
			return false
		}
	}

	if !assert.Eventually(t, func() bool { return exited() || ready() }, time.Minute, 200*time.Millisecond) || exited() {
		assert.FailNowf(t, "daemon did not become ready", "%s", d.Logs())
	}
}

// Logs returns the console log followed by every log file of the daemon.
func (d *Daemon) Logs() string {
	console, _ := os.ReadFile(d.ConsoleLog)
	return string(console) + ReadLogs(d.LogDir)
}

// ReadLogs returns the content of every log file under logDir, empty when
// the directory does not exist yet.
func ReadLogs(logDir string) string {
	var b strings.Builder
	entries, _ := os.ReadDir(logDir)
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			data, _ := os.ReadFile(filepath.Join(logDir, entry.Name()))
			b.Write(data)
		}
	}

	return b.String()
}

// CountLogs returns how many log lines match the regular expression pattern.
func (d *Daemon) CountLogs(pattern string) int {
	return CountMatchingLines(d.Logs(), regexp.MustCompile(pattern))
}

// CountMatchingLines returns how many lines of corpus match re.
func CountMatchingLines(corpus string, re *regexp.Regexp) int {
	count := 0
	for _, line := range strings.Split(corpus, "\n") {
		if re.MatchString(line) {
			count++
		}
	}

	return count
}

// WipeCache removes every per-blob file of the chunk cache so the next daemon
// starts cold. A stale group map left behind makes the daemon believe groups
// are ready while the re-created blob data is all zeros.
func WipeCache(cacheDir string) {
	for _, pattern := range []string{"*.blob.data", "*.blob.meta", "*.group.map", "*.prefetch.lock"} {
		matches, _ := filepath.Glob(filepath.Join(cacheDir, pattern))
		for _, match := range matches {
			_ = os.Remove(match)
		}
	}
}
