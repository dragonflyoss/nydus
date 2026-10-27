// Package mount starts the nydus daemons under test, mounts images through
// them and tears everything down again, whatever state the daemon is left in.
package mount

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
)

// stopGrace is how long a daemon gets to exit after SIGTERM before it is
// killed.
const stopGrace = 20 * time.Second

// logTail is how much of a daemon's log is printed when its test fails.
const logTail = 64 << 10

// Daemon is a background nydus process. Its console output goes to a log
// file whose tail is printed when the owning test fails, and it is always
// reaped by the test's cleanup.
type Daemon struct {
	Name    string
	LogPath string
	// LogDir is passed as --log-dir so file sinks land next to the console
	// log rather than in /var/log/nydus.
	LogDir string

	cmd    *exec.Cmd
	exited chan struct{}
	killed bool
}

// StartDaemon starts bin with args under dir. The daemon is stopped, and its
// log tail printed on failure, when t finishes. Daemons that take --log-dir
// should be given LogDir(dir, name).
func StartDaemon(t env.TB, dir, name, bin string, args ...string) *Daemon {
	t.Helper()
	d := &Daemon{
		Name:    name,
		LogPath: filepath.Join(dir, name+".log"),
		LogDir:  LogDir(dir, name),
	}
	if err := os.MkdirAll(d.LogDir, 0o755); err != nil {
		t.Fatalf("create %s: %v", d.LogDir, err)
	}
	logFile, err := os.Create(d.LogPath)
	if err != nil {
		t.Fatalf("create %s: %v", d.LogPath, err)
	}
	defer func() { _ = logFile.Close() }()

	d.cmd = exec.Command(bin, args...)
	d.cmd.Stdout = logFile
	d.cmd.Stderr = logFile
	if err := d.cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	d.exited = make(chan struct{})
	go func() { _ = d.cmd.Wait(); close(d.exited) }()

	t.Cleanup(func() {
		d.Stop()
		if t.Failed() {
			t.Logf("%s log (%s):\n%s", name, d.LogPath, tail(d.Log(), logTail))
		}
	})
	return d
}

// Pid returns the daemon's process id.
func (d *Daemon) Pid() int { return d.cmd.Process.Pid }

// Exited is closed once the daemon has exited and been reaped.
func (d *Daemon) Exited() <-chan struct{} { return d.exited }

// Alive reports whether the daemon is still running.
func (d *Daemon) Alive() bool {
	select {
	case <-d.exited:
		return false
	default:
		return true
	}
}

// ExitCode returns the daemon's exit code, or -1 while it runs or when a
// signal ended it.
func (d *Daemon) ExitCode() int {
	if d.Alive() {
		return -1
	}
	return d.cmd.ProcessState.ExitCode()
}

// Signal sends sig to the daemon if it is still running.
func (d *Daemon) Signal(sig syscall.Signal) {
	if d.Alive() {
		_ = d.cmd.Process.Signal(sig)
	}
}

// Stop sends SIGTERM and waits for the daemon to exit, killing it after a
// grace period. It reports whether the daemon exited on its own.
func (d *Daemon) Stop() bool {
	if !d.Alive() {
		return true
	}
	_ = d.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-d.exited:
		return true
	case <-time.After(stopGrace):
		d.killed = true
		d.Kill()
		return false
	}
}

// Killed reports whether Stop had to SIGKILL the daemon because it did not
// exit within the grace period after SIGTERM.
func (d *Daemon) Killed() bool { return d.killed }

// Kill SIGKILLs the daemon and waits until it has been reaped.
func (d *Daemon) Kill() {
	if d.Alive() {
		_ = d.cmd.Process.Kill()
	}
	<-d.exited
}

// Log returns the daemon's console output.
func (d *Daemon) Log() string {
	data, _ := os.ReadFile(d.LogPath)
	return string(data)
}

// FileLog returns everything the daemon wrote to the file sinks under
// LogDir, which largely repeats the console output.
func (d *Daemon) FileLog() string {
	return ReadLogs(d.LogDir)
}

// ReadLogs collects a daemon's rotating log files.
func ReadLogs(dir string) string {
	var b strings.Builder
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Type().IsRegular() {
			data, _ := os.ReadFile(filepath.Join(dir, e.Name()))
			b.Write(data)
		}
	}
	return b.String()
}

// WaitFor polls ready until it holds, failing early with the log when the
// daemon exits first and after timeout otherwise.
func (d *Daemon) WaitFor(t env.TB, timeout time.Duration, what string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if ready() {
			return
		}
		if !d.Alive() {
			t.Fatalf("%s exited (code %d) before %s", d.Name, d.ExitCode(), what)
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %s not reached within %s", d.Name, what, timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "...\n" + s[len(s)-n:]
}

// LogDir is where the daemon called name under dir keeps its file logs.
func LogDir(dir, name string) string {
	return filepath.Join(dir, name+"-logs")
}
