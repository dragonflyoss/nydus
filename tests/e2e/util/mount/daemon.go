package mount

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	stopTimeout = 20 * time.Second
	logTail     = 64 << 10
)

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
func StartDaemon(t testing.TB, dir, name, bin string, args ...string) *Daemon {
	t.Helper()
	return StartCmd(t, dir, name, exec.Command(bin, args...))
}

// StartCmd starts a prepared command as a daemon under dir: its stderr, and
// its stdout unless the caller already connected it, go to the console log.
// A connected Stdout must be an *os.File the caller owns, such as the write
// end of an os.Pipe: the Wait that reaps the daemon closes a StdoutPipe
// before its reader is done.
func StartCmd(t testing.TB, dir, name string, cmd *exec.Cmd) *Daemon {
	t.Helper()
	d := &Daemon{
		Name:    name,
		LogPath: filepath.Join(dir, name+".log"),
		LogDir:  LogDir(dir, name),
		cmd:     cmd,
	}

	if err := os.MkdirAll(d.LogDir, 0o755); err != nil {
		t.Fatalf("create %s: %v", d.LogDir, err)
	}

	logFile, err := os.Create(d.LogPath)
	if err != nil {
		t.Fatalf("create %s: %v", d.LogPath, err)
	}

	defer func() { _ = logFile.Close() }()

	if d.cmd.Stdout == nil {
		d.cmd.Stdout = logFile
	}

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

// Exited returns a channel that is closed once the daemon has exited and
// been reaped.
func (d *Daemon) Exited() <-chan struct{} { return d.exited }

// WaitExit waits up to timeout for the daemon to exit and reports whether
// it did.
func (d *Daemon) WaitExit(timeout time.Duration) bool {
	select {
	case <-d.exited:
		return true

	case <-time.After(timeout):
		return false
	}
}

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
func (d *Daemon) Signal(sig unix.Signal) {
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

	_ = d.cmd.Process.Signal(unix.SIGTERM)

	select {
	case <-d.exited:
		return true

	case <-time.After(stopTimeout):
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
	var b strings.Builder

	entries, _ := os.ReadDir(d.LogDir)
	for _, e := range entries {
		if e.Type().IsRegular() {
			data, _ := os.ReadFile(filepath.Join(d.LogDir, e.Name()))
			b.Write(data)
		}
	}

	return b.String()
}

// WaitFor polls ready on the calling goroutine until it holds, failing
// early when the daemon exits first and after timeout otherwise.
func (d *Daemon) WaitFor(t testing.TB, timeout time.Duration, what string, ready func() bool) {
	t.Helper()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()

	deadline := time.Now().Add(timeout)

	for {
		alive := d.Alive()

		if ready() {
			return
		}
		if !alive {
			t.Fatalf("%s exited (code %d) before %s", d.Name, d.ExitCode(), what)
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %s not reached within %s", d.Name, what, timeout)
		}

		<-tick.C
	}
}

// WaitForLog waits until the daemon's console or file log contains text.
func (d *Daemon) WaitForLog(t testing.TB, timeout time.Duration, text string) {
	t.Helper()
	d.WaitFor(t, timeout, "log line "+strconv.Quote(text), func() bool {
		return strings.Contains(d.Log(), text) || strings.Contains(d.FileLog(), text)
	})
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}

	return "...\n" + s[len(s)-n:]
}

// LogDir is where the daemon called name under dir keeps its file logs: next
// to the console log, or under NYDUS_E2E_LOG_DIR when that is set, so the
// logs outlive the test and CI can upload them.
func LogDir(dir, name string) string {
	if root := os.Getenv("NYDUS_E2E_LOG_DIR"); root != "" {
		dir = filepath.Join(root, strings.TrimPrefix(dir, os.TempDir()))
	}

	return filepath.Join(dir, name+"-logs")
}

// DaemonArgs appends the log flags for the daemon called name and the
// request's extra args.
func DaemonArgs(args []string, req Request, name string) []string {
	args = append(args, "--log-level", "info", "--log-dir", LogDir(req.Dir, name))
	return append(args, req.Args...)
}
