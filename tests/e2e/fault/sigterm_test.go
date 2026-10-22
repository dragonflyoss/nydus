package fault

import (
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/proc"
)

// TestSigterm stops the daemon with SIGTERM, as systemd and container
// runtimes do. The daemon unmounts, exits 0 and leaves no child process
// behind, also while 16 readers keep it busy: a mount that is busy for a
// moment must not make the unmount give up, and no reader may hang or read
// wrong bytes on the way down.
func TestSigterm(t *testing.T) {
	t.Parallel()
	img := fixture.Get(t, "zstd-4k")
	cases := []struct {
		a    mount.Adapter
		busy bool
	}{
		{mount.FUSE{}, false},
		{mount.FUSE{}, true},
		{mount.Fileio{}, false},
	}
	for _, c := range cases {
		name := c.a.Name() + "/idle"
		if c.busy {
			name = c.a.Name() + "/busy"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := mount.Mount(t, c.a, img, mount.Options{})
			prime(t, m)
			var rd *readers
			if c.busy {
				rd = startReaders(t, m.Root, dataFiles(t, img), 16)
				rd.waitOK(t, 16, readTimeout)
				// The readers open and close files; one file held open across
				// the signal makes the mount busy for certain.
				held, err := os.Open(m.Path(dataFiles(t, img)[0].Rel))
				if err != nil {
					t.Fatalf("open: %v", err)
				}
				defer func() { _ = held.Close() }()
			}

			kids := proc.Children(m.Daemon.Pid())
			dir, points := daemonDir(m), mountpoints(m)
			m.Daemon.Signal(syscall.SIGTERM)
			mustExit(t, m.Daemon, exitTimeout, "SIGTERM")
			if rd != nil {
				rd.stopWithin(t, 10*time.Second)
			}
			expectGone(t, kids, exitTimeout)
			clean := func(t env.TB) {
				if code := m.Daemon.ExitCode(); code != 0 {
					t.Errorf("want exit code 0 after SIGTERM, got %d", code)
				}
				expectNoMounts(t, dir, points...)
			}
			clean(t)
		})
	}
}
