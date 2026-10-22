package fault

import (
	"syscall"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/proc"
)

// TestDaemonCrash SIGKILLs the daemon while readers are busy. Every read in
// flight or issued afterwards returns within a bound and never returns
// wrong bytes: through FUSE it fails (ENOTCONN once the kernel aborts the
// connection); through fileio it fails or, for pages the kernel still
// caches, succeeds. Tearing down leaves no mount, and a new daemon on the
// same cache directory, holding whatever the killed one half wrote, serves
// the image exactly.
func TestDaemonCrash(t *testing.T) {
	t.Parallel()
	img := fixture.Get(t, "zstd-4k")
	for _, a := range adapters {
		t.Run(a.Name(), func(t *testing.T) {
			t.Parallel()
			m := mount.Mount(t, a, img, mount.Options{})
			rd := startReaders(t, m.Root, dataFiles(t, img), 8)
			rd.waitOK(t, 8, readTimeout)

			kids := proc.Children(m.Daemon.Pid())
			m.Daemon.Kill()
			killed := time.Now()
			rd.stopWithin(t, 10*time.Second)
			t.Logf("readers drained %s after the kill", time.Since(killed).Round(time.Millisecond))

			r := readWithin(t, m.Root, lookup(t, img, bigFile), 10*time.Second)
			t.Logf("read after the kill: %s", r)
			expectNotWrong(t, r)
			if a.Name() == "fuse" {
				expectFailed(t, r)
				if r.Err != nil && !isErrno(r.Err, syscall.ENOTCONN, syscall.ECONNABORTED, syscall.EIO) {
					t.Errorf("want ENOTCONN or EIO from a dead FUSE daemon: %s", r)
				}
			}

			dir, points := daemonDir(m), mountpoints(m)
			m.Unmount()
			if left, _ := proc.MountsUnder(dir); len(left) > 0 {
				t.Errorf("teardown after a crash left %v mounted", left)
				for _, p := range left {
					mount.Unmount(p)
				}
			}
			expectNoMounts(t, dir, points...)
			expectGone(t, kids, exitTimeout)

			again := mount.Mount(t, a, img, mount.Options{CacheDir: m.CacheDir})
			oracle.VerifyMount(t, again.Root, img.Want, img.Compare())
		})
	}
}
