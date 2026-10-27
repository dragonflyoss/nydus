package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// C14: when the backend starts failing, reads of data not yet cached fail
// with EIO, promptly and without ever returning wrong bytes, while cached
// data is still served and the daemon keeps running.
func init() {
	Register(Case{ID: "C14", Name: "BackendFailure", Scope: Own, RunOwn: runBackendFailure})
}

// backendFailureBudget bounds all reads after the backend failed; a hang
// (an unbounded retry, a lost reply) shows up as a timeout.
const backendFailureBudget = 60 * time.Second

func runBackendFailure(t *testing.T, a mount.Adapter) {
	img := fixture.Copy(t, SemanticImage(t))
	m := mount.Mount(t, a, img, mount.Options{
		Mode: mount.Cold,
		// Fetch only the missed chunk group, so reading one file does not
		// pull its neighbours into the cache.
		Config: func(c *mount.Config) { c.Storage.FetchSize = mount.Ptr(int64(0)) },
	})
	f := &Fixture{Mounted: m, Adapter: a}

	cached := "files/ten_blocks"
	want := wantBytes(t, f, cached)
	got, err := os.ReadFile(m.Path(cached))
	require.NoError(t, err)
	require.Equal(t, want, got)

	// The local backend keeps the blob open once it has read from it, so
	// removing the file would change nothing; truncating it makes every
	// further backend read come up short.
	require.NotEmpty(t, img.Blobs)
	for _, blob := range img.Blobs {
		require.NoError(t, os.Truncate(blob, 0))
	}

	type outcome struct {
		path string
		err  error
		ok   bool
	}
	files := hashedFiles(img.Want)
	readAll := func() []outcome {
		var out []outcome
		for _, e := range files {
			data, err := os.ReadFile(m.Path(string(e.Path)))
			sum := sha256.Sum256(data)
			out = append(out, outcome{string(e.Path), err, err == nil && hex.EncodeToString(sum[:]) == e.SHA256})
		}
		return out
	}
	done := make(chan []outcome, 1)
	go func() { done <- readAll() }()
	var results []outcome
	select {
	case results = <-done:
	case <-time.After(backendFailureBudget):
		t.Fatalf("reads did not finish within %s of the backend failing", backendFailureBudget)
	}

	failed := 0
	for _, r := range results {
		if r.err != nil {
			require.ErrorIs(t, r.err, unix.EIO, "%s: a failed backend read must surface as EIO", r.path)
			failed++
			continue
		}
		require.True(t, r.ok, "%s: read wrong bytes after the backend failed", r.path)
	}
	require.Positive(t, failed, "every read succeeded, so none reached the failing backend")

	// What was cached before the failure is still served, from the cache
	// rather than the page cache.
	fd := openRO(t, m.Path(cached))
	require.NoError(t, unix.Fadvise(fd, 0, 0, unix.FADV_DONTNEED))
	buf := make([]byte, len(want)+1)
	n, err := unix.Pread(fd, buf, 0)
	require.NoError(t, err, "%s: cached data after the backend failed", cached)
	require.Equal(t, want, buf[:n])

	// A failed read is not cached as success: retrying fails again.
	for _, r := range results {
		if r.err == nil {
			continue
		}
		_, err := os.ReadFile(m.Path(r.path))
		require.ErrorIs(t, err, unix.EIO, "%s: retry after a failed read", r.path)
		break
	}

	require.True(t, m.Daemon.Alive(), "the daemon died when its backend failed")
	require.True(t, mount.IsMountpoint(m.Root), "the mount went away when its backend failed")
	// Metadata does not depend on the blobs.
	require.NotEmpty(t, oracle.SortedDirents(t, m.Path("dirs/many_entries")))
}
