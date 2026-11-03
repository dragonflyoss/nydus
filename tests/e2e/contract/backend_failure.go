package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
)

func runBackendFailure(t *testing.T, a mount.Adapter) {
	img := fixture.Copy(t, semanticImage(t))

	m := mount.Mount(t, a, img, mount.Options{
		Mode: mount.Cold,
		// Fetch only the missed chunk group, so reading one file does not
		// pull its neighbours into the cache.
		Config: func(c *mount.Config) { c.Storage.FetchSize = mount.Ptr(int64(0)) },
	})

	f := &Fixture{Mounted: m, Adapter: a}

	cached := "files/ten_blocks"
	want := f.wantBytes(t, cached)
	got, err := os.ReadFile(m.Path(cached))
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.True(t, bytes.Equal(want, got)) {
		t.FailNow()
	}

	// The local backend keeps the blob open once it has read from it, so
	// removing the file would change nothing; truncating it makes every
	// further backend read come up short.
	if !assert.NotEmpty(t, img.Blobs) {
		t.FailNow()
	}

	for _, blob := range img.Blobs {
		assert.NoError(t, os.Truncate(blob, 0))
	}

	type outcome struct {
		path string
		err  error
		want string
		sum  string
	}

	files := hashedFiles(img.Want)

	readAll := func() []outcome {
		var out []outcome

		for _, e := range files {
			data, err := os.ReadFile(m.Path(string(e.Path)))
			sum := sha256.Sum256(data)
			out = append(out, outcome{string(e.Path), err, e.SHA256, hex.EncodeToString(sum[:])})
		}

		return out
	}

	done := make(chan []outcome, 1)

	go func() { done <- readAll() }()
	var results []outcome

	select {
	case results = <-done:

	case <-time.After(backendFailureTimeout):
		t.Fatalf("reads did not finish within %s of the backend failing", backendFailureTimeout)
	}

	failed := 0

	for _, r := range results {
		if r.err != nil {
			assert.ErrorIs(t, r.err, unix.EIO)
			failed++
			continue
		}

		assert.Equal(t, r.want, r.sum)
	}

	assert.Positive(t, failed)

	// What was cached before the failure is still served, from the cache
	// rather than the page cache.
	fd := openRO(t, m.Path(cached))
	if !assert.NoError(t, unix.Fadvise(fd, 0, 0, unix.FADV_DONTNEED)) {
		t.FailNow()
	}

	buf := make([]byte, len(want)+1)
	n, err := unix.Pread(fd, buf, 0)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.True(t, bytes.Equal(want, buf[:n]))

	// A failed read is not cached as success: retrying fails again.
	for _, r := range results {
		if r.err == nil {
			continue
		}

		_, err := os.ReadFile(m.Path(r.path))
		assert.ErrorIs(t, err, unix.EIO)
		break
	}

	if !assert.True(t, m.Daemon.Alive()) {
		t.FailNow()
	}
	if !assert.True(t, mount.IsMountpoint(m.Root)) {
		t.FailNow()
	}
	// Metadata does not depend on the blobs.
	assert.NotEmpty(t, fstest.SortedDirents(t, m.Path("dirs/many_entries")))
}
