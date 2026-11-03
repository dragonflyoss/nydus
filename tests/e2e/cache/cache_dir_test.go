package cache

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

const (
	mapCountOffset = 16
	mapStateOffset = 24
	mapAllReady    = 1
	mapHeaderSize  = 4096
)

type cacheDir struct {
	path string
}

func newCache(t testing.TB) cacheDir {
	t.Helper()
	return cacheDir{path: filepath.Join(env.WorkDir(t), "cache")}
}

func (c cacheDir) file(blob, suffix string) string {
	return filepath.Join(c.path, blob+suffix)
}

func (c cacheDir) mount(t testing.TB, img fixture.Image, edits ...func(*mount.Config)) peer {
	t.Helper()
	return peer{mount.Mount(t, mount.FUSE{}, img, mount.Options{
		CacheDir: c.path,
		Config: func(cfg *mount.Config) {
			for _, edit := range edits {
				edit(cfg)
			}
		},
	})}
}

func (c cacheDir) mountN(t testing.TB, n int, img fixture.Image, edits ...func(*mount.Config)) peers {
	t.Helper()
	mounts := make(peers, n)
	for i := range mounts {
		mounts[i] = c.mount(t, img, edits...)
	}

	return mounts
}

func prefetchAll(c *mount.Config) { c.Prefetch = &mount.PrefetchConfig{Scope: "all"} }

func (c cacheDir) waitAllReady(t testing.TB, blobs ...string) {
	t.Helper()
	for _, blob := range blobs {
		if !assert.Eventually(t, func() bool { return c.allReady(blob) }, 60*time.Second, 100*time.Millisecond) {
			t.FailNow()
		}
	}
}

func (c cacheDir) allReady(blob string) bool {
	f, err := os.Open(c.file(blob, mount.CacheMapSuffix))
	if err != nil {
		return false
	}

	defer func() { _ = f.Close() }()
	var state [4]byte
	if _, err := f.ReadAt(state[:], mapStateOffset); err != nil {
		return false
	}

	return binary.LittleEndian.Uint32(state[:])&mapAllReady != 0
}

func (c cacheDir) flipData(t testing.TB, blob string) int {
	t.Helper()
	f, err := os.OpenFile(c.file(blob, mount.CacheDataSuffix), os.O_RDWR, 0)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	fd := int(f.Fd())
	flipped := 0

	for off := int64(0); off < st.Size(); {
		data, err := unix.Seek(fd, off, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) {
			break
		}
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		hole, err := unix.Seek(fd, data, unix.SEEK_HOLE)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		for p := data; p < hole; p += 64 << 10 {
			var b [1]byte
			if _, err := f.ReadAt(b[:], p); !assert.NoError(t, err) {
				t.FailNow()
			}

			b[0] ^= 0xff
			if _, err := f.WriteAt(b[:], p); !assert.NoError(t, err) {
				t.FailNow()
			}

			flipped++
		}

		off = hole
	}

	return flipped
}

func (c cacheDir) forgeReady(t testing.TB, blob string) int {
	t.Helper()
	f, err := os.OpenFile(c.file(blob, mount.CacheMapSuffix), os.O_RDWR, 0)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { _ = f.Close() }()
	var hdr [4]byte
	if _, err := f.ReadAt(hdr[:], mapCountOffset); !assert.NoError(t, err) {
		t.FailNow()
	}

	count := int(binary.LittleEndian.Uint32(hdr[:]))
	bitmap := make([]byte, (count+7)/8)
	if _, err := f.ReadAt(bitmap, mapHeaderSize); !assert.NoError(t, err) {
		t.FailNow()
	}

	forged := 0

	for i := range count {
		if mask := byte(1) << (i % 8); bitmap[i/8]&mask == 0 {
			bitmap[i/8] |= mask
			forged++
		}
	}

	if _, err := f.WriteAt(bitmap, mapHeaderSize); !assert.NoError(t, err) {
		t.FailNow()
	}

	return forged
}

func (c cacheDir) holdFlock(t testing.TB, blob, suffix string) func() {
	t.Helper()
	f := openLockFile(t, c.file(blob, suffix))
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); !assert.NoError(t, err) {
		_ = f.Close()
		t.FailNow()
	}

	return releaser(t, f)
}

func (c cacheDir) holdOFD(t testing.TB, blob, suffix string) func() {
	t.Helper()
	f := openLockFile(t, c.file(blob, suffix))

	lk := unix.Flock_t{Type: unix.F_WRLCK}
	if err := unix.FcntlFlock(f.Fd(), unix.F_OFD_SETLK, &lk); !assert.NoError(t, err) {
		_ = f.Close()
		t.FailNow()
	}

	return releaser(t, f)
}

func openLockFile(t testing.TB, path string) *os.File {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); !assert.NoError(t, err) {
		t.FailNow()
	}

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return f
}

func releaser(t testing.TB, f *os.File) func() {
	var once sync.Once
	release := func() { once.Do(func() { _ = f.Close() }) }
	t.Cleanup(release)

	return release
}
