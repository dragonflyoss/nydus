package nbd

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// The transport dataset: two tiny files, a 400K file, a fan of small files
// of distinct sizes for the concurrent readers, and a file large enough to
// tell a bounded range fetch from a whole-blob pull.
const (
	largeFile = "large.bin"
	largeSize = 64 << 20
	manyFiles = 48
	repo      = "nydus-e2e/nbd"
)

func manyName(i int) string { return fmt.Sprintf("many/f%d.bin", i) }

// served is the dataset image behind an in-process registry, so a test can
// count the backend fetches.
type served struct {
	img fixture.Image
	reg *registry.Registry
}

// serveDataset builds the dataset image and pushes its blob to a registry.
// The dataset is specific to these tests, so it is built in the test's own
// directory rather than taken from the fixture cache.
func serveDataset(t *testing.T) *served {
	t.Helper()
	dir := env.WorkDir(t)
	src := filepath.Join(dir, "source")
	c := corpus.NewCorpus(t, src)
	c.CreateFile(t, "hello.txt", []byte("hello nydus nbd\n"))
	c.CreateFile(t, "subdir/nested.txt", []byte("nested file content\n"))
	writeRandom(t, c, "data.bin", 100*4096)
	writeRandom(t, c, largeFile, largeSize)
	for i := 1; i <= manyFiles; i++ {
		writeRandom(t, c, manyName(i), (4+(i*7)%20)*4096)
	}

	layout, err := fixture.LayoutByName("zstd")
	require.NoError(t, err)
	blobDir := filepath.Join(dir, "blobs")
	bootstrap := filepath.Join(dir, "image.bootstrap")
	blob, _ := fixture.BuildInto(t, blobDir, bootstrap, src, layout)
	img := fixture.Image{
		Name:      "transport-" + layout.Name,
		Layout:    layout,
		Corpus:    "transport",
		Bootstrap: bootstrap,
		BlobDir:   blobDir,
		Blobs:     []string{blob},
		Source:    src,
		Want:      oracle.ScanSource(t, src),
	}
	reg := registry.Start(t)
	reg.PushBlobs(t, repo, img.Blobs)
	return &served{img: img, reg: reg}
}

// writeRandom writes size pseudo-random bytes seeded by the file name, so
// every file differs yet the dataset is reproducible. (The legacy suite
// seeded by path length, which gave same-length paths identical content.)
func writeRandom(t *testing.T, c *corpus.Corpus, name string, size int) {
	t.Helper()
	data := make([]byte, size)
	_, _ = rand.NewChaCha8(sha256.Sum256([]byte(name))).Read(data)
	c.CreateFile(t, name, data)
}

// mount serves the dataset through NBD from the registry, with its cache in
// cacheDir (a fresh one when empty).
func (s *served) mount(t *testing.T, cacheDir string) *mount.Mounted {
	t.Helper()
	return mount.Mount(t, NBD{}, s.img, mount.Options{
		CacheDir: cacheDir,
		Config: func(c *mount.Config) {
			c.Backend = mount.RegistryBackend(mount.Registry{Addr: s.reg.URL, Repository: repo})
		},
	})
}

// blobGets counts the blob GETs the registry has served.
func (s *served) blobGets() int {
	n := 0
	for _, r := range s.reg.Faults.Requests() {
		if r.Method == http.MethodGet && strings.Contains(r.Path, "/blobs/sha256:") {
			n++
		}
	}
	return n
}

// cacheFiles returns the decoded blob cache files under dir.
func cacheFiles(dir string) []string {
	files, _ := filepath.Glob(filepath.Join(dir, "*.blob.data"))
	return files
}

// allocated returns the bytes allocated to path, not its apparent size: a
// sparse cache file only grows as ranges are fetched.
func allocated(path string) int64 {
	var st unix.Stat_t
	if unix.Stat(path, &st) != nil {
		return 0
	}
	return st.Blocks * 512
}

// cacheUsed sums the allocated bytes of every cache file under dir.
func cacheUsed(dir string) int64 {
	var total int64
	for _, f := range cacheFiles(dir) {
		total += allocated(f)
	}
	return total
}

// readAt reads up to n bytes of path at off.
func readAt(path string, off, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, n)
	got, err := f.ReadAt(buf, off)
	if err == io.EOF {
		err = nil
	}
	return buf[:got], err
}

// sameRange checks that mnt holds the bytes of src in [off, off+n).
func sameRange(src, mnt string, off, n int64) error {
	want, err := readAt(src, off, n)
	if err != nil {
		return err
	}
	got, err := readAt(mnt, off, n)
	if err != nil {
		return fmt.Errorf("read %s at %d: %w", mnt, off, err)
	}
	if !bytes.Equal(want, got) {
		return fmt.Errorf("%s: %d bytes at %d differ from the source", mnt, n, off)
	}
	return nil
}

// sameFile checks that mnt holds exactly the bytes of src.
func sameFile(src, mnt string) error {
	st, err := os.Stat(src)
	if err != nil {
		return err
	}
	return sameRange(src, mnt, 0, st.Size()+1)
}

// dropPageCache evicts path from the page cache, so the next read reaches
// the transport instead of being served by the kernel.
func dropPageCache(t *testing.T, path string) {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	require.NoError(t, unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED))
}

// requireHealthy asserts the daemon logged no protocol or read error.
func requireHealthy(t *testing.T, d *mount.Daemon) {
	t.Helper()
	mount.RequireHealthy(t, d)
}
