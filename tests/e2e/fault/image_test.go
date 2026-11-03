package fault

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/stretchr/testify/assert"
)

const (
	repo = "e2e/fault"

	readTimeout   = 60 * time.Second
	exitTimeout   = 15 * time.Second
	rejectTimeout = 10 * time.Second

	primeFile    = "data/size/00004096"
	bigFile      = "data/size/08392705"
	forgedFile   = "data/size/02097153"
	forgedOffset = 1<<20 + 100
)

var adapters = []mount.Adapter{mount.FUSE{}, mount.Fileio{}}

type image struct {
	fixture.Image
}

type dataFile struct {
	rel    string
	size   int64
	sha256 string
}

func (img image) dataFiles(t testing.TB) []dataFile {
	t.Helper()
	var out []dataFile

	for _, e := range img.Want {
		rel := string(e.Path)
		if e.Type == fstest.TypeReg && strings.HasPrefix(rel, "data/") && e.SHA256 != "" && e.Size > 0 && e.Size <= 16<<20 {
			out = append(out, dataFile{rel: rel, size: e.Size, sha256: e.SHA256})
		}
	}

	if !assert.NotEmpty(t, out) {
		t.FailNow()
	}

	slices.SortFunc(out, func(a, b dataFile) int { return strings.Compare(a.rel, b.rel) })

	return out
}

func (img image) lookup(t testing.TB, rel string) dataFile {
	t.Helper()
	for _, f := range img.dataFiles(t) {
		if f.rel == rel {
			return f
		}
	}

	t.Fatalf("image %s has no data file %s", img.Name, rel)

	return dataFile{}
}

type result struct {
	file    dataFile
	err     error
	wrong   bool
	elapsed time.Duration
}

func (r result) String() string {
	switch {
	case r.wrong:
		return fmt.Sprintf("%s: WRONG BYTES after %s", r.file.rel, r.elapsed)

	case r.err != nil:
		return fmt.Sprintf("%s: %v after %s", r.file.rel, r.err, r.elapsed)

	default:
		return fmt.Sprintf("%s: ok after %s", r.file.rel, r.elapsed)
	}
}

func (f dataFile) readOnce(t testing.TB, root string) result {
	t.Helper()
	return f.readWithin(t, root, readTimeout)
}

func (f dataFile) readWithin(t testing.TB, root string, timeout time.Duration) result {
	t.Helper()
	return f.judge(t, timeout, func() (string, error) { return fstest.HashFileCold(filepath.Join(root, f.rel)) })
}

func (f dataFile) judge(t testing.TB, timeout time.Duration, read func() (string, error)) result {
	t.Helper()
	ch := make(chan result, 1)
	start := time.Now()

	go func() {
		sum, err := read()
		ch <- result{file: f, err: err, wrong: err == nil && sum != f.sha256, elapsed: time.Since(start)}
	}()

	select {
	case r := <-ch:
		return r

	case <-time.After(timeout):
		t.Fatalf("read of %s did not return within %s: the daemon hangs", f.rel, timeout)
		return result{}
	}
}

func (r result) expectCorrect(t testing.TB) {
	t.Helper()
	assert.NoError(t, r.err)
	assert.False(t, r.wrong)
}

func (r result) expectNotWrong(t testing.TB) {
	t.Helper()
	assert.False(t, r.wrong)
}

func (r result) expectFailed(t testing.TB) {
	t.Helper()
	assert.Error(t, r.err)
}

type mounted struct {
	*mount.Mounted
}

func (img image) serve(t testing.TB) *registry.Served {
	t.Helper()
	return registry.Serve(t, img.Image, repo)
}

func (img image) mount(t testing.TB, a mount.Adapter, opts mount.Options) mounted {
	t.Helper()
	return mounted{mount.Mount(t, a, img.Image, opts)}
}

func (img image) mountRegistry(t testing.TB, a mount.Adapter, addr string, http *mount.HTTPConfig, verify bool) mounted {
	t.Helper()
	return img.mount(t, a, mount.Options{Config: func(c *mount.Config) {
		c.Backend = mount.RegistryBackend(mount.RegistryConfig{Addr: addr, Repository: repo, HTTP: http})

		if verify {
			c.Storage.SkipVerifyChecksums = mount.Ptr(false)
		}
	}})
}

func (m mounted) image() image { return image{m.Image} }

func (m mounted) prime(t testing.TB) {
	t.Helper()
	r := m.read(t, primeFile)
	if !assert.NoError(t, r.err) {
		t.FailNow()
	}
	if !assert.False(t, r.wrong) {
		t.FailNow()
	}
}

func (m mounted) read(t testing.TB, rel string) result {
	t.Helper()
	return m.image().lookup(t, rel).readOnce(t, m.Root)
}

func (m mounted) mustExit(t testing.TB, timeout time.Duration) {
	t.Helper()
	if !assert.True(t, m.Daemon.WaitExit(timeout)) {
		t.FailNow()
	}
}

func (m mounted) startReaders(t testing.TB, files []dataFile, n int) *readers {
	root := m.Root
	r := &readers{stop: make(chan struct{}), done: make(chan struct{})}
	t.Cleanup(r.halt)
	var wg sync.WaitGroup

	for i := range n {
		wg.Go(func() {
			for j := i; ; j++ {
				select {
				case <-r.stop:
					return

				default:
				}

				f := files[j%len(files)]
				sum, err := fstest.HashFileCold(filepath.Join(root, f.rel))

				switch {
				case err != nil:
					r.fails.Add(1)
					r.note(&r.firstErrs, fmt.Sprintf("%s: %v", f.rel, err))

					time.Sleep(10 * time.Millisecond)

				case sum != f.sha256:
					r.note(&r.wrong, f.rel)

				default:
					r.ok.Add(1)
				}
			}
		})
	}

	go func() { wg.Wait(); close(r.done) }()

	return r
}
