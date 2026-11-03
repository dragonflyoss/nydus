package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/experimental/fanotify"
	"github.com/dragonflyoss/nydus/tests/e2e/experimental/nbd"
	"github.com/dragonflyoss/nydus/tests/e2e/experimental/ublk"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

const (
	semanticLayout = "zstd-4k"

	faultInLimit    = 8 << 20
	unprivilegedUID = 65534

	faultInTimeout        = 30 * time.Second
	exitTimeout           = 15 * time.Second
	backendFailureTimeout = 60 * time.Second
)

type mounted struct {
	*mount.Mounted
	adapter mount.Adapter
}

func (m *mounted) src(rel string) string {
	if m.Image.Source == "" {
		return ""
	}

	return m.Image.Source + "/" + rel
}

type testCase struct {
	name    string
	test    func(t *testing.T, m *mounted)
	applies func(m *mounted) bool
}

var semanticCases = []testCase{
	{name: "Tree", test: testTree},
	{name: "ReadPaths", test: testReadPaths},
	{name: "Sparse", test: testSparse},
	{name: "Dirents", test: testDirents},
	{name: "PathResolution", test: testPathResolution},
	{name: "Xattr", test: testXattr},
	{name: "WriteRejection", test: testWriteRejection},
	{name: "Mmap", test: testMmap},
	{name: "ZeroCopy", test: testZeroCopy},
	{name: "Concurrency", test: testConcurrency},
	{name: "Attributes", test: testAttributes},
}

var dataCases = []testCase{
	{name: "Tree", test: testTree},
	{name: "SequentialRead", test: testSequentialRead},
	{name: "Sparse", test: testSparse},
	{name: "WarmCache", test: testWarmCache, applies: func(m *mounted) bool {
		return m.Mode == mount.Warm && mount.TraitsOf(m.adapter).API && !m.Image.Layout.Native
	}},
}

var ownCases = []struct {
	name string
	test func(t *testing.T, a mount.Adapter)
}{
	{name: "BackendFailure", test: testBackendFailure},
	{name: "Lifecycle", test: testLifecycle},
}

func semanticImage(t *testing.T) fixture.Image {
	t.Helper()
	return fixture.Build(t, fixture.Stress, fixture.MustLayout(t, semanticLayout))
}

func testAdapter(t *testing.T, a mount.Adapter) {
	a.Require(t)

	t.Run("Semantic", func(t *testing.T) {
		t.Parallel()
		runCases(t, semanticCases, &mounted{Mounted: mount.Mount(t, a, semanticImage(t), mount.Options{Mode: mount.Cold}), adapter: a})
	})

	for _, c := range ownCases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			c.test(t, a)
		})
	}

	for _, name := range fixture.Matrix {
		for _, mode := range mount.Modes {
			if !a.Supports(mode) || (mode == mount.Blob && strings.HasPrefix(name, fixture.MergedPrefix)) {
				continue
			}

			t.Run("Data/"+name+"/"+string(mode), func(t *testing.T) {
				t.Parallel()
				runCases(t, dataCases, &mounted{Mounted: mount.Mount(t, a, fixture.Get(t, name), mount.Options{Mode: mode}), adapter: a})
			})
		}
	}
}

func runCases(t *testing.T, cases []testCase, m *mounted) {
	for _, c := range cases {
		if c.applies != nil && !c.applies(m) {
			continue
		}

		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			c.test(t, m)
		})
	}
}

func hashedFiles(want []fstest.Entry) []fstest.Entry {
	var out []fstest.Entry

	for _, e := range want {
		if e.Type == fstest.TypeReg && e.SHA256 != "" {
			out = append(out, e)
		}
	}

	return out
}

func sequentialHash(path string, bufSize int) (string, int64, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", 0, err
	}

	defer func() { _ = unix.Close(fd) }()
	_ = unix.Fadvise(fd, 0, 0, unix.FADV_DONTNEED)

	h := sha256.New()
	buf := make([]byte, bufSize)
	var total int64

	for {
		n, err := unix.Read(fd, buf)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return "", total, err
		}
		if n == 0 {
			return hex.EncodeToString(h.Sum(nil)), total, nil
		}

		h.Write(buf[:n])
		total += int64(n)
	}
}

func (m *mounted) isKernelEROFS() bool {
	_, fuse := m.adapter.(mount.FUSE)
	return !fuse
}

func (m *mounted) wantBytes(t *testing.T, rel string) []byte {
	t.Helper()
	src := m.src(rel)
	if !assert.NotEmpty(t, src) {
		t.FailNow()
	}

	data, err := os.ReadFile(src)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return data
}

func TestFUSE(t *testing.T) {
	t.Parallel()
	testAdapter(t, mount.FUSE{})
}

func TestFileio(t *testing.T) {
	t.Parallel()
	testAdapter(t, mount.Fileio{})
}

func TestNBD(t *testing.T) {
	t.Parallel()
	testAdapter(t, nbd.NBD{})
}

func TestUblk(t *testing.T) {
	t.Parallel()
	testAdapter(t, ublk.Ublk{})
}

func TestFanotify(t *testing.T) {
	t.Parallel()
	testAdapter(t, fanotify.Fanotify{})
}
