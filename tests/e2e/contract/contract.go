// Package contract is the filesystem contract every way of serving an image
// must honor: FUSE and fileio (GA) and the experimental transports. A case
// is written once against a mounted image and runs unchanged against each
// adapter; an adapter's test is a single call to Run.
//
// Each case lives in a file named after it and is listed in cases. Cases come
// in three scopes. Semantic cases check behavior, which does not depend on how
// the image is encoded: they run once per adapter against the semantic
// image. Data cases check what is read back, which does: they run against
// every image of fixture.Matrix in every mode the adapter supports. That is
// "semantics once, data across the matrix". Own cases need a mount nothing
// else shares, such as one whose backend fails or that is torn down: they run
// once per adapter and mount the semantic image themselves.
package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// Scope selects the mounts a case runs against: the shared Semantic mount,
// the Data mounts, or, for Own, mounts the case starts itself. Semantic and
// Data combine; Own stands alone.
type Scope int

const (
	Semantic Scope = 1 << iota
	Data
	Own

	semanticLayout = "zstd-4k"

	faultInLimit    = 8 << 20
	unprivilegedUID = 65534

	faultInTimeout        = 30 * time.Second
	exitTimeout           = 15 * time.Second
	backendFailureTimeout = 60 * time.Second
)

// Fixture is the mount a Semantic or Data case runs against.
type Fixture struct {
	*mount.Mounted
	Adapter mount.Adapter
}

// Src joins rel onto the source tree of the image; empty for merged images.
func (f *Fixture) Src(rel string) string {
	if f.Image.Source == "" {
		return ""
	}

	return f.Image.Source + "/" + rel
}

// Case is one contract case.
type Case struct {
	Name  string
	Scope Scope
	// Run checks a Semantic or Data fixture. Cases call t.Parallel in their
	// subtests as they see fit; the case itself already runs in parallel.
	Run func(t *testing.T, f *Fixture)
	// RunOwn checks an Own case against the adapter.
	RunOwn func(t *testing.T, a mount.Adapter)
	// Supports narrows the adapters, modes or layouts a case applies to;
	// nil means all. Own cases see the zero Layout. A case that does not
	// apply is not run at all, rather than skipped, so the adapter's coverage
	// is visible in its case list.
	Supports func(a mount.Adapter, m mount.Mode, l fixture.Layout) bool
}

var cases = []Case{
	// The mount reproduces the image's tree exactly: paths, metadata,
	// content, link targets, hardlink groups and xattrs.
	{Name: "Tree", Scope: Semantic | Data, Run: runTree},

	// Every regular file reads back front to back, whatever the read size,
	// from a cold page cache, including into buffers that are themselves mapped
	// from the mount.
	{Name: "SequentialRead", Scope: Data, Run: runSequentialRead},

	// Reads that do not start or end where a sequential reader would:
	// unaligned and boundary-straddling preads, vectored reads, reads at and
	// past EOF, and holes.
	{Name: "ReadPaths", Scope: Semantic, Run: runReadPaths},

	// Lseek and the SEEK_DATA/SEEK_HOLE map obey POSIX, including offsets
	// past 4GiB. No hole granularity is assumed: the FUSE reader has no lseek
	// handler, so the kernel reports every file as one data extent, and a
	// chunked image would not report the extents of the source anyway.
	{Name: "Sparse", Scope: Semantic | Data, Run: runSparse},

	// The raw getdents64 stream rather than os.ReadDir, because the fields
	// os.ReadDir throws away (d_type, d_ino, d_off) are exactly the ones the
	// EROFS directory encoder has to get right; and the directory offset
	// protocol of fstests' t_dir_offset2: every d_off is unique, and seeking to
	// one resumes the stream at the following entry.
	{Name: "Dirents", Scope: Semantic, Run: runDirents},

	// Lookups, symlink resolution and the errors path walking must stop
	// with, including the loop shapes of generic/005.
	{Name: "PathResolution", Scope: Semantic, Run: runPathResolution},

	// Extended attributes: the size probe, ERANGE and ENODATA, empty and
	// binary values, every namespace a container image carries, and values that
	// spill out of the inline xattr body.
	{Name: "Xattr", Scope: Semantic, Run: runXattr},

	// Every mutating syscall is refused with EROFS. EACCES or EPERM would be
	// wrong: the caller is root, so the read-only mount is the only reason the
	// call cannot proceed. Afterwards nothing has changed.
	{Name: "WriteRejection", Scope: Semantic, Run: runWriteRejection},

	// Memory mappings of files on the mount: shared and private reads, the
	// zero-filled tail page, private copy-on-write, and no shared writable
	// mapping.
	{Name: "Mmap", Scope: Semantic, Run: runMmap},

	// The read paths that bypass read(2): sendfile, splice,
	// copy_file_range and O_DIRECT, plus the open flags that change what an open
	// returns.
	{Name: "ZeroCopy", Scope: Semantic, Run: runZeroCopy},

	// Concurrent readers agree, and what can never change does not:
	// timestamps stay put and repeated queries give the same answer.
	{Name: "Concurrency", Scope: Semantic, Run: runConcurrency},

	// A warm mount serves the whole tree from its cache: reading every byte
	// of data issues no backend read. Native erofs blobs are read in place and
	// never cached (nydus-storage/src/cache/raw.rs), so the case does not apply
	// to them.
	{
		Name: "WarmCache", Scope: Data, Run: runWarmCache,
		// Needs the daemon's backend counters.
		Supports: func(a mount.Adapter, m mount.Mode, l fixture.Layout) bool {
			return m == mount.Warm && mount.TraitsOf(a).API && !l.Native
		},
	},

	// Attributes and the syscalls built on them: metadata the builder has
	// to encode specially, inode identity, permission checks by an unprivileged
	// uid, statfs, locks, and how a process sees itself inside the mount.
	{Name: "Attributes", Scope: Semantic, Run: runAttributes},

	// When the backend starts failing, reads of data not yet cached fail
	// with EIO, promptly and without ever returning wrong bytes, while cached
	// data is still served and the daemon keeps running.
	{Name: "BackendFailure", Scope: Own, RunOwn: runBackendFailure},

	// A mount comes and goes cleanly: remounts give the same inode numbers,
	// SIGTERM unmounts and exits 0, and an unmount while files are open or mapped
	// is refused or, when lazy, leaves those references working.
	{Name: "Lifecycle", Scope: Own, RunOwn: runLifecycle},
}

// semanticImage is the image Semantic and Own cases run against: the
// Stress corpus, a superset of the Standard tree whose paths the semantic
// cases address by name, built with semanticLayout.
func semanticImage(t *testing.T) fixture.Image {
	t.Helper()
	return fixture.Build(t, fixture.Stress, fixture.MustLayout(t, semanticLayout))
}

// Run runs every applicable case against a: the semantic cases on one
// shared mount, the own cases, and the data cases on one mount per matrix
// image and mode. Every level runs in parallel.
func Run(t *testing.T, a mount.Adapter) {
	a.Require(t)

	for _, s := range subtests(a) {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			s.run(t)
		})
	}
}

// subtest is one top-level subtest of Run.
type subtest struct {
	name string
	run  func(t *testing.T)
}

// subtests lists the top-level subtests Run creates for a.
func subtests(a mount.Adapter) []subtest {
	out := []subtest{{name: "Semantic", run: func(t *testing.T) {
		runCases(t, Semantic, &Fixture{Mounted: mount.Mount(t, a, semanticImage(t), mount.Options{Mode: mount.Cold}), Adapter: a})
	}}}

	for _, c := range cases {
		if c.Scope != Own || (c.Supports != nil && !c.Supports(a, mount.Cold, fixture.Layout{})) {
			continue
		}

		out = append(out, subtest{name: c.Name, run: func(t *testing.T) { c.RunOwn(t, a) }})
	}

	for _, name := range fixture.Matrix {
		for _, mode := range mount.Modes {
			if !a.Supports(mode) || (mode == mount.Blob && strings.HasPrefix(name, fixture.MergedPrefix)) {
				continue
			}

			out = append(out, subtest{name: "Data/" + name + "/" + string(mode), run: func(t *testing.T) {
				runCases(t, Data, &Fixture{Mounted: mount.Mount(t, a, fixture.Get(t, name), mount.Options{Mode: mode}), Adapter: a})
			}})
		}
	}

	return out
}

func runCases(t *testing.T, scope Scope, f *Fixture) {
	for _, c := range cases {
		if c.Scope&scope == 0 || (c.Supports != nil && !c.Supports(f.Adapter, f.Mode, f.Image.Layout)) {
			continue
		}

		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			c.Run(t, f)
		})
	}
}

// hashedFiles returns the regular files of want whose whole content hash is
// recorded, i.e. those small enough to read in full.
func hashedFiles(want []fstest.Entry) []fstest.Entry {
	var out []fstest.Entry

	for _, e := range want {
		if e.Type == fstest.TypeReg && e.SHA256 != "" {
			out = append(out, e)
		}
	}

	return out
}

// sequentialHash reads path with read(2) calls of bufSize bytes, after
// dropping its cached pages so the reads reach the filesystem.
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

// isKernelEROFS reports whether the adapter serves the image through the
// kernel EROFS driver rather than the nydus FUSE reader; every adapter but
// FUSE does. Where the two legitimately differ the cases branch on it.
func (f *Fixture) isKernelEROFS() bool {
	_, fuse := f.Adapter.(mount.FUSE)
	return !fuse
}

// wantBytes returns the content rel has in the semantic image's source.
func (f *Fixture) wantBytes(t *testing.T, rel string) []byte {
	t.Helper()
	src := f.Src(rel)
	if !assert.NotEmpty(t, src) {
		t.FailNow()
	}

	data, err := os.ReadFile(src)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return data
}
