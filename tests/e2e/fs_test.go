package e2e

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// stressCorpusSeed keeps the stress tree reproducible; override it when
// chasing a failure that only a different shape produces.
const stressCorpusSeed = 20260806

// unprivilegedUID is the uid and gid the permission suite drops to.
const unprivilegedUID = 65534

// buildConfig is one `nydus build` parameterisation. Image layout is
// what turns a builder bug into a runtime bug, so the same test list is run
// against several encodings rather than a single canonical one.
//
// Blobs are always written with --blob-dir. `nydus fuse` rejects --bootstrap
// together with --blob, and resolves --blob-dir entries by the sha256 name
// that only --blob-dir produces, so a bootstrap-backed mount has no other
// option.
type buildConfig struct {
	// ID names the configuration in subtest names and paths.
	ID string

	// ChunkSize is the --chunk-size passed to the builder.
	ChunkSize int

	// Compressor is the --compressor passed to the builder.
	Compressor string
}

// buildConfigs deliberately picks the extremes of each dimension: the
// smallest legal chunk size against the built-in default, and uncompressed
// output against zstd.
var buildConfigs = []buildConfig{
	{
		ID:         "chunk4k-zstd",
		ChunkSize:  4096,
		Compressor: "zstd",
	},
	{
		ID:         "chunk1m-none",
		ChunkSize:  1 << 20,
		Compressor: "none",
	},
	{
		ID:         "chunk64k-zstd",
		ChunkSize:  64 << 10,
		Compressor: "zstd",
	},
	{
		ID:         "chunk4m-none",
		ChunkSize:  4 << 20,
		Compressor: "none",
	},
}

// mountedImage is one mounted image the read-only suites run against.
type mountedImage struct {
	// source is the tree the image was built from.
	source string

	// mountpoint is where the image is mounted.
	mountpoint string

	// bootstrap is the bootstrap of the image, for remounting it.
	bootstrap string

	// blobDir is the blob directory of the image, for remounting it.
	blobDir string
}

// at returns the path of rel inside the mount.
func (m *mountedImage) at(rel string) string { return filepath.Join(m.mountpoint, rel) }

// readOnlySuites are the read-only suites, each run as a parallel subtest against
// every build configuration and corpus.
var readOnlySuites = map[string]func(*testing.T, *mountedImage){
	"tree differential": func(t *testing.T, image *mountedImage) {
		util.CheckDirectoryEqual(t, image.source, image.mountpoint, true)
	},
	"fault in":          testFaultIn,
	"process view":      testProcessView,
	"write rejection":   testWriteRejection,
	"dirents":           testDirents,
	"dir offset":        testDirOffset,
	"inode identity":    testInodeIdentity,
	"metadata":          testMetadata,
	"read paths":        testReadPaths,
	"sparse map":        testSparseMap,
	"mmap":              testMmap,
	"seek":              testSeek,
	"splice sendfile":   testSpliceSendfile,
	"path resolution":   testPathResolution,
	"symlink loops":     testSymlinkLoops,
	"xattr":             testXattr,
	"statfs":            testStatfs,
	"open flags":        testOpenFlags,
	"permissions":       testPermissions,
	"locks and copy":    testLocksAndCopy,
	"stability":         testStability,
	"concurrency":       testConcurrency,
	"remount stability": testRemountStability,
}

// cwdMu serializes every subtest that changes the process working directory.
// The per-config suites run in parallel and the cwd is process-global, so
// without this the "getcwd inside mount" instances of different build configs
// race: one config's chdir (or deferred restore, or unmount) corrupts what
// another config's getcwd observes.
var cwdMu sync.Mutex

// TestFilesystemSemantics mounts a nydus image per build configuration and
// asserts POSIX behaviour that a read-only FUSE filesystem must get right.
//
// fstests cannot cover this ground: its generic tests assume a writable
// filesystem, so everything that matters for nydus (write rejection, dirent
// encoding, inode identity, mmap/splice on a read-only mount) either lives in
// the excluded set or does not exist upstream. These cases run against a single
// mount per build configuration and execute in parallel, which keeps the whole
// suite in the low seconds even though it covers far more syscalls than the
// fstests subset does.
func TestFilesystemSemantics(t *testing.T) {
	util.SkipUnlessRoot(t, "building the corpus needs device nodes and chown")

	// Both the directory testing hands out and the one above it are 0700, which
	// stops the permission suite's unprivileged uid from reaching the mount.
	root := t.TempDir()
	assert.NoError(t, os.Chmod(root, 0o755))
	assert.NoError(t, os.Chmod(filepath.Dir(root), 0o755))

	// Two corpora rather than one: the standard tree enumerates the cases a
	// human thinks of, the stress tree goes after the shapes that only appear
	// at volume (hundreds of sparse and special files, 255-byte names,
	// directories spanning several EROFS blocks).
	corpora := map[string]string{
		"standard": filepath.Join(root, "corpus-standard"),
		"stress":   filepath.Join(root, "corpus-stress"),
	}
	corpus.MakeStandardCorpus(t, corpora["standard"])
	corpus.MakeStressCorpus(t, corpora["stress"], stressCorpusSeed)

	for _, config := range buildConfigs {
		for corpusName, source := range corpora {
			t.Run(config.ID+"/"+corpusName, func(t *testing.T) {
				t.Parallel()

				// Build the image, then let erofs-utils validate the encoding
				// independently of the nydus reader: a builder bug the Rust
				// reader happens to tolerate still gets caught here.
				workDir := filepath.Join(root, config.ID+"-"+corpusName)
				blobDir := filepath.Join(workDir, "blobs")
				bootstrap := filepath.Join(workDir, "bootstrap")
				blob := util.BuildImage(t, nydusBin, bootstrap, blobDir, source, config.ChunkSize, "--compressor", config.Compressor)
				if blob == "" {
					return
				}

				// Mount the image once and run every suite against it.
				mountpoint := filepath.Join(workDir, "mnt")
				t.Cleanup(util.MountNydusBootstrap(t, nydusBin, bootstrap, blobDir, "", mountpoint))

				image := &mountedImage{source: source, mountpoint: mountpoint, bootstrap: bootstrap, blobDir: blobDir}
				for name, run := range readOnlySuites {
					t.Run(name, func(t *testing.T) {
						t.Parallel()
						run(t, image)
					})
				}
			})
		}
	}
}

// testWriteRejection asserts that every mutating syscall is refused with EROFS.
// Returning EACCES or EPERM instead would be wrong: the caller is root, so the
// permission checks pass and the read-only nature of the mount is the only
// reason the call cannot proceed.
func testWriteRejection(t *testing.T, image *mountedImage) {
	file := image.at("files/small_100b")
	dir := image.at("dirs/empty_dir")
	link := image.at("symlinks/link_to_file")
	absent := image.at("dirs/empty_dir/created")

	tests := []struct {
		name   string
		op     func() error
		alsoOK []error
	}{
		{name: "open write only", op: func() error { return util.TryOpen(file, unix.O_WRONLY, 0) }},
		{name: "open read write", op: func() error { return util.TryOpen(file, unix.O_RDWR, 0) }},
		{name: "open append", op: func() error { return util.TryOpen(file, unix.O_WRONLY|unix.O_APPEND, 0) }},
		{name: "open truncate", op: func() error { return util.TryOpen(file, unix.O_RDONLY|unix.O_TRUNC, 0) }},
		{name: "open create", op: func() error { return util.TryOpen(absent, unix.O_CREAT|unix.O_WRONLY, 0) }},
		{name: "access write", op: func() error { return unix.Access(file, unix.W_OK) }},
		{name: "truncate", op: func() error { return unix.Truncate(file, 0) }},
		{name: "unlink", op: func() error { return unix.Unlink(file) }},
		{name: "rmdir", op: func() error { return unix.Rmdir(dir) }},
		{name: "rename", op: func() error { return unix.Rename(file, absent) }},
		{name: "link", op: func() error { return unix.Link(file, absent) }},
		{name: "symlink", op: func() error { return unix.Symlink("target", absent) }},
		{name: "mkdir", op: func() error { return unix.Mkdir(absent, 0o755) }},
		{name: "mknod", op: func() error { return unix.Mknod(absent, unix.S_IFIFO|0o644, 0) }},
		{name: "chmod", op: func() error { return unix.Chmod(file, 0o600) }},
		{name: "chown", op: func() error { return unix.Chown(file, 12345, 12345) }},
		{name: "lchown", op: func() error { return unix.Lchown(link, 12345, 12345) }},
		{name: "utimensat", op: func() error {
			return unix.UtimesNano(file, []unix.Timespec{{Sec: 1}, {Sec: 1}})
		}},
		{name: "setxattr", op: func() error {
			return unix.Setxattr(file, "user.injected", []byte("x"), 0)
		}},
		{name: "removexattr", op: func() error {
			return unix.Removexattr(image.at("xattrs/user_basic"), "user.test")
		}},
		{
			name: "open tmpfile",
			op:   func() error { return util.TryOpen(image.at("dirs"), unix.O_TMPFILE|unix.O_RDWR, 0o600) },
			// O_TMPFILE is optional; a filesystem that never implements it
			// reports EOPNOTSUPP before it ever gets to the read-only check.
			alsoOK: []error{unix.EOPNOTSUPP, unix.EISDIR},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert := assert.New(t)

			err := tc.op()
			assert.Error(err, "%s unexpectedly succeeded on a read-only mount", tc.name)
			accepted := errors.Is(err, unix.EROFS) || slices.ContainsFunc(tc.alsoOK, func(ok error) bool { return errors.Is(err, ok) })
			assert.True(accepted, "%s returned %v, want EROFS", tc.name, err)
		})
	}
}

// testDirents checks the raw getdents64 stream rather than os.ReadDir, because
// the fields os.ReadDir throws away (d_type, d_ino, d_off) are exactly the ones
// the EROFS directory encoder has to get right.
func testDirents(t *testing.T, image *mountedImage) {
	t.Run("dot entries", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		names := util.DirentNames(util.ReadDirents(t, image.at("dirs/empty_dir"), 32<<10))
		assert.Contains(names, ".")
		assert.Contains(names, "..")
	})

	t.Run("type and ino match stat", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		for _, dir := range []string{"files", "symlinks", "special", "hardlinks", "names"} {
			for _, e := range util.ReadDirents(t, image.at(dir), 32<<10) {
				if e.Name == "." || e.Name == ".." {
					continue
				}

				var st unix.Stat_t
				assert.NoError(unix.Lstat(filepath.Join(image.at(dir), e.Name), &st))
				assert.Equal(util.DirentType(st.Mode), e.Type, "%s/%s: d_type does not match st_mode", dir, e.Name)
				assert.Equal(st.Ino, e.Ino, "%s/%s: d_ino does not match st_ino", dir, e.Name)
			}
		}
	})

	t.Run("large directory complete", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		// 200 entries do not fit in one 4KiB EROFS directory block, so this
		// walks the block-splitting path in the builder.
		got := map[string]int{}
		for _, e := range util.ReadDirents(t, image.at("dirs/many_entries"), 32<<10) {
			got[e.Name]++
		}
		delete(got, ".")
		delete(got, "..")

		assert.Len(got, 200, "wrong number of entries")
		for name, n := range got {
			assert.Equal(1, n, "%s appeared %d times", name, n)
		}
		for i := 1; i <= 200; i++ {
			assert.Contains(got, fmt.Sprintf("file_%04d", i))
		}
	})

	t.Run("small buffer yields same set", func(t *testing.T) {
		t.Parallel()

		// A buffer that only holds a few dirents forces many getdents64 calls
		// and exposes off-by-one errors in the resume offset.
		big := util.DirentNames(util.ReadDirents(t, image.at("dirs/many_entries"), 64<<10))
		small := util.DirentNames(util.ReadDirents(t, image.at("dirs/many_entries"), 512))
		slices.Sort(big)
		slices.Sort(small)
		assert.Equal(t, big, small)
	})

	t.Run("rewind repeats", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		fd, err := unix.Open(image.at("dirs/many_entries"), unix.O_RDONLY|unix.O_DIRECTORY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(fd) }()

		first := util.DirentNames(util.DrainDirents(t, fd, 1024))
		_, err = unix.Seek(fd, 0, unix.SEEK_SET)
		assert.NoError(err)
		second := util.DirentNames(util.DrainDirents(t, fd, 1024))

		slices.Sort(first)
		slices.Sort(second)
		assert.Equal(first, second, "rewinding the directory changed the entry set")
	})
}

// testInodeIdentity checks that inode numbers identify files the way the source
// tree does: shared by hardlinks, distinct otherwise, and on one device.
func testInodeIdentity(t *testing.T, image *mountedImage) {
	t.Run("hardlinks share inode", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		links := []string{
			"hardlinks/original",
			"hardlinks/link1",
			"hardlinks/link2",
			"hardlinks/subdir/link3",
		}
		var first unix.Stat_t
		assert.NoError(unix.Stat(image.at(links[0]), &first))
		assert.EqualValues(len(links), first.Nlink, "st_nlink does not match the hardlink count")

		for _, rel := range links[1:] {
			var st unix.Stat_t
			assert.NoError(unix.Stat(image.at(rel), &st))
			assert.Equal(first.Ino, st.Ino, "%s has a different inode number", rel)
			assert.Equal(first.Nlink, st.Nlink, "%s has a different link count", rel)
		}
	})

	t.Run("distinct files have distinct inodes", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		// Files with identical content must still be separate inodes: chunk
		// deduplication happens below the metadata layer and must not leak
		// into inode identity.
		var a, b unix.Stat_t
		assert.NoError(unix.Stat(image.at("hardlinks/same_content_a"), &a))
		assert.NoError(unix.Stat(image.at("hardlinks/same_content_b"), &b))
		assert.NotEqual(a.Ino, b.Ino)
		assert.EqualValues(1, a.Nlink)
	})

	t.Run("inodes unique across tree", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		seen := map[uint64]string{}
		assert.NoError(filepath.WalkDir(image.mountpoint, func(path string, _ os.DirEntry, err error) error {
			if err != nil {
				return err
			}

			var st unix.Stat_t
			if err := unix.Lstat(path, &st); err != nil {
				return err
			}
			if st.Nlink > 1 {
				return nil
			}

			prev, dup := seen[st.Ino]
			assert.False(dup, "inode %d shared by %s and %s without a hardlink", st.Ino, prev, path)
			seen[st.Ino] = path
			return nil
		}))
	})

	t.Run("single device", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		var rootSt unix.Stat_t
		assert.NoError(unix.Stat(image.mountpoint, &rootSt))
		assert.NoError(filepath.WalkDir(image.mountpoint, func(path string, _ os.DirEntry, err error) error {
			if err != nil {
				return err
			}

			var st unix.Stat_t
			if err := unix.Lstat(path, &st); err != nil {
				return err
			}
			assert.Equal(rootSt.Dev, st.Dev, "%s reports a different st_dev", path)
			return nil
		}))
	})
}

// testMetadata checks the stat fields the builder normalises or has to encode
// beyond the compact inode: root mode and mtime, device numbers, large ids,
// link counts and block counts.
func testMetadata(t *testing.T, image *mountedImage) {
	t.Run("root is always traversable", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		// Whatever umask staged the source tree, the root must not lock other
		// uids out of the image.
		var st unix.Stat_t
		assert.NoError(unix.Stat(image.mountpoint, &st))
		assert.EqualValues(0o755, st.Mode&0o777, "the root's permission bits are not pinned")
		assert.EqualValues(unix.S_IFDIR, st.Mode&unix.S_IFMT)
	})

	t.Run("root mtime is dropped", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		// The root's mtime is the build time, not a property of the content,
		// so the builder drops it to keep the bootstrap reproducible.
		var st unix.Stat_t
		assert.NoError(unix.Stat(image.mountpoint, &st))
		assert.Zero(st.Mtim.Sec, "the root's mtime should not be carried over")
		assert.Zero(st.Mtim.Nsec)
	})

	t.Run("device numbers", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		for rel, want := range map[string][2]uint32{
			"special/chardev": {1, 3},
			"special/blkdev":  {1, 0},
		} {
			var st unix.Stat_t
			assert.NoError(unix.Lstat(image.at(rel), &st))
			assert.EqualValues(want[0], unix.Major(st.Rdev), "%s: major", rel)
			assert.EqualValues(want[1], unix.Minor(st.Rdev), "%s: minor", rel)
		}
	})

	t.Run("large uid gid", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		// Beyond 16 bits the builder has to emit an extended inode instead of
		// the compact one.
		var st unix.Stat_t
		assert.NoError(unix.Lstat(image.at("special/large_uid_gid"), &st))
		assert.EqualValues(70000, st.Uid)
		assert.EqualValues(70001, st.Gid)
	})

	t.Run("directory link count", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		for _, rel := range []string{".", "dirs", "dirs/a", "dirs/empty_dir", "symlinks"} {
			path := image.at(rel)
			var st unix.Stat_t
			assert.NoError(unix.Stat(path, &st))

			subdirs := 0
			for _, e := range util.ReadDirents(t, path, 32<<10) {
				if e.Name != "." && e.Name != ".." && e.Type == unix.DT_DIR {
					subdirs++
				}
			}
			assert.EqualValues(subdirs+2, st.Nlink, "%s: st_nlink should be 2 + subdirectory count", rel)
		}
	})

	t.Run("blocks account for data", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		var empty, big unix.Stat_t
		assert.NoError(unix.Stat(image.at("files/empty"), &empty))
		assert.NoError(unix.Stat(image.at("files/large_256k"), &big))
		assert.Zero(empty.Blocks, "an empty file should not report allocated blocks")
		assert.GreaterOrEqual(big.Blocks*512, big.Size/2, "st_blocks is implausibly small for a %d byte file", big.Size)
	})
}

// testReadPaths covers the read syscalls at the edges where chunk stitching
// goes wrong: past EOF, across block boundaries, vectored and O_DIRECT.
func testReadPaths(t *testing.T, image *mountedImage) {
	t.Run("read past EOF", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		fd, err := unix.Open(image.at("files/tiny_2b"), unix.O_RDONLY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(fd) }()

		buf := make([]byte, 16)
		n, err := unix.Pread(fd, buf, 2)
		assert.NoError(err)
		assert.Zero(n, "reading at EOF should return 0 bytes")

		n, err = unix.Pread(fd, buf, 1<<20)
		assert.NoError(err)
		assert.Zero(n, "reading far past EOF should return 0 bytes")
	})

	t.Run("empty file", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		data, err := os.ReadFile(image.at("files/empty"))
		assert.NoError(err)
		assert.Empty(data)
	})

	t.Run("sparse hole reads zero", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		want, err := os.ReadFile(filepath.Join(image.source, "files/sparse_hole"))
		assert.NoError(err)
		got, err := os.ReadFile(image.at("files/sparse_hole"))
		assert.NoError(err)
		util.CheckBytesEqual(t, want, got, "sparse file content")
	})

	t.Run("unaligned cross boundary reads", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		rel := "files/ten_blocks"
		want, err := os.ReadFile(filepath.Join(image.source, rel))
		assert.NoError(err)
		fd, err := unix.Open(image.at(rel), unix.O_RDONLY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(fd) }()

		// Straddle every 4KiB block boundary with lengths that are not powers
		// of two, which is where chunk stitching tends to go wrong.
		for _, off := range []int64{0, 1, 4095, 4096, 4097, 8191, 8192, 12287, 20479} {
			for _, length := range []int{1, 3, 4095, 4096, 4097, 8193} {
				if off >= int64(len(want)) {
					continue
				}

				end := min(off+int64(length), int64(len(want)))
				buf := make([]byte, length)
				n, err := unix.Pread(fd, buf, off)
				if !assert.NoError(err, "pread(off=%d len=%d)", off, length) {
					return
				}
				assert.Equal(int(end-off), n, "pread(off=%d len=%d) short read", off, length)
				util.CheckBytesEqual(t, want[off:end], buf[:n], fmt.Sprintf("pread(off=%d len=%d)", off, length))
			}
		}
	})

	t.Run("preadv", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		rel := "files/two_blocks"
		want, err := os.ReadFile(filepath.Join(image.source, rel))
		assert.NoError(err)
		fd, err := unix.Open(image.at(rel), unix.O_RDONLY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(fd) }()

		first := make([]byte, 100)
		second := make([]byte, 4000)
		n, err := unix.Preadv(fd, [][]byte{first, second}, 4090)
		assert.NoError(err)
		assert.Equal(len(first)+len(second), n)
		util.CheckBytesEqual(t, want[4090:4090+100], first, "preadv first iovec")
		util.CheckBytesEqual(t, want[4190:4190+4000], second, "preadv second iovec")
	})

	t.Run("direct IO", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		rel := "files/two_blocks"
		want, err := os.ReadFile(filepath.Join(image.source, rel))
		assert.NoError(err)

		fd, err := unix.Open(image.at(rel), unix.O_RDONLY|unix.O_DIRECT, 0)
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP) {
			t.Skip("O_DIRECT not supported")
		}
		assert.NoError(err)
		defer func() { _ = unix.Close(fd) }()

		buf := util.PageAlignedBuffer(8192)
		n, err := unix.Pread(fd, buf[:4096], 0)
		assert.NoError(err)
		assert.Equal(4096, n)
		util.CheckBytesEqual(t, want[:4096], buf[:4096], "O_DIRECT read")
	})
}

// testMmap checks shared and private mappings of a read-only file, including
// the zero padding of the tail page.
func testMmap(t *testing.T, image *mountedImage) {
	t.Run("shared read matches file", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		rel := "files/ten_blocks"
		want, err := os.ReadFile(filepath.Join(image.source, rel))
		assert.NoError(err)

		data, unmap := util.MmapFile(t, image.at(rel), len(want), unix.PROT_READ, unix.MAP_SHARED)
		defer unmap()
		util.CheckBytesEqual(t, want, data, "MAP_SHARED mapping")
	})

	t.Run("tail page is zero padded", func(t *testing.T) {
		t.Parallel()

		// The file is 4097 bytes, so the bytes between EOF and the end of the
		// last page must read as zero.
		pageSize := os.Getpagesize()
		mapped := ((4097 + pageSize - 1) / pageSize) * pageSize
		data, unmap := util.MmapFile(t, image.at("files/one_over_block"), mapped, unix.PROT_READ, unix.MAP_PRIVATE)
		defer unmap()

		for i := 4097; i < mapped; i++ {
			assert.Zero(t, data[i], "byte %d past EOF is not zero", i)
		}
	})

	t.Run("private write is copy on write", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		rel := "files/exact_block"
		want, err := os.ReadFile(filepath.Join(image.source, rel))
		assert.NoError(err)

		data, unmap := util.MmapFile(t, image.at(rel), len(want), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
		data[0] ^= 0xff
		assert.NotEqual(want[0], data[0], "MAP_PRIVATE mapping should be writable")
		unmap()

		// The private modification must not have reached the filesystem.
		after, err := os.ReadFile(image.at(rel))
		assert.NoError(err)
		util.CheckBytesEqual(t, want, after, "file after a MAP_PRIVATE write")
	})

	t.Run("shared write mapping rejected", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		// A shared writable mapping needs a descriptor open for writing, and
		// a read-only mount only ever hands out read-only ones.
		fd, err := unix.Open(image.at("files/exact_block"), unix.O_RDONLY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(fd) }()

		_, err = unix.Mmap(fd, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		assert.ErrorIs(err, unix.EACCES)
	})
}

// testSeek checks lseek against every whence, including SEEK_DATA and
// SEEK_HOLE at EOF.
func testSeek(t *testing.T, image *mountedImage) {
	rel := "files/ten_blocks"
	size := int64(4096 * 10)

	t.Run("set cur end", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		fd, err := unix.Open(image.at(rel), unix.O_RDONLY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(fd) }()

		pos, err := unix.Seek(fd, 0, unix.SEEK_END)
		assert.NoError(err)
		assert.Equal(size, pos)

		pos, err = unix.Seek(fd, -4096, unix.SEEK_CUR)
		assert.NoError(err)
		assert.Equal(size-4096, pos)

		pos, err = unix.Seek(fd, 4096, unix.SEEK_SET)
		assert.NoError(err)
		assert.Equal(int64(4096), pos)
	})

	t.Run("negative offset rejected", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		fd, err := unix.Open(image.at(rel), unix.O_RDONLY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(fd) }()

		_, err = unix.Seek(fd, -1, unix.SEEK_SET)
		assert.ErrorIs(err, unix.EINVAL)
	})

	t.Run("data hole", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		fd, err := unix.Open(image.at(rel), unix.O_RDONLY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(fd) }()

		pos, err := unix.Seek(fd, 0, unix.SEEK_DATA)
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
			t.Skip("SEEK_DATA not supported")
		}
		assert.NoError(err)
		assert.GreaterOrEqual(pos, int64(0))

		// SEEK_HOLE past the last byte of data always lands at EOF.
		pos, err = unix.Seek(fd, size-1, unix.SEEK_HOLE)
		assert.NoError(err)
		assert.Equal(size, pos)

		// Seeking beyond EOF is defined to fail with ENXIO for both whences.
		_, err = unix.Seek(fd, size, unix.SEEK_DATA)
		assert.ErrorIs(err, unix.ENXIO)
		_, err = unix.Seek(fd, size, unix.SEEK_HOLE)
		assert.ErrorIs(err, unix.ENXIO)
	})
}

// testSpliceSendfile checks the zero-copy paths, sendfile and splice, out of a
// read-only file.
func testSpliceSendfile(t *testing.T, image *mountedImage) {
	rel := "files/two_blocks"
	want, err := os.ReadFile(filepath.Join(image.source, rel))
	assert.NoError(t, err)

	t.Run("sendfile", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		src, err := unix.Open(image.at(rel), unix.O_RDONLY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(src) }()
		dst, err := os.CreateTemp(t.TempDir(), "sendfile")
		assert.NoError(err)
		defer func() { _ = dst.Close() }()

		var offset int64
		n, err := unix.Sendfile(int(dst.Fd()), src, &offset, len(want))
		assert.NoError(err)
		assert.Equal(len(want), n)

		got, err := os.ReadFile(dst.Name())
		assert.NoError(err)
		util.CheckBytesEqual(t, want, got, "sendfile output")
	})

	t.Run("splice", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		src, err := unix.Open(image.at(rel), unix.O_RDONLY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(src) }()
		var pipeFds [2]int
		assert.NoError(unix.Pipe(pipeFds[:]))
		defer func() { _ = unix.Close(pipeFds[0]) }()
		defer func() { _ = unix.Close(pipeFds[1]) }()

		var offset int64
		n, err := unix.Splice(src, &offset, pipeFds[1], nil, 4096, 0)
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) {
			t.Skip("splice not supported")
		}
		if !assert.NoError(err) {
			return
		}
		assert.Positive(n)

		buf := make([]byte, n)
		read, err := unix.Read(pipeFds[0], buf)
		if !assert.NoError(err) {
			return
		}
		util.CheckBytesEqual(t, want[:read], buf[:read], "spliced bytes")
	})
}

// testPathResolution checks symlink targets and the errors lookup must return
// for dangling links, non-directories, overlong and missing names.
func testPathResolution(t *testing.T, image *mountedImage) {
	t.Run("readlink targets", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		for rel, want := range map[string]string{
			"symlinks/link_to_file":  "target_file",
			"symlinks/link_to_dir":   "target_dir",
			"symlinks/relative_link": "../files/tiny_2b",
			"symlinks/dangling":      "nonexistent_target",
			"symlinks/chain_a":       "chain_b",
			"symlinks/chain_b":       "chain_c",
		} {
			got, err := os.Readlink(image.at(rel))
			assert.NoError(err, "readlink %s", rel)
			assert.Equal(want, got, "%s", rel)
		}
	})

	t.Run("chain resolves", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		data, err := os.ReadFile(image.at("symlinks/chain_a"))
		assert.NoError(err)
		assert.Equal("chain_end", string(data))
	})

	t.Run("dangling symlink", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		var st unix.Stat_t
		assert.NoError(unix.Lstat(image.at("symlinks/dangling"), &st), "lstat must succeed")
		assert.ErrorIs(unix.Stat(image.at("symlinks/dangling"), &st), unix.ENOENT)
	})

	t.Run("no follow", func(t *testing.T) {
		t.Parallel()
		assert.ErrorIs(t, util.TryOpen(image.at("symlinks/link_to_file"), unix.O_RDONLY|unix.O_NOFOLLOW, 0), unix.ELOOP)
	})

	t.Run("not a directory", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		assert.ErrorIs(t, unix.Stat(image.at("files/tiny_2b/child"), &st), unix.ENOTDIR)
	})

	t.Run("name too long", func(t *testing.T) {
		t.Parallel()

		// The kernel FUSE layer only rejects names above FUSE_NAME_MAX (1024),
		// so advertising f_namelen=255 obliges lookup to enforce NAME_MAX too.
		var st unix.Stat_t
		assert.ErrorIs(t, unix.Lstat(image.at("files/"+corpus.LongName('z', 300)), &st), unix.ENAMETOOLONG)
	})

	t.Run("max length name resolves", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		assert.NoError(t, unix.Lstat(image.at("names/"+corpus.LongName('a', 250)), &st))
	})

	t.Run("missing entry", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		assert.ErrorIs(t, unix.Lstat(image.at("files/definitely_absent"), &st), unix.ENOENT)
	})
}

// testXattr checks the xattr size probes, buffer errors and the shared-xattr
// spill path of EROFS.
func testXattr(t *testing.T, image *mountedImage) {
	t.Run("size probe", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		size, err := unix.Getxattr(image.at("xattrs/user_long_val"), "user.longval", nil)
		assert.NoError(err)
		assert.Equal(512, size, "a nil buffer must report the value size")
	})

	t.Run("buffer too small", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		_, err := unix.Getxattr(image.at("xattrs/user_long_val"), "user.longval", make([]byte, 8))
		assert.ErrorIs(err, unix.ERANGE)
		_, err = unix.Listxattr(image.at("xattrs/user_huge_ibody"), make([]byte, 4))
		assert.ErrorIs(err, unix.ERANGE)
	})

	t.Run("missing attribute", func(t *testing.T) {
		t.Parallel()
		_, err := unix.Getxattr(image.at("xattrs/user_basic"), "user.absent", make([]byte, 64))
		assert.ErrorIs(t, err, unix.ENODATA)
	})

	t.Run("empty value", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		size, err := unix.Getxattr(image.at("xattrs/user_empty_val"), "user.empty", nil)
		assert.NoError(err)
		assert.Zero(size)
	})

	t.Run("privileged namespaces", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		assert.Equal([]byte("trusted_value"), util.GetXattr(t, image.at("xattrs/trusted_attr"), "trusted.test"))
		assert.Equal([]byte("sec_value"), util.GetXattr(t, image.at("xattrs/security_attr"), "security.test"))
	})

	t.Run("inline body overflow", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		// Three ~900 byte values do not fit in the inline xattr body of an
		// EROFS inode, so this exercises the shared-xattr spill path.
		path := image.at("xattrs/user_huge_ibody")
		assert.Len(util.ListXattr(t, path), 3)
		for i := range 3 {
			assert.Len(util.GetXattr(t, path, fmt.Sprintf("user.large_%02d", i)), 900)
		}
	})
}

// testStatfs checks the filesystem-wide values statfs advertises.
func testStatfs(t *testing.T, image *mountedImage) {
	assert := assert.New(t)

	var st unix.Statfs_t
	assert.NoError(unix.Statfs(image.mountpoint, &st))
	assert.EqualValues(unix.FUSE_SUPER_MAGIC, st.Type, "f_type should be FUSE_SUPER_MAGIC")
	assert.Positive(st.Bsize, "f_bsize must be positive")
	assert.EqualValues(255, st.Namelen, "f_namelen should be NAME_MAX")

	// Nothing can ever be written here, so there is no free space to report.
	assert.Zero(st.Bavail, "a read-only filesystem must report no available blocks")
}

// testOpenFlags checks the open flags and *at variants a read-only mount still
// has to honour.
func testOpenFlags(t *testing.T, image *mountedImage) {
	t.Run("O_DIRECTORY on file", func(t *testing.T) {
		t.Parallel()
		assert.ErrorIs(t, util.TryOpen(image.at("files/tiny_2b"), unix.O_RDONLY|unix.O_DIRECTORY, 0), unix.ENOTDIR)
	})

	t.Run("O_DIRECTORY on dir", func(t *testing.T) {
		t.Parallel()
		assert.NoError(t, util.TryOpen(image.at("dirs"), unix.O_RDONLY|unix.O_DIRECTORY, 0))
	})

	t.Run("O_PATH", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		fd, err := unix.Open(image.at("special/fifo"), unix.O_PATH|unix.O_NOFOLLOW, 0)
		assert.NoError(err, "O_PATH must work even on a FIFO")
		defer func() { _ = unix.Close(fd) }()

		var st unix.Stat_t
		assert.NoError(unix.Fstat(fd, &st))
		assert.EqualValues(unix.S_IFIFO, st.Mode&unix.S_IFMT)
	})

	t.Run("openat relative", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		dirFd, err := unix.Open(image.at("files"), unix.O_RDONLY|unix.O_DIRECTORY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(dirFd) }()
		fd, err := unix.Openat(dirFd, "tiny_2b", unix.O_RDONLY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(fd) }()

		buf := make([]byte, 2)
		n, err := unix.Read(fd, buf)
		if !assert.NoError(err) {
			return
		}
		assert.Equal("hi", string(buf[:n]))
	})

	t.Run("statx at empty path", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		fd, err := unix.Open(image.at("files/exact_block"), unix.O_RDONLY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(fd) }()

		var stx unix.Statx_t
		err = unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_BASIC_STATS, &stx)
		if errors.Is(err, unix.ENOSYS) {
			t.Skip("statx not available")
		}
		assert.NoError(err)
		assert.EqualValues(4096, stx.Size)
	})

	t.Run("fifo does not block with O_PATH", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		// Opening a FIFO for reading would block; O_PATH resolves it without
		// engaging the pipe semantics, which is what a metadata-only lookup
		// must support.
		fd, err := unix.Open(image.at("special/fifo"), unix.O_PATH, 0)
		assert.NoError(err)
		assert.NoError(unix.Close(fd))
	})
}

// testConcurrency reads and walks the mount from many goroutines at once and
// checks they all agree.
func testConcurrency(t *testing.T, image *mountedImage) {
	rel := "files/large_256k"
	want, err := os.ReadFile(filepath.Join(image.source, rel))
	assert.NoError(t, err)

	t.Run("parallel reads agree", func(t *testing.T) {
		t.Parallel()

		const workers = 16
		var wg sync.WaitGroup
		errs := make([]error, workers)

		for i := range workers {
			wg.Go(func() {
				for round := range 4 {
					got, readErr := os.ReadFile(image.at(rel))
					if readErr != nil {
						errs[i] = readErr
						return
					}
					if !bytes.Equal(want, got) {
						errs[i] = fmt.Errorf("worker %d round %d read different bytes", i, round)
						return
					}
				}
			})
		}
		wg.Wait()

		for _, e := range errs {
			assert.NoError(t, e)
		}
	})

	t.Run("parallel walks", func(t *testing.T) {
		t.Parallel()

		const workers = 8
		var wg sync.WaitGroup
		counts := make([]int, workers)

		for i := range workers {
			wg.Go(func() {
				_ = filepath.WalkDir(image.mountpoint, func(_ string, _ os.DirEntry, err error) error {
					if err != nil {
						return err
					}
					counts[i]++
					return nil
				})
			})
		}
		wg.Wait()

		for i := 1; i < workers; i++ {
			assert.Equal(t, counts[0], counts[i], "concurrent walks saw a different number of entries")
		}
	})
}

// testRemountStability catches non-deterministic metadata: inode numbers are
// derived from the on-disk NID, so they must survive an unmount/remount cycle
// unchanged.
func testRemountStability(t *testing.T, image *mountedImage) {
	assert := assert.New(t)

	before := util.InodeMap(t, image.mountpoint)
	remount := filepath.Join(t.TempDir(), "remount")
	defer util.MountNydusBootstrap(t, nydusBin, image.bootstrap, image.blobDir, "", remount)()
	after := util.InodeMap(t, remount)

	assert.Equal(len(before), len(after), "the remount exposed a different number of paths")
	for rel, ino := range before {
		assert.Equal(ino, after[rel], "%s changed inode number across a remount", rel)
	}
}

// testDirOffset checks the directory offset protocol from fstests'
// src/t_dir_offset2.c: every d_off in a directory is unique, and seeking a
// directory fd to a recorded d_off resumes the stream at the following entry.
// EROFS encodes d_off itself, so a wrong encoding silently breaks any tool that
// resumes a large directory listing.
func testDirOffset(t *testing.T, image *mountedImage) {
	dirs := []string{"dirs/many_entries", "dirs", "dirs/empty_dir"}

	t.Run("offsets unique", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		for _, rel := range dirs {
			fd, err := unix.Open(image.at(rel), unix.O_RDONLY|unix.O_DIRECTORY, 0)
			assert.NoError(err)

			seen := map[int64]string{}
			for _, e := range util.DrainDirents(t, fd, 4096) {
				prev, dup := seen[e.Off]
				assert.False(dup, "%s: %q and %q share d_off %d", rel, prev, e.Name, e.Off)
				seen[e.Off] = e.Name
			}
			assert.NoError(unix.Close(fd))
		}
	})

	t.Run("seek resumes stream", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		for _, rel := range dirs {
			fd, err := unix.Open(image.at(rel), unix.O_RDONLY|unix.O_DIRECTORY, 0)
			assert.NoError(err)

			entries := util.DrainDirents(t, fd, 4096)
			for i := range entries {
				var from int64
				if i > 0 {
					from = entries[i-1].Off
				}
				_, err := unix.Seek(fd, from, unix.SEEK_SET)
				assert.NoError(err, "%s: seek to d_off %d", rel, from)

				next := util.DrainDirents(t, fd, 4096)
				if !assert.NotEmpty(next, "%s: nothing left after d_off %d", rel, from) {
					continue
				}
				assert.Equal(entries[i].Name, next[0].Name, "%s: resuming at d_off %d yielded the wrong entry", rel, from)
				assert.Equal(entries[i].Ino, next[0].Ino, "%s: d_ino changed after seek", rel)
			}
			assert.NoError(unix.Close(fd))
		}
	})

	t.Run("seek is repeatable", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		fd, err := unix.Open(image.at("dirs/many_entries"), unix.O_RDONLY|unix.O_DIRECTORY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(fd) }()

		entries := util.DrainDirents(t, fd, 4096)
		if !assert.Greater(len(entries), 10) {
			return
		}
		mid := entries[len(entries)/2].Off

		var first []util.Dirent
		for i := range 3 {
			_, err := unix.Seek(fd, mid, unix.SEEK_SET)
			assert.NoError(err)
			got := util.DrainDirents(t, fd, 4096)
			if i == 0 {
				first = got
				continue
			}
			assert.Equal(first, got, "re-seeking to the same d_off gave a different tail")
		}
	})

	t.Run("separate handles are independent", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		path := image.at("dirs/many_entries")
		a, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(a) }()
		b, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(b) }()

		buf := make([]byte, 4096)
		n, err := unix.Getdents(a, buf)
		assert.NoError(err)
		assert.Positive(n, "the first read on handle A returned nothing")

		// B has never been read, so it must still start from the beginning.
		full := util.DrainDirents(t, b, 1<<16)
		assert.Contains(util.DirentNames(full), ".", "handle B lost its own position")
	})

	t.Run("rewind by zero", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		fd, err := unix.Open(image.at("dirs/many_entries"), unix.O_RDONLY|unix.O_DIRECTORY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(fd) }()

		want := util.DrainDirents(t, fd, 4096)
		_, err = unix.Seek(fd, 0, unix.SEEK_SET)
		assert.NoError(err)
		assert.Equal(want, util.DrainDirents(t, fd, 4096))
	})
}

// testPermissions drops to an unprivileged uid and checks that the mode, uid and
// gid Nydus reports actually gate access. The mount carries
// `default_permissions`, so this is what proves the attributes reaching the
// kernel are the ones the source tree had.
func testPermissions(t *testing.T, image *mountedImage) {
	if !util.HasMountOption(t, image.mountpoint, "allow_other") {
		t.Skip("the daemon does not mount with allow_other, so no uid but its own can reach the mount")
	}

	openAsUser := func(t *testing.T, path string) error {
		return util.AsUser(t, unprivilegedUID, func() error { return util.TryOpen(path, unix.O_RDONLY, 0) })
	}
	readdirAsUser := func(t *testing.T, path string) error {
		return util.AsUser(t, unprivilegedUID, func() error {
			fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
			if err != nil {
				return err
			}
			defer func() { _ = unix.Close(fd) }()

			_, err = unix.Getdents(fd, make([]byte, 4096))
			return err
		})
	}

	tests := []struct {
		name string
		rel  string
		want error
	}{
		{name: "world readable opens", rel: "perms/other_owner_r"},
		{name: "owner only denied", rel: "perms/other_owner_none", want: unix.EACCES},
		{name: "mode zero denied", rel: "perms/no_perm", want: unix.EACCES},
		{name: "read only file opens", rel: "perms/r_only"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := openAsUser(t, image.at(tc.rel))
			if tc.want == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tc.want)
		})
	}

	t.Run("traverse without list", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		// 0711: reachable by name, but the listing is denied.
		assert.NoError(openAsUser(t, image.at("perms/x_only_dir/hidden")))
		assert.ErrorIs(readdirAsUser(t, image.at("perms/x_only_dir")), unix.EACCES)
	})

	t.Run("list without traverse", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		// 0444: the names are visible but no child can be reached through it.
		assert.NoError(readdirAsUser(t, image.at("perms/r_only_dir")))
		assert.ErrorIs(openAsUser(t, image.at("perms/r_only_dir/listed")), unix.EACCES)
	})

	t.Run("access matches open", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		// access(2) consults the real uid, which setfsuid does not change, so the
		// comparison has to go through faccessat2's AT_EACCESS against the fsuid
		// the kernel actually uses for the lookup.
		assert.NoError(util.AsUser(t, unprivilegedUID, func() error {
			return unix.Faccessat(unix.AT_FDCWD, image.at("perms/other_owner_r"), unix.R_OK, unix.AT_EACCESS)
		}))
		assert.ErrorIs(util.AsUser(t, unprivilegedUID, func() error {
			return unix.Faccessat(unix.AT_FDCWD, image.at("perms/other_owner_none"), unix.R_OK, unix.AT_EACCESS)
		}), unix.EACCES)
	})
}

// testSymlinkLoops covers the shapes generic/005 uses: resolution has to stop
// with ELOOP instead of recursing.
func testSymlinkLoops(t *testing.T, image *mountedImage) {
	for _, rel := range []string{"symlinks/self_loop", "symlinks/loop_a", "symlinks/loop_b"} {
		t.Run(strings.TrimPrefix(rel, "symlinks/"), func(t *testing.T) {
			t.Parallel()
			assert := assert.New(t)

			var st unix.Stat_t
			assert.ErrorIs(unix.Stat(image.at(rel), &st), unix.ELOOP)

			// The link itself is still readable; only following it loops.
			assert.NoError(unix.Lstat(image.at(rel), &st))
			_, err := unix.Readlink(image.at(rel), make([]byte, 256))
			assert.NoError(err)
		})
	}

	t.Run("chain beyond kernel budget", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		// The kernel follows at most 40 links, so the tail of a 50-link chain
		// must fail while a short prefix still resolves.
		var st unix.Stat_t
		assert.ErrorIs(unix.Stat(image.at("symlinks/deep_49"), &st), unix.ELOOP)
		assert.NoError(unix.Stat(image.at("symlinks/deep_05"), &st))
	})

	t.Run("path longer than PATH_MAX", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		long := image.mountpoint + "/" + strings.Repeat("a/", 3000) + "x"
		assert.ErrorIs(t, unix.Stat(long, &st), unix.ENAMETOOLONG)
	})

	t.Run("parent of subdirectory is root", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		var root, parent, b unix.Stat_t
		assert.NoError(unix.Stat(image.mountpoint, &root))
		assert.NoError(unix.Stat(image.at("dirs/a/b/.."), &parent))
		assert.NoError(unix.Stat(image.at("dirs/a"), &b))
		assert.Equal(b.Ino, parent.Ino, "dirs/a/b/.. should be dirs/a")

		assert.NoError(unix.Stat(image.at("dirs/.."), &parent))
		assert.Equal(root.Ino, parent.Ino, "dirs/.. should be the filesystem root")
	})
}

// testSparseMap walks every sparse file with SEEK_DATA and SEEK_HOLE and checks
// the invariants POSIX requires, without assuming a particular hole
// granularity: a chunked image will not report the same extents the staging
// filesystem does.
func testSparseMap(t *testing.T, image *mountedImage) {
	// Only files with at least one hole are interesting, and only ones small
	// enough to scan exhaustively.
	var sparseFiles []string
	assert.NoError(t, filepath.WalkDir(image.source, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}

		info, err := d.Info()
		assert.NoError(t, err)
		if info.Size() > 0 && info.Size() <= util.MaxFullCompareSize &&
			util.AllocatedBytes(t, path) < info.Size() {
			rel, err := filepath.Rel(image.source, path)
			assert.NoError(t, err)
			sparseFiles = append(sparseFiles, rel)
		}
		return nil
	}))
	assert.NotEmpty(t, sparseFiles, "the corpus has no sparse files to map")

	t.Run("extents are well formed", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		for _, rel := range sparseFiles {
			fd, err := unix.Open(image.at(rel), unix.O_RDONLY, 0)
			assert.NoError(err)
			var st unix.Stat_t
			assert.NoError(unix.Fstat(fd, &st))
			size := st.Size

			// Alternate DATA and HOLE from 0; every step must advance, stay
			// within the file, and terminate.
			pos := int64(0)
			steps := 0
			for pos < size {
				steps++
				assert.Less(steps, 1<<16, "%s: extent walk did not terminate", rel)

				data, err := unix.Seek(fd, pos, unix.SEEK_DATA)
				if errors.Is(err, unix.ENXIO) {
					break
				}
				assert.NoError(err, "%s: SEEK_DATA at %d", rel, pos)
				assert.Less(data, size, "%s: SEEK_DATA past EOF", rel)
				if !assert.GreaterOrEqual(data, pos, "%s: SEEK_DATA went backwards", rel) {
					break
				}

				hole, err := unix.Seek(fd, data, unix.SEEK_HOLE)
				assert.NoError(err, "%s: SEEK_HOLE at %d", rel, data)
				assert.LessOrEqual(hole, size, "%s: SEEK_HOLE past EOF", rel)
				if !assert.Greater(hole, data, "%s: SEEK_HOLE did not advance", rel) {
					break
				}
				pos = hole
			}
			assert.NoError(unix.Close(fd))
		}
	})

	t.Run("holes read zero", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		for _, rel := range sparseFiles {
			fd, err := unix.Open(image.at(rel), unix.O_RDONLY, 0)
			assert.NoError(err)
			var st unix.Stat_t
			assert.NoError(unix.Fstat(fd, &st))

			pos := int64(0)
			for pos < st.Size {
				hole, err := unix.Seek(fd, pos, unix.SEEK_HOLE)
				if !assert.NoError(err) || hole >= st.Size {
					break
				}

				next, err := unix.Seek(fd, hole, unix.SEEK_DATA)
				if errors.Is(err, unix.ENXIO) {
					next = st.Size
				} else if !assert.NoError(err) {
					break
				}

				n := min(next-hole, 1<<20)
				buf := make([]byte, n)
				_, err = unix.Pread(fd, buf, hole)
				assert.NoError(err)
				assert.Equal(make([]byte, n), buf, "%s: bytes %d..%d are reported as a hole but are not zero", rel, hole, hole+n)
				pos = next
			}
			assert.NoError(unix.Close(fd))
		}
	})

	t.Run("empty file has no data", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		fd, err := unix.Open(image.at("files/empty"), unix.O_RDONLY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(fd) }()

		_, err = unix.Seek(fd, 0, unix.SEEK_DATA)
		assert.ErrorIs(err, unix.ENXIO)
		_, err = unix.Seek(fd, 0, unix.SEEK_HOLE)
		assert.ErrorIs(err, unix.ENXIO)
	})
}

// testStability covers behaviour that has to hold because the mount can never
// change: timestamps do not move, and repeated queries agree.
func testStability(t *testing.T, image *mountedImage) {
	t.Run("read does not advance atime", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		path := image.at("files/small_100b")
		var before unix.Stat_t
		assert.NoError(unix.Stat(path, &before))

		data, err := os.ReadFile(path)
		assert.NoError(err)
		assert.NotEmpty(data)

		var after unix.Stat_t
		assert.NoError(unix.Stat(path, &after))
		assert.Equal(before.Atim, after.Atim, "a read-only mount must not advance atime")
		assert.Equal(before.Mtim, after.Mtim)
		assert.Equal(before.Ctim, after.Ctim)
	})

	t.Run("readdir does not advance atime", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		path := image.at("dirs/many_entries")
		var before, after unix.Stat_t
		assert.NoError(unix.Stat(path, &before))

		_, err := os.ReadDir(path)
		assert.NoError(err)
		assert.NoError(unix.Stat(path, &after))
		assert.Equal(before.Atim, after.Atim)
	})

	t.Run("statx reports no birth time", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		var stx unix.Statx_t
		assert.NoError(unix.Statx(unix.AT_FDCWD, image.at("files/small_100b"), 0, unix.STATX_ALL, &stx))

		// EROFS stores no creation time, so the mask must not claim one.
		assert.Zero(stx.Mask&unix.STATX_BTIME, "btime reported but EROFS has none")
		assert.NotZero(stx.Mask & unix.STATX_MTIME)
		assert.NotZero(stx.Mask & unix.STATX_INO)
	})

	t.Run("statx no follow sees the link", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		rel := "symlinks/link_to_file"
		target, err := os.Readlink(image.at(rel))
		assert.NoError(err)

		var stx unix.Statx_t
		assert.NoError(unix.Statx(unix.AT_FDCWD, image.at(rel), unix.AT_SYMLINK_NOFOLLOW, unix.STATX_ALL, &stx))
		assert.EqualValues(unix.S_IFLNK, stx.Mode&unix.S_IFMT)
		assert.EqualValues(len(target), stx.Size, "a symlink's size is its target length")
	})
}

// testLocksAndCopy covers the syscalls container workloads reach for that are
// neither plain reads nor writes.
func testLocksAndCopy(t *testing.T, image *mountedImage) {
	t.Run("shared flock succeeds", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		fd, err := unix.Open(image.at("files/small_100b"), unix.O_RDONLY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(fd) }()

		assert.NoError(unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB))
		assert.NoError(unix.Flock(fd, unix.LOCK_UN))
	})

	t.Run("read lock succeeds", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		fd, err := unix.Open(image.at("files/small_100b"), unix.O_RDONLY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(fd) }()

		lock := unix.Flock_t{Type: unix.F_RDLCK, Whence: unix.SEEK_SET}
		assert.NoError(unix.FcntlFlock(uintptr(fd), unix.F_SETLK, &lock))

		probe := unix.Flock_t{Type: unix.F_RDLCK, Whence: unix.SEEK_SET}
		assert.NoError(unix.FcntlFlock(uintptr(fd), unix.F_GETLK, &probe))
		assert.EqualValues(unix.F_UNLCK, probe.Type, "an unheld range should read back unlocked")
	})

	t.Run("copy_file_range reads source", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		src, err := unix.Open(image.at("files/small_100b"), unix.O_RDONLY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(src) }()
		dstPath := filepath.Join(t.TempDir(), "copy")
		dst, err := unix.Open(dstPath, unix.O_RDWR|unix.O_CREAT, 0o600)
		assert.NoError(err)
		defer func() { _ = unix.Close(dst) }()
		want, err := os.ReadFile(image.at("files/small_100b"))
		assert.NoError(err)

		n, err := unix.CopyFileRange(src, nil, dst, nil, len(want), 0)
		if errors.Is(err, unix.EXDEV) || errors.Is(err, unix.EOPNOTSUPP) {
			t.Skip("copy_file_range is not offered across these filesystems")
		}
		assert.NoError(err)
		assert.Equal(len(want), n)

		got, err := os.ReadFile(dstPath)
		assert.NoError(err)
		assert.Equal(want, got)
	})

	t.Run("fsync on read only file succeeds", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		fd, err := unix.Open(image.at("files/small_100b"), unix.O_RDONLY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(fd) }()

		// Nothing is dirty, so this must be a no-op rather than an error.
		assert.NoError(unix.Fsync(fd))
	})

	t.Run("fallocate rejected", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		fd, err := unix.Open(image.at("files/small_100b"), unix.O_RDONLY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(fd) }()

		assert.Error(unix.Fallocate(fd, 0, 0, 4096), "fallocate succeeded on a read-only mount")
	})
}

// testFaultIn reads into a destination buffer that is itself an mmap of a file on
// the same mount. Servicing the read then has to fault that page in, which
// issues a second request while the first is still in flight. A filesystem that
// serialises the two deadlocks, so every case here also serves as a hang
// detector.
func testFaultIn(t *testing.T, image *mountedImage) {
	file := image.at("files/ten_blocks")
	backing := image.at("files/large_256k")
	want, err := os.ReadFile(file)
	assert.NoError(t, err)

	// mapPrivate maps the first size bytes of path privately, as the read
	// destination. It runs off the test goroutine, so it reports failure
	// instead of asserting.
	mapPrivate := func(path string, size int) ([]byte, error) {
		fd, err := unix.Open(path, unix.O_RDONLY, 0)
		if err != nil {
			return nil, err
		}
		defer func() { _ = unix.Close(fd) }()

		return unix.Mmap(fd, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
	}

	tests := []struct {
		name     string
		flags    int
		mapped   string
		vectored bool
	}{
		{name: "read into mapped buffer", mapped: backing},
		{name: "readv into mapped buffers", mapped: backing, vectored: true},
		// O_DIRECT needs an aligned buffer, and an mmap is page aligned.
		{name: "direct read into mapped buffer", flags: unix.O_DIRECT, mapped: backing},
		// The tightest case: source and destination are the same file, so the
		// fault lands on a page the read is already serving.
		{name: "mapped buffer backed by the same file", mapped: file},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert := assert.New(t)

			fd, err := unix.Open(file, unix.O_RDONLY|tc.flags, 0)
			if tc.flags&unix.O_DIRECT != 0 && errors.Is(err, unix.EINVAL) {
				t.Skip("O_DIRECT is not offered here")
			}
			if !assert.NoError(err) {
				return
			}
			defer func() { _ = unix.Close(fd) }()

			// The read runs under a watchdog: a deadlock shows up as a test
			// that never returns, which would otherwise just stall CI. The
			// goroutine only reports over the channel and never touches t,
			// which the timeout may already have ended.
			var got []byte
			done := make(chan error, 1)
			go func() {
				done <- func() error {
					buf, err := mapPrivate(tc.mapped, len(want))
					if err != nil {
						return err
					}
					defer func() { _ = unix.Munmap(buf) }()

					var n int
					if tc.vectored {
						half := len(want) / 2
						n, err = unix.Preadv(fd, [][]byte{buf[:half], buf[half:]}, 0)
					} else {
						n, err = unix.Pread(fd, buf, 0)
					}
					if err != nil {
						return err
					}
					got = bytes.Clone(buf[:n])

					return nil
				}()
			}()

			select {
			case err := <-done:
				if !assert.NoError(err) {
					return
				}
				util.CheckBytesEqual(t, want, got, tc.name)
			case <-time.After(30 * time.Second):
				t.Fatal("timed out; the read most likely deadlocked faulting in its own buffer")
			}
		})
	}
}

// testProcessView covers the syscalls a process uses to locate itself, which
// depend on the parent chain and on dentry names being reported correctly.
func testProcessView(t *testing.T, image *mountedImage) {
	t.Run("getcwd inside mount", func(t *testing.T) {
		assert := assert.New(t)

		// Not parallel: it changes the process working directory. cwdMu
		// additionally serializes it against the same subtest in other
		// parallel build configs.
		cwdMu.Lock()
		defer cwdMu.Unlock()

		rel := "dirs/a/b/c"
		saved, err := os.Getwd()
		assert.NoError(err)
		defer func() { _ = os.Chdir(saved) }()

		assert.NoError(os.Chdir(image.at(rel)))
		cwd, err := os.Getwd()
		assert.NoError(err, "getcwd failed inside the mount")
		assert.Equal(image.at(rel), cwd)

		assert.NoError(os.Chdir(".."))
		cwd, err = os.Getwd()
		assert.NoError(err)
		assert.Equal(image.at("dirs/a/b"), cwd)
	})

	t.Run("proc fd resolves to path", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		path := image.at("files/small_100b")
		fd, err := unix.Open(path, unix.O_RDONLY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(fd) }()

		target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
		assert.NoError(err)
		assert.Equal(path, target, "/proc/self/fd should name the open file")
	})

	t.Run("file handle either works or is refused", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		// A filesystem with no export support must say so rather than hand back
		// a handle it cannot resolve.
		handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, image.at("files/small_100b"), 0)
		if err != nil {
			assert.True(errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP) ||
				errors.Is(err, unix.EPERM) || errors.Is(err, unix.EINVAL),
				"name_to_handle_at failed with an unexpected error: %v", err)
			return
		}

		mountFd, err := unix.Open(image.mountpoint, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(mountFd) }()
		fd, err := unix.OpenByHandleAt(mountFd, handle, unix.O_RDONLY)
		if err != nil {
			assert.True(errors.Is(err, unix.ESTALE) || errors.Is(err, unix.EOPNOTSUPP),
				"a handed-out handle failed to reopen: %v", err)
			return
		}
		defer func() { _ = unix.Close(fd) }()

		var viaHandle, viaPath unix.Stat_t
		assert.NoError(unix.Fstat(fd, &viaHandle))
		assert.NoError(unix.Stat(image.at("files/small_100b"), &viaPath))
		assert.Equal(viaPath.Ino, viaHandle.Ino)
	})

	t.Run("open file description locks", func(t *testing.T) {
		t.Parallel()
		assert := assert.New(t)

		// OFD locks are what modern SQLite and systemd use; a read lock must be
		// available even though nothing can ever be written.
		fd, err := unix.Open(image.at("files/small_100b"), unix.O_RDONLY, 0)
		assert.NoError(err)
		defer func() { _ = unix.Close(fd) }()

		lock := unix.Flock_t{Type: unix.F_RDLCK, Whence: unix.SEEK_SET, Len: 0}
		err = unix.FcntlFlock(uintptr(fd), unix.F_OFD_SETLK, &lock)
		if errors.Is(err, unix.EINVAL) {
			t.Skip("OFD locks are not offered here")
		}
		assert.NoError(err)

		probe := unix.Flock_t{Type: unix.F_RDLCK, Whence: unix.SEEK_SET, Len: 0}
		assert.NoError(unix.FcntlFlock(uintptr(fd), unix.F_OFD_GETLK, &probe))
		assert.EqualValues(unix.F_UNLCK, probe.Type)
	})
}

// TestAutomaticNoXattr checks that the removed --no-xattr option is gone from
// `nydus fuse` and that xattr support is decided per image, with the removed
// NYDUS_FUSE_NO_XATTR override set to prove it has no effect: a mount of an
// image without xattrs answers EOPNOTSUPP, one with xattrs serves them and
// hides the internal trusted.nydus.no_xattr marker.
func TestAutomaticNoXattr(t *testing.T) {
	util.SkipUnlessRoot(t, "FUSE and trusted xattr fixtures")

	t.Run("removed option", func(t *testing.T) {
		assert := assert.New(t)

		output, err := exec.Command(nydusBin, "fuse", "--mountpoint", t.TempDir(), "--no-xattr").CombinedOutput()
		assert.Error(err)
		assert.Contains(string(output), "unexpected argument '--no-xattr'")

		output, err = exec.Command(nydusBin, "fuse", "--help").CombinedOutput()
		assert.NoError(err)
		assert.NotContains(string(output), "--no-xattr")
		assert.NotContains(string(output), "NYDUS_FUSE_NO_XATTR")
	})

	tests := []struct {
		name  string
		path  string
		key   string
		value []byte
	}{
		{name: "no xattr"},
		{name: "file xattr", path: "file", key: "user.test", value: []byte("value")},
		{name: "empty value", path: "file", key: "user.empty", value: []byte{}},
		{name: "root xattr", path: ".", key: "user.root", value: []byte("root")},
		{name: "directory xattr", path: "nested", key: "user.dir", value: []byte("directory")},
		{name: "internal name on non-root", path: "file", key: "trusted.nydus.no_xattr", value: []byte("1")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// The removed override must not change what the mount serves.
			t.Setenv("NYDUS_FUSE_NO_XATTR", "true")

			// Stage the source tree with the case's xattr and a stale
			// internal marker the builder must not carry over.
			root := t.TempDir()
			source := filepath.Join(root, "source")
			assert.NoError(t, os.MkdirAll(filepath.Join(source, "nested"), 0o755))
			assert.NoError(t, os.WriteFile(filepath.Join(source, "file"), []byte("payload"), 0o644))
			if tc.key != "" {
				assert.NoError(t, unix.Setxattr(filepath.Join(source, tc.path), tc.key, tc.value, 0))
			}
			assert.NoError(t, unix.Setxattr(source, "trusted.nydus.no_xattr", []byte("stale"), 0))

			// Build the image.
			blobDir := filepath.Join(root, "blobs")
			bootstrap := filepath.Join(root, "bootstrap")
			blob := util.BuildImage(t, nydusBin, bootstrap, blobDir, source, 1<<20)
			if blob == "" {
				return
			}

			for _, layout := range []string{"blob", "bootstrap"} {
				t.Run(layout, func(t *testing.T) {
					assert := assert.New(t)

					mountpoint := filepath.Join(root, "mnt-"+layout)
					if layout == "blob" {
						t.Cleanup(util.MountNydusBlob(t, nydusBin, blob, mountpoint))
					} else {
						t.Cleanup(util.MountNydusBootstrap(t, nydusBin, bootstrap, blobDir, "", mountpoint))
					}

					data, err := os.ReadFile(filepath.Join(mountpoint, "file"))
					assert.NoError(err)
					assert.Equal([]byte("payload"), data)

					// Query twice: the second round must agree with the first.
					for range 2 {
						if tc.key == "" {
							_, err = unix.Getxattr(filepath.Join(mountpoint, "file"), "user.absent", nil)
							assert.ErrorIs(err, unix.EOPNOTSUPP)
							_, err = unix.Listxattr(mountpoint, nil)
							assert.ErrorIs(err, unix.EOPNOTSUPP)
							continue
						}

						assert.Equal(tc.value, util.GetXattr(t, filepath.Join(mountpoint, tc.path), tc.key))
						assert.Contains(util.ListXattr(t, filepath.Join(mountpoint, tc.path)), tc.key)
						_, err = unix.Getxattr(mountpoint, "trusted.nydus.no_xattr", nil)
						assert.ErrorIs(err, unix.ENODATA)
						assert.NotContains(util.ListXattr(t, mountpoint), "trusted.nydus.no_xattr")
					}
				})
			}
		})
	}
}
