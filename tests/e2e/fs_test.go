package e2e

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/dragonflyoss/nydus/tests/e2e/corpus"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Read-only and FUSE conformance suite.
//
// fstests cannot cover this ground: its generic tests assume a writable
// filesystem, so everything that matters for NydusFS (write rejection, dirent
// encoding, inode identity, mmap/splice on a read-only mount) either lives in
// the excluded set or does not exist upstream. These cases run against a single
// mount per build configuration and execute in parallel, which keeps the whole
// suite in the low seconds even though it covers far more syscalls than the
// fstests subset does.

const fuseSuperMagic = 0x65735546

// TestFilesystemSemantics mounts a NydusFS image per build configuration and
// asserts POSIX behaviour that a read-only FUSE filesystem must get right.
func TestFilesystemSemantics(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to build the corpus (device nodes, chown)")
	}

	nydusBin := mustLookupExecutable(t, "nydus")
	root := t.TempDir()
	// Both the directory testing hands out and the one above it are 0700, which
	// stops the permission suite's unprivileged uid from reaching the mount.
	require.NoError(t, os.Chmod(root, 0o755))
	require.NoError(t, os.Chmod(filepath.Dir(root), 0o755))

	// Two corpora rather than one: the standard tree enumerates the cases a
	// human thinks of, the stress tree goes after the shapes that only appear
	// at volume (hundreds of sparse and special files, 255-byte names,
	// directories spanning several EROFS blocks).
	corpora := map[string]string{
		"standard": filepath.Join(root, "corpus-standard"),
		"stress":   filepath.Join(root, "corpus-stress"),
	}
	corpus.MakeStandardCorpus(t, corpora["standard"])
	corpus.MakeStressCorpus(t, corpora["stress"], readOnlyCorpusSeed)

	for _, cfg := range fsBuildConfigs {
		for corpusName, corpus := range corpora {
			t.Run(cfg.ID+"/"+corpusName, func(t *testing.T) {
				t.Parallel()

				cfgRoot := filepath.Join(root, cfg.ID+"-"+corpusName)
				require.NoError(t, os.MkdirAll(cfgRoot, 0o755))
				img := fsBuildImage(t, nydusBin, cfg, cfgRoot, "ro", corpus)

				mnt := filepath.Join(cfgRoot, "mnt")
				cleanup := mountNydusBootstrap(t, nydusBin, img.Bootstrap, img.BlobDir, mnt)
				t.Cleanup(cleanup)

				fs := &roFixture{src: corpus, mnt: mnt, nydusBin: nydusBin, img: img}
				for name, run := range roSuites() {
					t.Run(name, func(t *testing.T) {
						t.Parallel()
						run(t, fs)
					})
				}
			})
		}
	}
}

// readOnlyCorpusSeed keeps the stress tree reproducible; override it when
// chasing a failure that only a different shape produces.
const readOnlyCorpusSeed = 20260806

// fsBuildConfig is one `nydus build` parameterisation. Image layout is
// what turns a builder bug into a runtime bug, so the same test list is run
// against several encodings rather than a single canonical one.
//
// Blobs are always written with --blob-dir. `nydus fuse` rejects --bootstrap
// together with --blob, and resolves --blob-dir entries by the sha256 name
// that only --blob-dir produces, so a bootstrap-backed mount has no other
// option.
type fsBuildConfig struct {
	ID             string
	ChunkSize      int
	BlockGroupSize int // 0 keeps the nydus default
	Compressor     string
}

// fsBuildConfigs deliberately picks the extremes of each dimension: the
// smallest legal chunk size against the built-in default, and uncompressed
// output against zstd.
var fsBuildConfigs = []fsBuildConfig{
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
		ID:             "chunk4m-none-tightgroup",
		ChunkSize:      4 << 20,
		BlockGroupSize: 4 << 20,
		Compressor:     "none",
	},
}

type fsImage struct {
	Bootstrap string
	BlobDir   string
}

func fsBuildImage(t *testing.T, nydusBin string, cfg fsBuildConfig, cfgRoot, name, corpus string) fsImage {
	t.Helper()

	blobDir := filepath.Join(cfgRoot, name+"-blobs")
	bootstrap := filepath.Join(cfgRoot, name+".bootstrap")
	require.NoError(t, os.MkdirAll(blobDir, 0o755))

	args := []string{
		"build",
		"--chunk-size", strconv.Itoa(cfg.ChunkSize),
		"--compressor", cfg.Compressor,
		"--bootstrap", bootstrap,
		"--blob-dir", blobDir,
	}
	if cfg.BlockGroupSize > 0 {
		args = append(args, "--block-group-size", strconv.Itoa(cfg.BlockGroupSize))
	}
	args = append(args, corpus)

	out, err := exec.Command(nydusBin, args...).CombinedOutput()
	require.NoError(t, err, "nydus build failed for %s/%s: %s", cfg.ID, name, out)

	// The image is EROFS, so erofs-utils validates the encoding independently
	// of the nydus reader: a builder bug the Rust reader happens to tolerate
	// still gets caught here.
	fsckErofsImage(t, bootstrap, blobDir)

	return fsImage{Bootstrap: bootstrap, BlobDir: blobDir}
}

type roFixture struct {
	src      string
	mnt      string
	nydusBin string
	img      fsImage
}

func (f *roFixture) at(rel string) string { return filepath.Join(f.mnt, rel) }

func roSuites() map[string]func(*testing.T, *roFixture) {
	return map[string]func(*testing.T, *roFixture){
		"TreeDifferential": func(t *testing.T, f *roFixture) { roDiffTree(t, f.src, f.mnt, true) },
		"FaultIn":          roFaultIn,
		"ProcessView":      roProcessView,
		"WriteRejection":   roWriteRejection,
		"Dirents":          roDirents,
		"DirOffset":        roDirOffset,
		"InodeIdentity":    roInodeIdentity,
		"Metadata":         roMetadata,
		"ReadPaths":        roReadPaths,
		"SparseMap":        roSparseMap,
		"Mmap":             roMmap,
		"Seek":             roSeek,
		"SpliceSendfile":   roSpliceSendfile,
		"PathResolution":   roPathResolution,
		"SymlinkLoops":     roSymlinkLoops,
		"Xattr":            roXattr,
		"Statfs":           roStatfs,
		"OpenFlags":        roOpenFlags,
		"Permissions":      roPermissions,
		"LocksAndCopy":     roLocksAndCopy,
		"Stability":        roStability,
		"Concurrency":      roConcurrency,
		"RemountStability": roRemountStability,
	}
}

// ---------------------------------------------------------------------------
// Write rejection
// ---------------------------------------------------------------------------

// roWriteRejection asserts that every mutating syscall is refused with EROFS.
// Returning EACCES or EPERM instead would be wrong: the caller is root, so the
// permission checks pass and the read-only nature of the mount is the only
// reason the call cannot proceed.
func roWriteRejection(t *testing.T, f *roFixture) {
	file := f.at("files/small_100b")
	dir := f.at("dirs/empty_dir")
	link := f.at("symlinks/link_to_file")
	fresh := f.at("dirs/empty_dir/created")

	cases := []struct {
		name   string
		op     func() error
		alsoOK []error
	}{
		{name: "OpenWriteOnly", op: func() error { return roOpen(file, unix.O_WRONLY) }},
		{name: "OpenReadWrite", op: func() error { return roOpen(file, unix.O_RDWR) }},
		{name: "OpenAppend", op: func() error { return roOpen(file, unix.O_WRONLY|unix.O_APPEND) }},
		{name: "OpenTruncate", op: func() error { return roOpen(file, unix.O_RDONLY|unix.O_TRUNC) }},
		{name: "OpenCreate", op: func() error { return roOpen(fresh, unix.O_CREAT|unix.O_WRONLY) }},
		{name: "Truncate", op: func() error { return unix.Truncate(file, 0) }},
		{name: "Unlink", op: func() error { return unix.Unlink(file) }},
		{name: "Rmdir", op: func() error { return unix.Rmdir(dir) }},
		{name: "Rename", op: func() error { return unix.Rename(file, fresh) }},
		{name: "Link", op: func() error { return unix.Link(file, fresh) }},
		{name: "Symlink", op: func() error { return unix.Symlink("target", fresh) }},
		{name: "Mkdir", op: func() error { return unix.Mkdir(fresh, 0o755) }},
		{name: "Mknod", op: func() error { return unix.Mknod(fresh, unix.S_IFIFO|0o644, 0) }},
		{name: "Chmod", op: func() error { return unix.Chmod(file, 0o600) }},
		{name: "Chown", op: func() error { return unix.Chown(file, 12345, 12345) }},
		{name: "Lchown", op: func() error { return unix.Lchown(link, 12345, 12345) }},
		{name: "UtimesNano", op: func() error {
			return unix.UtimesNano(file, []unix.Timespec{{Sec: 1}, {Sec: 1}})
		}},
		{name: "Setxattr", op: func() error {
			return unix.Setxattr(file, "user.injected", []byte("x"), 0)
		}},
		{name: "Removexattr", op: func() error {
			return unix.Removexattr(f.at("xattrs/user_basic"), "user.test")
		}},
		{
			name: "OpenTmpfile",
			op:   func() error { return roOpenMode(f.at("dirs"), unix.O_TMPFILE|unix.O_RDWR, 0o600) },
			// O_TMPFILE is optional; a filesystem that never implements it
			// reports EOPNOTSUPP before it ever gets to the read-only check.
			alsoOK: []error{unix.EOPNOTSUPP, unix.EISDIR},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.op()
			require.Error(t, err, "%s unexpectedly succeeded on a read-only mount", tc.name)
			if errors.Is(err, unix.EROFS) {
				return
			}
			for _, ok := range tc.alsoOK {
				if errors.Is(err, ok) {
					return
				}
			}
			t.Fatalf("%s returned %v, want EROFS", tc.name, err)
		})
	}
}

func roOpen(path string, flags int) error { return roOpenMode(path, flags, 0) }

func roOpenMode(path string, flags int, mode uint32) error {
	fd, err := unix.Open(path, flags, mode)
	if err == nil {
		_ = unix.Close(fd)
	}
	return err
}

// ---------------------------------------------------------------------------
// Directory entries
// ---------------------------------------------------------------------------

type roDirent struct {
	Name string
	Ino  uint64
	Type uint8
	Off  int64
}

// roDirents checks the raw getdents64 stream rather than os.ReadDir, because
// the fields os.ReadDir throws away (d_type, d_ino, d_off) are exactly the ones
// the EROFS directory encoder has to get right.
func roDirents(t *testing.T, f *roFixture) {
	t.Run("DotEntries", func(t *testing.T) {
		t.Parallel()
		entries := roReadDirents(t, f.at("dirs/empty_dir"))
		names := roDirentNames(entries)
		require.Contains(t, names, ".")
		require.Contains(t, names, "..")
	})

	t.Run("TypeAndInoMatchStat", func(t *testing.T) {
		t.Parallel()
		for _, dir := range []string{"files", "symlinks", "special", "hardlinks", "names"} {
			entries := roReadDirents(t, f.at(dir))
			for _, e := range entries {
				if e.Name == "." || e.Name == ".." {
					continue
				}
				var st unix.Stat_t
				require.NoError(t, unix.Lstat(filepath.Join(f.at(dir), e.Name), &st))
				require.Equal(t, roExpectedDirentType(st.Mode), e.Type,
					"%s/%s: d_type does not match st_mode", dir, e.Name)
				require.Equal(t, st.Ino, e.Ino, "%s/%s: d_ino does not match st_ino", dir, e.Name)
			}
		}
	})

	t.Run("LargeDirectoryComplete", func(t *testing.T) {
		t.Parallel()
		// 200 entries do not fit in one 4KiB EROFS directory block, so this
		// walks the block-splitting path in the builder.
		entries := roReadDirents(t, f.at("dirs/many_entries"))
		got := map[string]int{}
		for _, e := range entries {
			got[e.Name]++
		}
		delete(got, ".")
		delete(got, "..")
		require.Len(t, got, 200, "wrong number of entries")
		for name, n := range got {
			require.Equal(t, 1, n, "%s appeared %d times", name, n)
		}
		for i := 1; i <= 200; i++ {
			require.Contains(t, got, fmt.Sprintf("file_%04d", i))
		}
	})

	t.Run("SmallBufferYieldsSameSet", func(t *testing.T) {
		t.Parallel()
		// A buffer that only holds a few dirents forces many getdents64 calls
		// and exposes off-by-one errors in the resume offset.
		big := roDirentNames(roReadDirentsBuf(t, f.at("dirs/many_entries"), 64<<10))
		small := roDirentNames(roReadDirentsBuf(t, f.at("dirs/many_entries"), 512))
		sort.Strings(big)
		sort.Strings(small)
		require.Equal(t, big, small)
	})

	t.Run("RewindRepeats", func(t *testing.T) {
		t.Parallel()
		fd, err := unix.Open(f.at("dirs/many_entries"), unix.O_RDONLY|unix.O_DIRECTORY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(fd) }()

		first := roDirentNames(roDrainDirents(t, fd, 1024))
		_, err = unix.Seek(fd, 0, unix.SEEK_SET)
		require.NoError(t, err)
		second := roDirentNames(roDrainDirents(t, fd, 1024))

		sort.Strings(first)
		sort.Strings(second)
		require.Equal(t, first, second, "rewinding the directory changed the entry set")
	})

}

func roExpectedDirentType(mode uint32) uint8 {
	switch mode & unix.S_IFMT {
	case unix.S_IFREG:
		return unix.DT_REG
	case unix.S_IFDIR:
		return unix.DT_DIR
	case unix.S_IFLNK:
		return unix.DT_LNK
	case unix.S_IFIFO:
		return unix.DT_FIFO
	case unix.S_IFSOCK:
		return unix.DT_SOCK
	case unix.S_IFCHR:
		return unix.DT_CHR
	case unix.S_IFBLK:
		return unix.DT_BLK
	default:
		return unix.DT_UNKNOWN
	}
}

func roReadDirents(t *testing.T, dir string) []roDirent {
	return roReadDirentsBuf(t, dir, 32<<10)
}

func roReadDirentsBuf(t *testing.T, dir string, bufSize int) []roDirent {
	t.Helper()

	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	require.NoError(t, err, "open %s", dir)
	defer func() { _ = unix.Close(fd) }()

	return roDrainDirents(t, fd, bufSize)
}

// roDrainDirents decodes the raw getdents64 stream. unix.ParseDirent would be
// simpler but discards d_type, d_ino and d_off, which is precisely what needs
// checking here.
func roDrainDirents(t *testing.T, fd int, bufSize int) []roDirent {
	t.Helper()

	buf := make([]byte, bufSize)
	var out []roDirent
	for {
		n, err := unix.Getdents(fd, buf)
		require.NoError(t, err)
		if n == 0 {
			return out
		}

		for offset := 0; offset < n; {
			raw := (*unix.Dirent)(unsafe.Pointer(&buf[offset]))
			reclen := int(raw.Reclen)
			require.Greater(t, reclen, 0, "malformed dirent record length")

			nameBytes := unsafe.Slice((*byte)(unsafe.Pointer(&raw.Name[0])), reclen-int(unsafe.Offsetof(raw.Name)))
			if i := bytes.IndexByte(nameBytes, 0); i >= 0 {
				nameBytes = nameBytes[:i]
			}

			out = append(out, roDirent{
				Name: string(nameBytes),
				Ino:  raw.Ino,
				Type: raw.Type,
				Off:  raw.Off,
			})
			offset += reclen
		}
	}
}

// ---------------------------------------------------------------------------
// Inode identity
// ---------------------------------------------------------------------------

func roInodeIdentity(t *testing.T, f *roFixture) {
	t.Run("HardlinksShareInode", func(t *testing.T) {
		t.Parallel()
		group := []string{
			"hardlinks/original",
			"hardlinks/link1",
			"hardlinks/link2",
			"hardlinks/subdir/link3",
		}

		var first unix.Stat_t
		require.NoError(t, unix.Stat(f.at(group[0]), &first))
		require.EqualValues(t, len(group), first.Nlink, "st_nlink does not match the hardlink count")

		for _, rel := range group[1:] {
			var st unix.Stat_t
			require.NoError(t, unix.Stat(f.at(rel), &st))
			require.Equal(t, first.Ino, st.Ino, "%s has a different inode number", rel)
			require.Equal(t, first.Nlink, st.Nlink, "%s has a different link count", rel)
		}
	})

	t.Run("DistinctFilesHaveDistinctInodes", func(t *testing.T) {
		t.Parallel()
		// Files with identical content must still be separate inodes: chunk
		// deduplication happens below the metadata layer and must not leak
		// into inode identity.
		var a, b unix.Stat_t
		require.NoError(t, unix.Stat(f.at("hardlinks/same_content_a"), &a))
		require.NoError(t, unix.Stat(f.at("hardlinks/same_content_b"), &b))
		require.NotEqual(t, a.Ino, b.Ino)
		require.EqualValues(t, 1, a.Nlink)
	})

	t.Run("InodesUniqueAcrossTree", func(t *testing.T) {
		t.Parallel()
		seen := map[uint64]string{}
		require.NoError(t, filepath.WalkDir(f.mnt, func(path string, d os.DirEntry, err error) error {
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
			if prev, dup := seen[st.Ino]; dup {
				t.Errorf("inode %d shared by %s and %s without a hardlink", st.Ino, prev, path)
			}
			seen[st.Ino] = path
			return nil
		}))
	})

	t.Run("SingleDevice", func(t *testing.T) {
		t.Parallel()
		var rootSt unix.Stat_t
		require.NoError(t, unix.Stat(f.mnt, &rootSt))
		require.NoError(t, filepath.WalkDir(f.mnt, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			var st unix.Stat_t
			if err := unix.Lstat(path, &st); err != nil {
				return err
			}
			require.Equal(t, rootSt.Dev, st.Dev, "%s reports a different st_dev", path)
			return nil
		}))
	})
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func roMetadata(t *testing.T, f *roFixture) {

	t.Run("RootIsAlwaysTraversable", func(t *testing.T) {
		t.Parallel()
		// Whatever umask staged the source tree, the root must not lock other
		// uids out of the image.
		var st unix.Stat_t
		require.NoError(t, unix.Stat(f.mnt, &st))
		require.EqualValues(t, 0o755, st.Mode&0o777, "the root's permission bits are not pinned")
		require.EqualValues(t, unix.S_IFDIR, st.Mode&unix.S_IFMT)
	})

	t.Run("RootMtimeIsDropped", func(t *testing.T) {
		t.Parallel()
		// The root's mtime is the build time, not a property of the content,
		// so the builder drops it to keep the bootstrap reproducible.
		var st unix.Stat_t
		require.NoError(t, unix.Stat(f.mnt, &st))
		require.Zero(t, st.Mtim.Sec, "the root's mtime should not be carried over")
		require.Zero(t, st.Mtim.Nsec)
	})

	t.Run("DeviceNumbers", func(t *testing.T) {
		t.Parallel()
		for rel, want := range map[string][2]uint32{
			"special/chardev": {1, 3},
			"special/blkdev":  {1, 0},
		} {
			var st unix.Stat_t
			require.NoError(t, unix.Lstat(f.at(rel), &st))
			require.EqualValues(t, want[0], unix.Major(st.Rdev), "%s: major", rel)
			require.EqualValues(t, want[1], unix.Minor(st.Rdev), "%s: minor", rel)
		}
	})

	t.Run("LargeUidGid", func(t *testing.T) {
		t.Parallel()
		// Beyond 16 bits the builder has to emit an extended inode instead of
		// the compact one.
		var st unix.Stat_t
		require.NoError(t, unix.Lstat(f.at("special/large_uid_gid"), &st))
		require.EqualValues(t, 70000, st.Uid)
		require.EqualValues(t, 70001, st.Gid)
	})

	t.Run("DirectoryLinkCount", func(t *testing.T) {
		t.Parallel()
		for _, rel := range []string{".", "dirs", "dirs/a", "dirs/empty_dir", "symlinks"} {
			path := f.at(rel)
			var st unix.Stat_t
			require.NoError(t, unix.Stat(path, &st))

			subdirs := 0
			for _, e := range roReadDirents(t, path) {
				if e.Name == "." || e.Name == ".." {
					continue
				}
				if e.Type == unix.DT_DIR {
					subdirs++
				}
			}
			require.EqualValues(t, subdirs+2, st.Nlink, "%s: st_nlink should be 2 + subdirectory count", rel)
		}
	})

	t.Run("BlocksAccountForData", func(t *testing.T) {
		t.Parallel()
		var empty, big unix.Stat_t
		require.NoError(t, unix.Stat(f.at("files/empty"), &empty))
		require.NoError(t, unix.Stat(f.at("files/large_256k"), &big))
		require.Zero(t, empty.Blocks, "an empty file should not report allocated blocks")
		require.GreaterOrEqual(t, big.Blocks*512, big.Size/2,
			"st_blocks is implausibly small for a %d byte file", big.Size)
	})
}

// ---------------------------------------------------------------------------
// Read paths
// ---------------------------------------------------------------------------

func roReadPaths(t *testing.T, f *roFixture) {

	t.Run("ReadPastEOF", func(t *testing.T) {
		t.Parallel()
		fd, err := unix.Open(f.at("files/tiny_2b"), unix.O_RDONLY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(fd) }()

		buf := make([]byte, 16)
		n, err := unix.Pread(fd, buf, 2)
		require.NoError(t, err)
		require.Zero(t, n, "reading at EOF should return 0 bytes")

		n, err = unix.Pread(fd, buf, 1<<20)
		require.NoError(t, err)
		require.Zero(t, n, "reading far past EOF should return 0 bytes")
	})

	t.Run("EmptyFile", func(t *testing.T) {
		t.Parallel()
		data, err := os.ReadFile(f.at("files/empty"))
		require.NoError(t, err)
		require.Empty(t, data)
	})

	t.Run("SparseHoleReadsZero", func(t *testing.T) {
		t.Parallel()
		want, err := os.ReadFile(filepath.Join(f.src, "files/sparse_hole"))
		require.NoError(t, err)
		got, err := os.ReadFile(f.at("files/sparse_hole"))
		require.NoError(t, err)
		require.True(t, bytes.Equal(want, got), "sparse file content differs")
	})

	t.Run("UnalignedCrossBoundaryReads", func(t *testing.T) {
		t.Parallel()
		rel := "files/ten_blocks"
		want, err := os.ReadFile(filepath.Join(f.src, rel))
		require.NoError(t, err)

		fd, err := unix.Open(f.at(rel), unix.O_RDONLY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(fd) }()

		// Straddle every 4KiB block boundary with lengths that are not powers
		// of two, which is where chunk stitching tends to go wrong.
		for _, off := range []int64{0, 1, 4095, 4096, 4097, 8191, 8192, 12287, 20479} {
			for _, length := range []int{1, 3, 4095, 4096, 4097, 8193} {
				if off >= int64(len(want)) {
					continue
				}
				end := off + int64(length)
				if end > int64(len(want)) {
					end = int64(len(want))
				}
				buf := make([]byte, length)
				n, err := unix.Pread(fd, buf, off)
				require.NoError(t, err, "pread(off=%d len=%d)", off, length)
				require.Equal(t, int(end-off), n, "pread(off=%d len=%d) short read", off, length)
				require.True(t, bytes.Equal(want[off:end], buf[:n]),
					"pread(off=%d len=%d) returned different bytes", off, length)
			}
		}
	})

	t.Run("Preadv", func(t *testing.T) {
		t.Parallel()
		rel := "files/two_blocks"
		want, err := os.ReadFile(filepath.Join(f.src, rel))
		require.NoError(t, err)

		fd, err := unix.Open(f.at(rel), unix.O_RDONLY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(fd) }()

		first := make([]byte, 100)
		second := make([]byte, 4000)
		n, err := unix.Preadv(fd, [][]byte{first, second}, 4090)
		require.NoError(t, err)
		require.Equal(t, len(first)+len(second), n)
		require.True(t, bytes.Equal(want[4090:4090+100], first))
		require.True(t, bytes.Equal(want[4190:4190+4000], second))
	})

	t.Run("DirectIO", func(t *testing.T) {
		t.Parallel()
		rel := "files/two_blocks"
		want, err := os.ReadFile(filepath.Join(f.src, rel))
		require.NoError(t, err)

		fd, err := unix.Open(f.at(rel), unix.O_RDONLY|unix.O_DIRECT, 0)
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP) {
			t.Skip("O_DIRECT not supported")
		}
		require.NoError(t, err)
		defer func() { _ = unix.Close(fd) }()

		buf := roAlignedBuffer(8192)
		n, err := unix.Pread(fd, buf[:4096], 0)
		require.NoError(t, err)
		require.Equal(t, 4096, n)
		require.True(t, bytes.Equal(want[:4096], buf[:4096]), "O_DIRECT read returned different bytes")
	})
}

// roAlignedBuffer returns a page-aligned slice, which O_DIRECT requires.
func roAlignedBuffer(size int) []byte {
	pageSize := os.Getpagesize()
	raw := make([]byte, size+pageSize)
	offset := int(uintptr(unsafe.Pointer(&raw[0])) % uintptr(pageSize))
	if offset != 0 {
		offset = pageSize - offset
	}
	return raw[offset : offset+size]
}

// ---------------------------------------------------------------------------
// mmap
// ---------------------------------------------------------------------------

func roMmap(t *testing.T, f *roFixture) {
	t.Run("SharedReadMatchesFile", func(t *testing.T) {
		t.Parallel()
		rel := "files/ten_blocks"
		want, err := os.ReadFile(filepath.Join(f.src, rel))
		require.NoError(t, err)

		data, unmap := roMmapFile(t, f.at(rel), len(want), unix.PROT_READ, unix.MAP_SHARED)
		defer unmap()
		require.True(t, bytes.Equal(want, data))
	})

	t.Run("TailPageIsZeroPadded", func(t *testing.T) {
		t.Parallel()
		// The bytes between EOF and the end of the last page must read as zero.
		rel := "files/one_over_block" // 4097 bytes, so 4095 padding bytes
		pageSize := os.Getpagesize()
		mapped := ((4097 + pageSize - 1) / pageSize) * pageSize

		data, unmap := roMmapFile(t, f.at(rel), mapped, unix.PROT_READ, unix.MAP_PRIVATE)
		defer unmap()

		for i := 4097; i < mapped; i++ {
			require.Zero(t, data[i], "byte %d past EOF is not zero", i)
		}
	})

	t.Run("PrivateWriteIsCopyOnWrite", func(t *testing.T) {
		t.Parallel()
		rel := "files/exact_block"
		want, err := os.ReadFile(filepath.Join(f.src, rel))
		require.NoError(t, err)

		data, unmap := roMmapFile(t, f.at(rel), len(want), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
		data[0] ^= 0xff
		require.NotEqual(t, want[0], data[0], "MAP_PRIVATE mapping should be writable")
		unmap()

		// The private modification must not have reached the filesystem.
		after, err := os.ReadFile(f.at(rel))
		require.NoError(t, err)
		require.True(t, bytes.Equal(want, after), "a MAP_PRIVATE write leaked into the filesystem")
	})

	t.Run("SharedWriteMappingRejected", func(t *testing.T) {
		t.Parallel()
		// A shared writable mapping needs a writable fd, which a read-only
		// mount must refuse in the first place.
		require.Error(t, roOpen(f.at("files/exact_block"), unix.O_RDWR))
	})
}

func roMmapFile(t *testing.T, path string, length, prot, flags int) ([]byte, func()) {
	t.Helper()

	fd, err := unix.Open(path, unix.O_RDONLY, 0)
	require.NoError(t, err)
	defer func() { _ = unix.Close(fd) }()

	if length == 0 {
		return nil, func() {}
	}
	data, err := unix.Mmap(fd, 0, length, prot, flags)
	require.NoError(t, err, "mmap %s", path)

	var once sync.Once
	return data, func() { once.Do(func() { _ = unix.Munmap(data) }) }
}

// ---------------------------------------------------------------------------
// lseek
// ---------------------------------------------------------------------------

func roSeek(t *testing.T, f *roFixture) {
	rel := "files/ten_blocks"
	size := int64(4096 * 10)

	t.Run("SetCurEnd", func(t *testing.T) {
		t.Parallel()
		fd, err := unix.Open(f.at(rel), unix.O_RDONLY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(fd) }()

		pos, err := unix.Seek(fd, 0, unix.SEEK_END)
		require.NoError(t, err)
		require.Equal(t, size, pos)

		pos, err = unix.Seek(fd, -4096, unix.SEEK_CUR)
		require.NoError(t, err)
		require.Equal(t, size-4096, pos)

		pos, err = unix.Seek(fd, 4096, unix.SEEK_SET)
		require.NoError(t, err)
		require.Equal(t, int64(4096), pos)
	})

	t.Run("NegativeOffsetRejected", func(t *testing.T) {
		t.Parallel()
		fd, err := unix.Open(f.at(rel), unix.O_RDONLY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(fd) }()

		_, err = unix.Seek(fd, -1, unix.SEEK_SET)
		require.ErrorIs(t, err, unix.EINVAL)
	})

	t.Run("DataHole", func(t *testing.T) {
		t.Parallel()
		fd, err := unix.Open(f.at(rel), unix.O_RDONLY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(fd) }()

		pos, err := unix.Seek(fd, 0, unix.SEEK_DATA)
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
			t.Skip("SEEK_DATA not supported")
		}
		require.NoError(t, err)
		require.GreaterOrEqual(t, pos, int64(0))

		// SEEK_HOLE past the last byte of data always lands at EOF.
		pos, err = unix.Seek(fd, size-1, unix.SEEK_HOLE)
		require.NoError(t, err)
		require.Equal(t, size, pos)

		// Seeking beyond EOF is defined to fail with ENXIO for both whences.
		_, err = unix.Seek(fd, size, unix.SEEK_DATA)
		require.ErrorIs(t, err, unix.ENXIO)
		_, err = unix.Seek(fd, size, unix.SEEK_HOLE)
		require.ErrorIs(t, err, unix.ENXIO)
	})
}

// ---------------------------------------------------------------------------
// splice / sendfile
// ---------------------------------------------------------------------------

func roSpliceSendfile(t *testing.T, f *roFixture) {
	rel := "files/two_blocks"
	want, err := os.ReadFile(filepath.Join(f.src, rel))
	require.NoError(t, err)

	t.Run("Sendfile", func(t *testing.T) {
		t.Parallel()
		src, err := unix.Open(f.at(rel), unix.O_RDONLY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(src) }()

		dst, err := os.CreateTemp(t.TempDir(), "sendfile")
		require.NoError(t, err)
		defer func() { _ = dst.Close() }()

		var offset int64
		n, err := unix.Sendfile(int(dst.Fd()), src, &offset, len(want))
		require.NoError(t, err)
		require.Equal(t, len(want), n)

		got, err := os.ReadFile(dst.Name())
		require.NoError(t, err)
		require.True(t, bytes.Equal(want, got))
	})

	t.Run("Splice", func(t *testing.T) {
		t.Parallel()
		src, err := unix.Open(f.at(rel), unix.O_RDONLY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(src) }()

		var pipeFds [2]int
		require.NoError(t, unix.Pipe(pipeFds[:]))
		defer func() { _ = unix.Close(pipeFds[0]) }()
		defer func() { _ = unix.Close(pipeFds[1]) }()

		var offset int64
		n, err := unix.Splice(src, &offset, pipeFds[1], nil, 4096, 0)
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) {
			t.Skip("splice not supported")
		}
		require.NoError(t, err)
		require.Positive(t, n)

		buf := make([]byte, n)
		read, err := unix.Read(pipeFds[0], buf)
		require.NoError(t, err)
		require.True(t, bytes.Equal(want[:read], buf[:read]))
	})
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

func roPathResolution(t *testing.T, f *roFixture) {
	t.Run("ReadlinkTargets", func(t *testing.T) {
		t.Parallel()
		for rel, want := range map[string]string{
			"symlinks/link_to_file":  "target_file",
			"symlinks/link_to_dir":   "target_dir",
			"symlinks/relative_link": "../files/tiny_2b",
			"symlinks/dangling":      "nonexistent_target",
			"symlinks/chain_a":       "chain_b",
			"symlinks/chain_b":       "chain_c",
		} {
			got, err := os.Readlink(f.at(rel))
			require.NoError(t, err, "readlink %s", rel)
			require.Equal(t, want, got, "%s", rel)
		}
	})

	t.Run("ChainResolves", func(t *testing.T) {
		t.Parallel()
		data, err := os.ReadFile(f.at("symlinks/chain_a"))
		require.NoError(t, err)
		require.Equal(t, "chain_end", string(data))
	})

	t.Run("DanglingSymlink", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		require.NoError(t, unix.Lstat(f.at("symlinks/dangling"), &st), "lstat must succeed")
		require.ErrorIs(t, unix.Stat(f.at("symlinks/dangling"), &st), unix.ENOENT)
	})

	t.Run("NoFollow", func(t *testing.T) {
		t.Parallel()
		err := roOpen(f.at("symlinks/link_to_file"), unix.O_RDONLY|unix.O_NOFOLLOW)
		require.ErrorIs(t, err, unix.ELOOP)
	})

	t.Run("NotADirectory", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		require.ErrorIs(t, unix.Stat(f.at("files/tiny_2b/child"), &st), unix.ENOTDIR)
	})

	t.Run("NameTooLong", func(t *testing.T) {
		t.Parallel()
		// The kernel FUSE layer only rejects names above FUSE_NAME_MAX (1024),
		// so advertising f_namelen=255 obliges lookup to enforce NAME_MAX too.
		var st unix.Stat_t
		err := unix.Lstat(f.at("files/"+corpus.LongName('z', 300)), &st)
		require.ErrorIs(t, err, unix.ENAMETOOLONG)
	})

	t.Run("MaxLengthNameResolves", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		require.NoError(t, unix.Lstat(f.at("names/"+corpus.LongName('a', 250)), &st))
	})

	t.Run("MissingEntry", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		require.ErrorIs(t, unix.Lstat(f.at("files/definitely_absent"), &st), unix.ENOENT)
	})
}

// ---------------------------------------------------------------------------
// Extended attributes
// ---------------------------------------------------------------------------

func roXattr(t *testing.T, f *roFixture) {

	t.Run("SizeProbe", func(t *testing.T) {
		t.Parallel()
		path := f.at("xattrs/user_long_val")
		size, err := unix.Getxattr(path, "user.longval", nil)
		require.NoError(t, err)
		require.Equal(t, 512, size, "a nil buffer must report the value size")
	})

	t.Run("BufferTooSmall", func(t *testing.T) {
		t.Parallel()
		_, err := unix.Getxattr(f.at("xattrs/user_long_val"), "user.longval", make([]byte, 8))
		require.ErrorIs(t, err, unix.ERANGE)

		_, err = unix.Listxattr(f.at("xattrs/user_huge_ibody"), make([]byte, 4))
		require.ErrorIs(t, err, unix.ERANGE)
	})

	t.Run("MissingAttribute", func(t *testing.T) {
		t.Parallel()
		_, err := unix.Getxattr(f.at("xattrs/user_basic"), "user.absent", make([]byte, 64))
		require.ErrorIs(t, err, unix.ENODATA)
	})

	t.Run("EmptyValue", func(t *testing.T) {
		t.Parallel()
		size, err := unix.Getxattr(f.at("xattrs/user_empty_val"), "user.empty", nil)
		require.NoError(t, err)
		require.Zero(t, size)
	})

	t.Run("PrivilegedNamespaces", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, []byte("trusted_value"), roGetXattr(t, f.at("xattrs/trusted_attr"), "trusted.test"))
		require.Equal(t, []byte("sec_value"), roGetXattr(t, f.at("xattrs/security_attr"), "security.test"))
	})

	t.Run("InlineBodyOverflow", func(t *testing.T) {
		t.Parallel()
		// Three ~900 byte values do not fit in the inline xattr body of an
		// EROFS inode, so this exercises the shared-xattr spill path.
		names := roListXattr(t, f.at("xattrs/user_huge_ibody"))
		require.Len(t, names, 3)
		for i := 0; i < 3; i++ {
			name := fmt.Sprintf("user.large_%02d", i)
			require.Len(t, roGetXattr(t, f.at("xattrs/user_huge_ibody"), name), 900)
		}
	})
}

// ---------------------------------------------------------------------------
// statfs
// ---------------------------------------------------------------------------

func roStatfs(t *testing.T, f *roFixture) {
	var st unix.Statfs_t
	require.NoError(t, unix.Statfs(f.mnt, &st))

	require.EqualValues(t, fuseSuperMagic, st.Type, "f_type should be FUSE_SUPER_MAGIC")
	require.Positive(t, st.Bsize, "f_bsize must be positive")
	require.EqualValues(t, 255, st.Namelen, "f_namelen should be NAME_MAX")

	// Nothing can ever be written here, so there is no free space to report.
	require.Zero(t, st.Bavail, "a read-only filesystem must report no available blocks")
}

// ---------------------------------------------------------------------------
// Open flags
// ---------------------------------------------------------------------------

func roOpenFlags(t *testing.T, f *roFixture) {
	t.Run("ODirectoryOnFile", func(t *testing.T) {
		t.Parallel()
		require.ErrorIs(t, roOpen(f.at("files/tiny_2b"), unix.O_RDONLY|unix.O_DIRECTORY), unix.ENOTDIR)
	})

	t.Run("ODirectoryOnDir", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, roOpen(f.at("dirs"), unix.O_RDONLY|unix.O_DIRECTORY))
	})

	t.Run("OPath", func(t *testing.T) {
		t.Parallel()
		fd, err := unix.Open(f.at("special/fifo"), unix.O_PATH|unix.O_NOFOLLOW, 0)
		require.NoError(t, err, "O_PATH must work even on a FIFO")
		defer func() { _ = unix.Close(fd) }()

		var st unix.Stat_t
		require.NoError(t, unix.Fstat(fd, &st))
		require.EqualValues(t, unix.S_IFIFO, st.Mode&unix.S_IFMT)
	})

	t.Run("OpenatRelative", func(t *testing.T) {
		t.Parallel()
		dirFd, err := unix.Open(f.at("files"), unix.O_RDONLY|unix.O_DIRECTORY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(dirFd) }()

		fd, err := unix.Openat(dirFd, "tiny_2b", unix.O_RDONLY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(fd) }()

		buf := make([]byte, 2)
		n, err := unix.Read(fd, buf)
		require.NoError(t, err)
		require.Equal(t, "hi", string(buf[:n]))
	})

	t.Run("StatxAtEmptyPath", func(t *testing.T) {
		t.Parallel()
		fd, err := unix.Open(f.at("files/exact_block"), unix.O_RDONLY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(fd) }()

		var stx unix.Statx_t
		err = unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_BASIC_STATS, &stx)
		if errors.Is(err, unix.ENOSYS) {
			t.Skip("statx not available")
		}
		require.NoError(t, err)
		require.EqualValues(t, 4096, stx.Size)
	})

	t.Run("FifoDoesNotBlockWithOPath", func(t *testing.T) {
		t.Parallel()
		// Opening a FIFO for reading would block; O_PATH resolves it without
		// engaging the pipe semantics, which is what a metadata-only lookup
		// must support.
		fd, err := unix.Open(f.at("special/fifo"), unix.O_PATH, 0)
		require.NoError(t, err)
		require.NoError(t, unix.Close(fd))
	})
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

func roConcurrency(t *testing.T, f *roFixture) {
	rel := "files/large_256k"
	want, err := os.ReadFile(filepath.Join(f.src, rel))
	require.NoError(t, err)

	t.Run("ParallelReadsAgree", func(t *testing.T) {
		t.Parallel()
		const workers = 16
		var wg sync.WaitGroup
		errs := make([]error, workers)

		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				for round := 0; round < 4; round++ {
					got, readErr := os.ReadFile(f.at(rel))
					if readErr != nil {
						errs[idx] = readErr
						return
					}
					if !bytes.Equal(want, got) {
						errs[idx] = fmt.Errorf("worker %d round %d read different bytes", idx, round)
						return
					}
				}
			}(i)
		}
		wg.Wait()

		for _, e := range errs {
			require.NoError(t, e)
		}
	})

	t.Run("ParallelWalks", func(t *testing.T) {
		t.Parallel()
		const workers = 8
		var wg sync.WaitGroup
		counts := make([]int, workers)

		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				_ = filepath.WalkDir(f.mnt, func(_ string, _ os.DirEntry, err error) error {
					if err != nil {
						return err
					}
					counts[idx]++
					return nil
				})
			}(i)
		}
		wg.Wait()

		for i := 1; i < workers; i++ {
			require.Equal(t, counts[0], counts[i], "concurrent walks saw a different number of entries")
		}
	})
}

// ---------------------------------------------------------------------------
// Remount stability
// ---------------------------------------------------------------------------

// roRemountStability catches non-deterministic metadata: inode numbers are
// derived from the on-disk NID, so they must survive an unmount/remount cycle
// unchanged.
func roRemountStability(t *testing.T, f *roFixture) {
	before := roInodeMap(t, f.mnt)

	second := filepath.Join(t.TempDir(), "remount")
	cleanup := mountNydusBootstrap(t, f.nydusBin, f.img.Bootstrap, f.img.BlobDir, second)
	defer cleanup()

	after := roInodeMap(t, second)

	require.Equal(t, len(before), len(after), "the remount exposed a different number of paths")
	for rel, ino := range before {
		require.Equal(t, ino, after[rel], "%s changed inode number across a remount", rel)
	}
}

func roInodeMap(t *testing.T, mnt string) map[string]uint64 {
	t.Helper()

	out := map[string]uint64{}
	require.NoError(t, filepath.WalkDir(mnt, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(mnt, path)
		if err != nil {
			return err
		}
		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			return err
		}
		out[rel] = st.Ino
		return nil
	}))
	return out
}

// roDirOffset checks the directory offset protocol from fstests'
// src/t_dir_offset2.c: every d_off in a directory is unique, and seeking a
// directory fd to a recorded d_off resumes the stream at the following entry.
// EROFS encodes d_off itself, so a wrong encoding silently breaks any tool that
// resumes a large directory listing.
func roDirOffset(t *testing.T, f *roFixture) {
	dirs := []string{"dirs/many_entries", "dirs", "dirs/empty_dir"}

	t.Run("OffsetsUnique", func(t *testing.T) {
		t.Parallel()
		for _, rel := range dirs {
			fd, err := unix.Open(f.at(rel), unix.O_RDONLY|unix.O_DIRECTORY, 0)
			require.NoError(t, err)

			seen := map[int64]string{}
			for _, e := range roDrainDirents(t, fd, 4096) {
				prev, dup := seen[e.Off]
				require.False(t, dup, "%s: %q and %q share d_off %d", rel, prev, e.Name, e.Off)
				seen[e.Off] = e.Name
			}
			require.NoError(t, unix.Close(fd))
		}
	})

	t.Run("SeekResumesStream", func(t *testing.T) {
		t.Parallel()
		for _, rel := range dirs {
			fd, err := unix.Open(f.at(rel), unix.O_RDONLY|unix.O_DIRECTORY, 0)
			require.NoError(t, err)

			all := roDrainDirents(t, fd, 4096)
			for i := range all {
				var from int64
				if i > 0 {
					from = all[i-1].Off
				}
				_, err := unix.Seek(fd, from, unix.SEEK_SET)
				require.NoError(t, err, "%s: seek to d_off %d", rel, from)

				next := roDrainDirents(t, fd, 4096)
				require.NotEmpty(t, next, "%s: nothing left after d_off %d", rel, from)
				require.Equal(t, all[i].Name, next[0].Name,
					"%s: resuming at d_off %d yielded the wrong entry", rel, from)
				require.Equal(t, all[i].Ino, next[0].Ino, "%s: d_ino changed after seek", rel)
			}
			require.NoError(t, unix.Close(fd))
		}
	})

	t.Run("SeekIsRepeatable", func(t *testing.T) {
		t.Parallel()
		fd, err := unix.Open(f.at("dirs/many_entries"), unix.O_RDONLY|unix.O_DIRECTORY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(fd) }()

		all := roDrainDirents(t, fd, 4096)
		require.Greater(t, len(all), 10)
		mid := all[len(all)/2].Off

		var first []roDirent
		for i := 0; i < 3; i++ {
			_, err := unix.Seek(fd, mid, unix.SEEK_SET)
			require.NoError(t, err)
			got := roDrainDirents(t, fd, 4096)
			if i == 0 {
				first = got
				continue
			}
			require.Equal(t, first, got, "re-seeking to the same d_off gave a different tail")
		}
	})

	t.Run("SeparateHandlesAreIndependent", func(t *testing.T) {
		t.Parallel()
		path := f.at("dirs/many_entries")
		a, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(a) }()
		b, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(b) }()

		buf := make([]byte, 4096)
		n, err := unix.Getdents(a, buf)
		require.NoError(t, err)
		require.Positive(t, n, "the first read on handle A returned nothing")

		// B has never been read, so it must still start from the beginning.
		full := roDrainDirents(t, b, 1<<16)
		require.Contains(t, roDirentNames(full), ".", "handle B lost its own position")
	})

	t.Run("RewindByZero", func(t *testing.T) {
		t.Parallel()
		fd, err := unix.Open(f.at("dirs/many_entries"), unix.O_RDONLY|unix.O_DIRECTORY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(fd) }()

		want := roDrainDirents(t, fd, 4096)
		_, err = unix.Seek(fd, 0, unix.SEEK_SET)
		require.NoError(t, err)
		require.Equal(t, want, roDrainDirents(t, fd, 4096))
	})
}

func roDirentNames(entries []roDirent) []string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	return names
}

// roPermissions drops to an unprivileged uid and checks that the mode, uid and
// gid Nydus reports actually gate access. The mount carries
// `default_permissions`, so this is what proves the attributes reaching the
// kernel are the ones the source tree had.
func roPermissions(t *testing.T, f *roFixture) {
	t.Run("WriteAccessRejected", func(t *testing.T) {
		t.Parallel()
		// A read-only mount must deny W_OK even for a mode that allows it and
		// even for root.
		var st unix.Stat_t
		require.NoError(t, unix.Stat(f.at("perms/rwx"), &st))
		require.EqualValues(t, 0o777, st.Mode&0o7777, "corpus file lost its mode")

		err := unix.Access(f.at("perms/rwx"), unix.W_OK)
		require.Error(t, err, "W_OK succeeded on a read-only mount")
		require.ErrorIs(t, err, unix.EROFS)
	})

	t.Run("SetuidBitsSurvive", func(t *testing.T) {
		t.Parallel()
		for rel, want := range map[string]uint32{
			"perms/setuid":    0o4755,
			"perms/setgid":    0o2755,
			"perms/sticky":    0o1755,
			"perms/suid_sgid": 0o6755,
		} {
			var st unix.Stat_t
			require.NoError(t, unix.Stat(f.at(rel), &st))
			require.EqualValues(t, want, st.Mode&0o7777, "%s lost its special bits", rel)
		}
	})

	if os.Geteuid() != 0 {
		t.Skip("dropping privileges requires root")
	}
	if !roMountAllowsOtherUsers(t, f.mnt) {
		t.Skip("the mount lacks allow_other, so no uid but the daemon's can reach it at all")
	}

	cases := []struct {
		name string
		rel  string
		mode int
		want error
	}{
		{name: "WorldReadableOpens", rel: "perms/other_owner_r", mode: unix.O_RDONLY},
		{name: "OwnerOnlyDenied", rel: "perms/other_owner_none", mode: unix.O_RDONLY, want: unix.EACCES},
		{name: "ModeZeroDenied", rel: "perms/no_perm", mode: unix.O_RDONLY, want: unix.EACCES},
		{name: "ReadOnlyFileOpens", rel: "perms/r_only", mode: unix.O_RDONLY},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := roOpenAsUser(t, f.at(tc.rel))
			if tc.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tc.want)
		})
	}

	t.Run("TraverseWithoutList", func(t *testing.T) {
		t.Parallel()
		// 0711: reachable by name, but the listing is denied.
		require.NoError(t, roOpenAsUser(t, f.at("perms/x_only_dir/hidden")))
		require.ErrorIs(t, roReaddirAsUser(t, f.at("perms/x_only_dir")), unix.EACCES)
	})

	t.Run("ListWithoutTraverse", func(t *testing.T) {
		t.Parallel()
		// 0444: the names are visible but no child can be reached through it.
		require.NoError(t, roReaddirAsUser(t, f.at("perms/r_only_dir")))
		require.ErrorIs(t, roOpenAsUser(t, f.at("perms/r_only_dir/listed")), unix.EACCES)
	})

	t.Run("AccessMatchesOpen", func(t *testing.T) {
		t.Parallel()
		// access(2) consults the real uid, which setfsuid does not change, so the
		// comparison has to go through faccessat2's AT_EACCESS against the fsuid
		// the kernel actually uses for the lookup.
		require.NoError(t, roAsUser(t, func() error {
			return unix.Faccessat(unix.AT_FDCWD, f.at("perms/other_owner_r"), unix.R_OK, unix.AT_EACCESS)
		}))
		require.ErrorIs(t, roAsUser(t, func() error {
			return unix.Faccessat(unix.AT_FDCWD, f.at("perms/other_owner_none"), unix.R_OK, unix.AT_EACCESS)
		}), unix.EACCES)
	})

}

const roUnprivilegedUID = 65534

// roAsUser runs fn with the calling thread's filesystem uid and gid dropped to
// an unprivileged pair. setfsuid is per-thread and, once the fsuid is non-zero,
// the kernel also clears CAP_DAC_OVERRIDE and friends from the effective set,
// which is exactly the check being exercised here.
func roAsUser(t *testing.T, fn func() error) error {
	t.Helper()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	require.NoError(t, unix.Setfsgid(roUnprivilegedUID))
	require.NoError(t, unix.Setfsuid(roUnprivilegedUID))
	defer func() {
		_ = unix.Setfsuid(0)
		_ = unix.Setfsgid(0)
	}()

	// setfsuid cannot report failure, and running these checks as root would
	// make every one of them pass, so read the fsuid back before trusting fn.
	require.EqualValues(t, roUnprivilegedUID, roThreadFsuid(t), "fsuid was not dropped")

	return fn()
}

// roThreadFsuid returns the calling thread's filesystem uid, the fourth field
// of the Uid line in /proc/thread-self/status.
func roThreadFsuid(t *testing.T) int {
	t.Helper()

	status, err := os.ReadFile("/proc/thread-self/status")
	require.NoError(t, err)
	for _, line := range strings.Split(string(status), "\n") {
		rest, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		require.Len(t, fields, 4, "unexpected Uid line: %q", line)
		fsuid, err := strconv.Atoi(fields[3])
		require.NoError(t, err)
		return fsuid
	}
	t.Fatal("no Uid line in /proc/thread-self/status")
	return -1
}

func roOpenAsUser(t *testing.T, path string) error {
	return roAsUser(t, func() error {
		fd, err := unix.Open(path, unix.O_RDONLY, 0)
		if err == nil {
			_ = unix.Close(fd)
		}
		return err
	})
}

func roReaddirAsUser(t *testing.T, path string) error {
	return roAsUser(t, func() error {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if err != nil {
			return err
		}
		defer func() { _ = unix.Close(fd) }()
		_, err = unix.Getdents(fd, make([]byte, 4096))
		return err
	})
}

// roSymlinkLoops covers the shapes generic/005 uses: resolution has to stop
// with ELOOP instead of recursing.
func roSymlinkLoops(t *testing.T, f *roFixture) {
	for _, rel := range []string{"symlinks/self_loop", "symlinks/loop_a", "symlinks/loop_b"} {
		t.Run(strings.TrimPrefix(rel, "symlinks/"), func(t *testing.T) {
			t.Parallel()
			var st unix.Stat_t
			require.ErrorIs(t, unix.Stat(f.at(rel), &st), unix.ELOOP)

			// The link itself is still readable; only following it loops.
			require.NoError(t, unix.Lstat(f.at(rel), &st))
			buf := make([]byte, 256)
			_, err := unix.Readlink(f.at(rel), buf)
			require.NoError(t, err)
		})
	}

	t.Run("ChainBeyondKernelBudget", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		// The kernel follows at most 40 links, so the tail of a 50-link chain
		// must fail while a short prefix still resolves.
		require.ErrorIs(t, unix.Stat(f.at("symlinks/deep_49"), &st), unix.ELOOP)
		require.NoError(t, unix.Stat(f.at("symlinks/deep_05"), &st))
	})

	t.Run("PathLongerThanPathMax", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		long := f.mnt + "/" + strings.Repeat("a/", 3000) + "x"
		require.ErrorIs(t, unix.Stat(long, &st), unix.ENAMETOOLONG)
	})

	t.Run("ParentOfSubdirectoryIsRoot", func(t *testing.T) {
		t.Parallel()
		var root, parent unix.Stat_t
		require.NoError(t, unix.Stat(f.mnt, &root))
		require.NoError(t, unix.Stat(f.at("dirs/a/b/.."), &parent))

		var b unix.Stat_t
		require.NoError(t, unix.Stat(f.at("dirs/a"), &b))
		require.Equal(t, b.Ino, parent.Ino, "dirs/a/b/.. should be dirs/a")

		require.NoError(t, unix.Stat(f.at("dirs/.."), &parent))
		require.Equal(t, root.Ino, parent.Ino, "dirs/.. should be the filesystem root")
	})
}

// roSparseMap walks every sparse file with SEEK_DATA and SEEK_HOLE and checks
// the invariants POSIX requires, without assuming a particular hole
// granularity: a chunked image will not report the same extents the staging
// filesystem does.
func roSparseMap(t *testing.T, f *roFixture) {
	var files []string
	require.NoError(t, filepath.WalkDir(f.src, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		info, err := d.Info()
		require.NoError(t, err)
		// Only files with at least one hole are interesting, and only ones
		// small enough to scan exhaustively.
		if info.Size() > 0 && info.Size() <= roFullReadLimit &&
			info.Sys().(*syscall.Stat_t).Blocks*512 < info.Size() {
			rel, err := filepath.Rel(f.src, path)
			require.NoError(t, err)
			files = append(files, rel)
		}
		return nil
	}))
	require.NotEmpty(t, files, "the corpus has no sparse files to map")

	t.Run("ExtentsAreWellFormed", func(t *testing.T) {
		t.Parallel()
		for _, rel := range files {
			fd, err := unix.Open(f.at(rel), unix.O_RDONLY, 0)
			require.NoError(t, err)

			var st unix.Stat_t
			require.NoError(t, unix.Fstat(fd, &st))
			size := st.Size

			// Alternate DATA and HOLE from 0; every step must advance, stay
			// within the file, and terminate.
			pos := int64(0)
			steps := 0
			for pos < size {
				steps++
				require.Less(t, steps, 1<<16, "%s: extent walk did not terminate", rel)

				data, err := unix.Seek(fd, pos, unix.SEEK_DATA)
				if errors.Is(err, unix.ENXIO) {
					break
				}
				require.NoError(t, err, "%s: SEEK_DATA at %d", rel, pos)
				require.GreaterOrEqual(t, data, pos, "%s: SEEK_DATA went backwards", rel)
				require.Less(t, data, size, "%s: SEEK_DATA past EOF", rel)

				hole, err := unix.Seek(fd, data, unix.SEEK_HOLE)
				require.NoError(t, err, "%s: SEEK_HOLE at %d", rel, data)
				require.Greater(t, hole, data, "%s: SEEK_HOLE did not advance", rel)
				require.LessOrEqual(t, hole, size, "%s: SEEK_HOLE past EOF", rel)
				pos = hole
			}
			require.NoError(t, unix.Close(fd))
		}
	})

	t.Run("HolesReadZero", func(t *testing.T) {
		t.Parallel()
		for _, rel := range files {
			fd, err := unix.Open(f.at(rel), unix.O_RDONLY, 0)
			require.NoError(t, err)

			var st unix.Stat_t
			require.NoError(t, unix.Fstat(fd, &st))

			pos := int64(0)
			for pos < st.Size {
				hole, err := unix.Seek(fd, pos, unix.SEEK_HOLE)
				require.NoError(t, err)
				if hole >= st.Size {
					break
				}
				next, err := unix.Seek(fd, hole, unix.SEEK_DATA)
				if errors.Is(err, unix.ENXIO) {
					next = st.Size
				} else {
					require.NoError(t, err)
				}

				n := next - hole
				if n > 1<<20 {
					n = 1 << 20
				}
				buf := make([]byte, n)
				_, err = unix.Pread(fd, buf, hole)
				require.NoError(t, err)
				require.Equal(t, make([]byte, n), buf,
					"%s: bytes %d..%d are reported as a hole but are not zero", rel, hole, hole+n)
				pos = next
			}
			require.NoError(t, unix.Close(fd))
		}
	})

	t.Run("EmptyFileHasNoData", func(t *testing.T) {
		t.Parallel()
		fd, err := unix.Open(f.at("files/empty"), unix.O_RDONLY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(fd) }()

		_, err = unix.Seek(fd, 0, unix.SEEK_DATA)
		require.ErrorIs(t, err, unix.ENXIO)
		_, err = unix.Seek(fd, 0, unix.SEEK_HOLE)
		require.ErrorIs(t, err, unix.ENXIO)
	})
}

// roStability covers behaviour that has to hold because the mount can never
// change: timestamps do not move, and repeated queries agree.
func roStability(t *testing.T, f *roFixture) {
	t.Run("ReadDoesNotAdvanceAtime", func(t *testing.T) {
		t.Parallel()
		path := f.at("files/small_100b")

		var before unix.Stat_t
		require.NoError(t, unix.Stat(path, &before))

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.NotEmpty(t, data)

		var after unix.Stat_t
		require.NoError(t, unix.Stat(path, &after))
		require.Equal(t, before.Atim, after.Atim, "a read-only mount must not advance atime")
		require.Equal(t, before.Mtim, after.Mtim)
		require.Equal(t, before.Ctim, after.Ctim)
	})

	t.Run("ReaddirDoesNotAdvanceAtime", func(t *testing.T) {
		t.Parallel()
		path := f.at("dirs/many_entries")

		var before unix.Stat_t
		require.NoError(t, unix.Stat(path, &before))
		_, err := os.ReadDir(path)
		require.NoError(t, err)
		var after unix.Stat_t
		require.NoError(t, unix.Stat(path, &after))
		require.Equal(t, before.Atim, after.Atim)
	})

	t.Run("StatxReportsNoBirthTime", func(t *testing.T) {
		t.Parallel()
		var stx unix.Statx_t
		err := unix.Statx(unix.AT_FDCWD, f.at("files/small_100b"),
			0, unix.STATX_ALL, &stx)
		require.NoError(t, err)

		// EROFS stores no creation time, so the mask must not claim one.
		require.Zero(t, stx.Mask&unix.STATX_BTIME, "btime reported but EROFS has none")
		require.NotZero(t, stx.Mask&unix.STATX_MTIME)
		require.NotZero(t, stx.Mask&unix.STATX_INO)
	})

	t.Run("StatxNoFollowSeesTheLink", func(t *testing.T) {
		t.Parallel()
		rel := "symlinks/link_to_file"
		target, err := os.Readlink(f.at(rel))
		require.NoError(t, err)

		var stx unix.Statx_t
		require.NoError(t, unix.Statx(unix.AT_FDCWD, f.at(rel),
			unix.AT_SYMLINK_NOFOLLOW, unix.STATX_ALL, &stx))
		require.EqualValues(t, unix.S_IFLNK, stx.Mode&unix.S_IFMT)
		require.EqualValues(t, len(target), stx.Size, "a symlink's size is its target length")
	})
}

// roLocksAndCopy covers the syscalls container workloads reach for that are
// neither plain reads nor writes.
func roLocksAndCopy(t *testing.T, f *roFixture) {
	t.Run("SharedFlockSucceeds", func(t *testing.T) {
		t.Parallel()
		fd, err := unix.Open(f.at("files/small_100b"), unix.O_RDONLY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(fd) }()

		require.NoError(t, unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB))
		require.NoError(t, unix.Flock(fd, unix.LOCK_UN))
	})

	t.Run("ReadLockSucceeds", func(t *testing.T) {
		t.Parallel()
		fd, err := unix.Open(f.at("files/small_100b"), unix.O_RDONLY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(fd) }()

		lk := unix.Flock_t{Type: unix.F_RDLCK, Whence: unix.SEEK_SET}
		require.NoError(t, unix.FcntlFlock(uintptr(fd), unix.F_SETLK, &lk))

		probe := unix.Flock_t{Type: unix.F_RDLCK, Whence: unix.SEEK_SET}
		require.NoError(t, unix.FcntlFlock(uintptr(fd), unix.F_GETLK, &probe))
		require.EqualValues(t, unix.F_UNLCK, probe.Type, "an unheld range should read back unlocked")
	})

	t.Run("CopyFileRangeReadsSource", func(t *testing.T) {
		t.Parallel()
		src, err := unix.Open(f.at("files/small_100b"), unix.O_RDONLY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(src) }()

		dstPath := filepath.Join(t.TempDir(), "copy")
		dst, err := unix.Open(dstPath, unix.O_RDWR|unix.O_CREAT, 0o600)
		require.NoError(t, err)
		defer func() { _ = unix.Close(dst) }()

		want, err := os.ReadFile(f.at("files/small_100b"))
		require.NoError(t, err)

		n, err := unix.CopyFileRange(src, nil, dst, nil, len(want), 0)
		if errors.Is(err, unix.EXDEV) || errors.Is(err, unix.EOPNOTSUPP) {
			t.Skip("copy_file_range is not offered across these filesystems")
		}
		require.NoError(t, err)
		require.Equal(t, len(want), n)

		got, err := os.ReadFile(dstPath)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	t.Run("FsyncOnReadOnlyFileSucceeds", func(t *testing.T) {
		t.Parallel()
		fd, err := unix.Open(f.at("files/small_100b"), unix.O_RDONLY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(fd) }()

		// Nothing is dirty, so this must be a no-op rather than an error.
		require.NoError(t, unix.Fsync(fd))
	})

	t.Run("FallocateRejected", func(t *testing.T) {
		t.Parallel()
		fd, err := unix.Open(f.at("files/small_100b"), unix.O_RDONLY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(fd) }()

		err = unix.Fallocate(fd, 0, 0, 4096)
		require.Error(t, err, "fallocate succeeded on a read-only mount")
	})
}

// roMountAllowsOtherUsers reports whether the FUSE mount was created with
// allow_other. Without it the kernel refuses every request from a uid other
// than the daemon's, before any mode bit is consulted.
func roMountAllowsOtherUsers(t *testing.T, mnt string) bool {
	t.Helper()

	mounts, err := os.ReadFile("/proc/self/mounts")
	require.NoError(t, err)
	for _, line := range strings.Split(string(mounts), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[1] != mnt {
			continue
		}
		for _, opt := range strings.Split(fields[3], ",") {
			if opt == "allow_other" {
				return true
			}
		}
		return false
	}
	return false
}

// roFaultIn reads into a destination buffer that is itself an mmap of a file on
// the same mount. Servicing the read then has to fault that page in, which
// issues a second request while the first is still in flight. A filesystem that
// serialises the two deadlocks, so every case here also serves as a hang
// detector.
func roFaultIn(t *testing.T, f *roFixture) {
	src := f.at("files/ten_blocks")
	backing := f.at("files/large_256k")

	withMappedBuffer := func(t *testing.T, size int, fn func(buf []byte)) {
		t.Helper()
		buf, unmap := roMmapFile(t, backing, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
		defer unmap()
		fn(buf)
	}

	// Everything below runs under a watchdog: a deadlock shows up as a test
	// that never returns, which would otherwise just stall CI.
	deadline := func(t *testing.T, fn func()) {
		t.Helper()
		done := make(chan struct{})
		go func() {
			defer close(done)
			fn()
		}()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatal("timed out; the read most likely deadlocked faulting in its own buffer")
		}
	}

	want, err := os.ReadFile(src)
	require.NoError(t, err)

	t.Run("ReadIntoMappedBuffer", func(t *testing.T) {
		t.Parallel()
		deadline(t, func() {
			fd, err := unix.Open(src, unix.O_RDONLY, 0)
			require.NoError(t, err)
			defer func() { _ = unix.Close(fd) }()

			withMappedBuffer(t, len(want), func(buf []byte) {
				n, err := unix.Pread(fd, buf, 0)
				require.NoError(t, err)
				require.Equal(t, len(want), n)
				require.Equal(t, want, buf[:n])
			})
		})
	})

	t.Run("ReadvIntoMappedBuffers", func(t *testing.T) {
		t.Parallel()
		deadline(t, func() {
			fd, err := unix.Open(src, unix.O_RDONLY, 0)
			require.NoError(t, err)
			defer func() { _ = unix.Close(fd) }()

			withMappedBuffer(t, len(want), func(buf []byte) {
				half := len(want) / 2
				n, err := unix.Preadv(fd, [][]byte{buf[:half], buf[half:]}, 0)
				require.NoError(t, err)
				require.Equal(t, len(want), n)
				require.Equal(t, want, buf[:n])
			})
		})
	})

	t.Run("DirectReadIntoMappedBuffer", func(t *testing.T) {
		t.Parallel()
		deadline(t, func() {
			fd, err := unix.Open(src, unix.O_RDONLY|unix.O_DIRECT, 0)
			if errors.Is(err, unix.EINVAL) {
				t.Skip("O_DIRECT is not offered here")
			}
			require.NoError(t, err)
			defer func() { _ = unix.Close(fd) }()

			// O_DIRECT needs an aligned buffer, and an mmap is page aligned.
			withMappedBuffer(t, len(want), func(buf []byte) {
				n, err := unix.Pread(fd, buf, 0)
				require.NoError(t, err)
				require.Equal(t, len(want), n)
				require.Equal(t, want, buf[:n])
			})
		})
	})

	t.Run("MappedBufferBackedByTheSameFile", func(t *testing.T) {
		t.Parallel()
		// The tightest case: source and destination are the same file, so the
		// fault lands on a page the read is already serving.
		deadline(t, func() {
			fd, err := unix.Open(src, unix.O_RDONLY, 0)
			require.NoError(t, err)
			defer func() { _ = unix.Close(fd) }()

			buf, unmap := roMmapFile(t, src, len(want), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
			defer unmap()

			n, err := unix.Pread(fd, buf, 0)
			require.NoError(t, err)
			require.Equal(t, len(want), n)
		})
	})
}

// roProcessView covers the syscalls a process uses to locate itself, which
// depend on the parent chain and on dentry names being reported correctly.
// cwdMu serializes every subtest that changes the process working directory.
// The per-config suites run in parallel and the cwd is process-global, so
// without this the GetcwdInsideMount instances of different build configs
// race: one config's chdir (or deferred restore, or unmount) corrupts what
// another config's getcwd observes.
var cwdMu sync.Mutex

func roProcessView(t *testing.T, f *roFixture) {
	t.Run("GetcwdInsideMount", func(t *testing.T) {
		// Not parallel: it changes the process working directory. cwdMu
		// additionally serializes it against the same subtest in other
		// parallel build configs.
		cwdMu.Lock()
		defer cwdMu.Unlock()

		rel := "dirs/a/b/c"
		saved, err := os.Getwd()
		require.NoError(t, err)
		defer func() { _ = os.Chdir(saved) }()

		require.NoError(t, os.Chdir(f.at(rel)))
		cwd, err := os.Getwd()
		require.NoError(t, err, "getcwd failed inside the mount")
		require.Equal(t, f.at(rel), cwd)

		require.NoError(t, os.Chdir(".."))
		cwd, err = os.Getwd()
		require.NoError(t, err)
		require.Equal(t, f.at("dirs/a/b"), cwd)
	})

	t.Run("ProcFdResolvesToPath", func(t *testing.T) {
		t.Parallel()
		path := f.at("files/small_100b")
		fd, err := unix.Open(path, unix.O_RDONLY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(fd) }()

		target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
		require.NoError(t, err)
		require.Equal(t, path, target, "/proc/self/fd should name the open file")
	})

	t.Run("FileHandleEitherWorksOrIsRefused", func(t *testing.T) {
		t.Parallel()
		// A filesystem with no export support must say so rather than hand back
		// a handle it cannot resolve.
		handle, mountID, err := unix.NameToHandleAt(unix.AT_FDCWD, f.at("files/small_100b"), 0)
		if err != nil {
			require.True(t,
				errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP) ||
					errors.Is(err, unix.EPERM) || errors.Is(err, unix.EINVAL),
				"name_to_handle_at failed with an unexpected error: %v", err)
			return
		}

		mountFd, err := unix.Open(f.mnt, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(mountFd) }()
		_ = mountID

		fd, err := unix.OpenByHandleAt(mountFd, handle, unix.O_RDONLY)
		if err != nil {
			require.True(t, errors.Is(err, unix.ESTALE) || errors.Is(err, unix.EOPNOTSUPP),
				"a handed-out handle failed to reopen: %v", err)
			return
		}
		defer func() { _ = unix.Close(fd) }()

		var viaHandle, viaPath unix.Stat_t
		require.NoError(t, unix.Fstat(fd, &viaHandle))
		require.NoError(t, unix.Stat(f.at("files/small_100b"), &viaPath))
		require.Equal(t, viaPath.Ino, viaHandle.Ino)
	})

	t.Run("OpenFileDescriptionLocks", func(t *testing.T) {
		t.Parallel()
		// OFD locks are what modern SQLite and systemd use; a read lock must be
		// available even though nothing can ever be written.
		fd, err := unix.Open(f.at("files/small_100b"), unix.O_RDONLY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(fd) }()

		lk := unix.Flock_t{Type: unix.F_RDLCK, Whence: unix.SEEK_SET, Len: 0}
		err = unix.FcntlFlock(uintptr(fd), unix.F_OFD_SETLK, &lk)
		if errors.Is(err, unix.EINVAL) {
			t.Skip("OFD locks are not offered here")
		}
		require.NoError(t, err)

		probe := unix.Flock_t{Type: unix.F_RDLCK, Whence: unix.SEEK_SET, Len: 0}
		require.NoError(t, unix.FcntlFlock(uintptr(fd), unix.F_OFD_GETLK, &probe))
		require.EqualValues(t, unix.F_UNLCK, probe.Type)
	})
}
