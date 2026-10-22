package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// TestReproducibleBuild pins the build against the inputs that historically
// leak into an image: the wall clock, the order the source filesystem happens
// to report things in, and the paths the build ran under. Two builds that agree
// here produce the same layer digest, so a rebuild costs no registry storage.
func TestReproducibleBuild(t *testing.T) {
	util.SkipUnlessRoot(t, "building the corpus")

	workDir := t.TempDir()
	build := func(t *testing.T, source string) (bootstrap string, blob string) {
		t.Helper()
		outDir, err := os.MkdirTemp(workDir, "out-")
		assert.NoError(t, err)
		bootstrap = filepath.Join(outDir, "boot")
		blob = util.BuildImage(t, nydusBin, bootstrap, filepath.Join(outDir, "blobs"), source, 4096)
		return bootstrap, blob
	}

	sameImage := func(t *testing.T, sourceA, sourceB string) {
		t.Helper()
		bootstrapA, blobA := build(t, sourceA)
		bootstrapB, blobB := build(t, sourceB)
		assert.Equal(t, util.Sha256File(t, bootstrapA), util.Sha256File(t, bootstrapB), "bootstrap differs")
		assert.Equal(t, filepath.Base(blobA), filepath.Base(blobB), "blob digest differs")
	}

	// A tree with one of everything the builder has to encode.
	stage := func(t *testing.T, dir string, reverse bool) {
		assert.NoError(t, os.MkdirAll(filepath.Join(dir, "d"), 0o755))
		assert.NoError(t, os.WriteFile(filepath.Join(dir, "d", "base"), []byte("payload"), 0o644))
		assert.NoError(t, os.Symlink("base", filepath.Join(dir, "d", "link")))

		// Create the files, hardlinks and xattrs in forward or reverse order.
		indices := make([]int, 24)
		for i := range indices {
			indices[i] = i
		}
		if reverse {
			slices.Reverse(indices)
		}
		for _, i := range indices {
			path := filepath.Join(dir, "d", fmt.Sprintf("f%02d", i))
			assert.NoError(t, os.WriteFile(path, []byte(strings.Repeat("x", i*97)), 0o644))
			assert.NoError(t, os.Link(filepath.Join(dir, "d", "base"),
				filepath.Join(dir, "d", fmt.Sprintf("h%02d", i))))
			assert.NoError(t, unix.Setxattr(filepath.Join(dir, "d", "base"),
				fmt.Sprintf("user.a%02d", i), []byte("v"), 0))
		}

		// A fixed timestamp everywhere, so only the ordering varies.
		assert.NoError(t, filepath.WalkDir(dir, func(path string, _ os.DirEntry, err error) error {
			if err != nil {
				return err
			}

			timestamp := unix.NsecToTimespec(time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
			return unix.UtimesNanoAt(unix.AT_FDCWD, path, []unix.Timespec{timestamp, timestamp}, unix.AT_SYMLINK_NOFOLLOW)
		}))
	}

	t.Run("same source twice", func(t *testing.T) {
		source := filepath.Join(workDir, "same")
		stage(t, source, false)
		sameImage(t, source, source)
	})

	t.Run("creation order does not matter", func(t *testing.T) {
		a := filepath.Join(workDir, "fwd")
		b := filepath.Join(workDir, "rev")
		stage(t, a, false)
		stage(t, b, true)
		sameImage(t, a, b)
	})

	t.Run("source path does not matter", func(t *testing.T) {
		a := filepath.Join(workDir, "p")
		b := filepath.Join(workDir, "a", "much", "longer", "path", "to", "the", "same", "tree")
		stage(t, a, false)
		stage(t, b, false)
		sameImage(t, a, b)
	})

	t.Run("empty tree has no clock", func(t *testing.T) {
		// Nothing but a root means no mtime to anchor the epoch to; reading the
		// clock there would change the image on every build.
		assert := assert.New(t)
		a := filepath.Join(workDir, "empty-a")
		b := filepath.Join(workDir, "empty-b")
		assert.NoError(os.MkdirAll(a, 0o755))
		assert.NoError(os.MkdirAll(b, 0o755))
		sameImage(t, a, b)
	})

	t.Run("root mtime does not matter", func(t *testing.T) {
		a := filepath.Join(workDir, "rm-a")
		b := filepath.Join(workDir, "rm-b")
		stage(t, a, false)
		stage(t, b, false)
		for dir, when := range map[string]time.Time{
			a: time.Date(2021, 6, 1, 0, 0, 0, 0, time.UTC),
			b: time.Date(2024, 11, 30, 0, 0, 0, 0, time.UTC),
		} {
			timestamp := unix.NsecToTimespec(when.UnixNano())
			assert.NoError(t, unix.UtimesNanoAt(unix.AT_FDCWD, dir, []unix.Timespec{timestamp, timestamp}, 0))
		}
		sameImage(t, a, b)
	})

	t.Run("merge is stable", func(t *testing.T) {
		layer1 := filepath.Join(workDir, "l1")
		layer2 := filepath.Join(workDir, "l2")
		stage(t, layer1, false)
		stage(t, layer2, true)
		_, blob1 := build(t, layer1)
		_, blob2 := build(t, layer2)

		mergedA := filepath.Join(workDir, "merged-a")
		mergedB := filepath.Join(workDir, "merged-b")
		util.MergeBootstrap(t, nydusBin, mergedA, blob1, blob2)
		util.MergeBootstrap(t, nydusBin, mergedB, blob1, blob2)
		assert.Equal(t, util.Sha256File(t, mergedA), util.Sha256File(t, mergedB), "merged bootstrap differs")
	})
}

// TestBuildExclude builds an image with `--exclude` and checks the excluded
// entries are in neither the tree nor the blob while their siblings are.
func TestBuildExclude(t *testing.T) {
	util.SkipUnlessRoot(t, "mounting FUSE")
	assert := assert.New(t)
	workDir := t.TempDir()
	source := filepath.Join(workDir, "source")
	blobDir := filepath.Join(workDir, "blobs")
	bootstrap := filepath.Join(workDir, "image.boot")
	for _, dir := range []string{"keep", "drop", "drop/nested"} {
		assert.NoError(os.MkdirAll(filepath.Join(source, dir), 0o755))
	}
	util.WriteRandomFile(t, filepath.Join(source, "keep", "a.bin"), 256<<10)
	util.WriteRandomFile(t, filepath.Join(source, "drop", "b.bin"), 256<<10)
	util.WriteRandomFile(t, filepath.Join(source, "drop", "nested", "c.bin"), 256<<10)
	util.WriteRandomFile(t, filepath.Join(source, "cache.tmp"), 256<<10)

	blob := util.BuildImage(t, nydusBin, bootstrap, blobDir, source, 1<<20,
		"--exclude", filepath.Join(source, "drop"),
		"--exclude", filepath.Join(source, "cache.tmp"))
	info, err := os.Stat(blob)
	assert.NoError(err)
	assert.Less(info.Size(), int64(600<<10), "the excluded data is still in the blob")

	mountpoint := filepath.Join(workDir, "mnt")
	t.Cleanup(util.MountNydusBootstrap(t, nydusBin, bootstrap, blobDir, "", mountpoint))
	assert.FileExists(filepath.Join(mountpoint, "keep", "a.bin"))
	assert.NoFileExists(filepath.Join(mountpoint, "drop"))
	assert.NoFileExists(filepath.Join(mountpoint, "cache.tmp"))
	assert.Equal(util.Sha256File(t, filepath.Join(source, "keep", "a.bin")), util.Sha256File(t, filepath.Join(mountpoint, "keep", "a.bin")))
}
