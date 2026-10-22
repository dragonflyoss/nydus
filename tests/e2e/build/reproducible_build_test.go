package build

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestReproducibleBuild pins the build against the inputs that historically
// leak into an image: the wall clock, the order the source filesystem reports
// entries in, and the paths the build runs under. Two builds that agree here
// produce the same layer digest, so a rebuild costs no registry storage.
func TestReproducibleBuild(t *testing.T) {
	t.Parallel()
	for _, name := range fixture.MergeLayouts {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			layout, err := fixture.LayoutByName(name)
			require.NoError(t, err)
			root := env.WorkDir(t)

			build := func(t *testing.T, src string) (bootstrap, blob string) {
				t.Helper()
				out, err := os.MkdirTemp(root, "out-")
				require.NoError(t, err)
				bootstrap = filepath.Join(out, "boot")
				blob, _ = fixture.BuildInto(t, filepath.Join(out, "blobs"), bootstrap, src, layout)
				return bootstrap, blob
			}
			sameImage := func(t *testing.T, a, b string) {
				t.Helper()
				aBoot, aBlob := build(t, a)
				bBoot, bBlob := build(t, b)
				require.Equal(t, fileSHA256(t, aBoot), fileSHA256(t, bBoot), "bootstrap differs")
				require.Equal(t, filepath.Base(aBlob), filepath.Base(bBlob), "blob digest differs")
			}

			t.Run("SameSourceTwice", func(t *testing.T) {
				src := filepath.Join(root, "same")
				stageReproducible(t, src, false)
				sameImage(t, src, src)
			})
			t.Run("CreationOrderDoesNotMatter", func(t *testing.T) {
				a, b := filepath.Join(root, "fwd"), filepath.Join(root, "rev")
				stageReproducible(t, a, false)
				stageReproducible(t, b, true)
				sameImage(t, a, b)
			})
			t.Run("SourcePathDoesNotMatter", func(t *testing.T) {
				a := filepath.Join(root, "p")
				b := filepath.Join(root, "a", "much", "longer", "path", "to", "the", "same", "tree")
				stageReproducible(t, a, false)
				stageReproducible(t, b, false)
				sameImage(t, a, b)
			})
			t.Run("EmptyTreeHasNoClock", func(t *testing.T) {
				// Nothing but a root leaves no mtime to anchor the epoch to;
				// reading the clock instead would change every build.
				a, b := filepath.Join(root, "empty-a"), filepath.Join(root, "empty-b")
				require.NoError(t, os.MkdirAll(a, 0o755))
				require.NoError(t, os.MkdirAll(b, 0o755))
				sameImage(t, a, b)
			})
			t.Run("RootMtimeDoesNotMatter", func(t *testing.T) {
				a, b := filepath.Join(root, "rm-a"), filepath.Join(root, "rm-b")
				stageReproducible(t, a, false)
				stageReproducible(t, b, false)
				for dir, when := range map[string]time.Time{
					a: time.Date(2021, 6, 1, 0, 0, 0, 0, time.UTC),
					b: time.Date(2024, 11, 30, 0, 0, 0, 0, time.UTC),
				} {
					ts := unix.NsecToTimespec(when.UnixNano())
					require.NoError(t, unix.UtimesNanoAt(unix.AT_FDCWD, dir, []unix.Timespec{ts, ts}, 0))
				}
				sameImage(t, a, b)
			})
			t.Run("MergeIsStable", func(t *testing.T) {
				l1, l2 := filepath.Join(root, "l1"), filepath.Join(root, "l2")
				stageReproducible(t, l1, false)
				stageReproducible(t, l2, true)
				_, blob1 := build(t, l1)
				_, blob2 := build(t, l2)
				first, second := filepath.Join(root, "merged-a"), filepath.Join(root, "merged-b")
				fixture.Run(t, env.Nydus(t), "merge", "--bootstrap", first, blob1, blob2)
				fixture.Run(t, env.Nydus(t), "merge", "--bootstrap", second, blob1, blob2)
				require.Equal(t, fileSHA256(t, first), fileSHA256(t, second), "merged bootstrap differs")
			})
		})
	}
}

// stageReproducible creates a tree with one of everything the builder has to
// order (entries, hardlinks, xattrs), in forward or reverse creation order,
// under a fixed timestamp so only the ordering varies.
func stageReproducible(t *testing.T, dir string, reverse bool) {
	t.Helper()
	env.RequireRoot(t)
	d := filepath.Join(dir, "d")
	require.NoError(t, os.MkdirAll(d, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(d, "base"), []byte("payload"), 0o644))
	require.NoError(t, os.Symlink("base", filepath.Join(d, "link")))

	names := make([]int, 24)
	for i := range names {
		names[i] = i
		if reverse {
			names[i] = len(names) - 1 - i
		}
	}
	for _, i := range names {
		require.NoError(t, os.WriteFile(filepath.Join(d, fmt.Sprintf("f%02d", i)), []byte(strings.Repeat("x", i*97)), 0o644))
		require.NoError(t, os.Link(filepath.Join(d, "base"), filepath.Join(d, fmt.Sprintf("h%02d", i))))
		require.NoError(t, unix.Setxattr(filepath.Join(d, "base"), fmt.Sprintf("user.a%02d", i), []byte("v"), 0))
	}

	ts := unix.NsecToTimespec(time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	require.NoError(t, filepath.WalkDir(dir, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return unix.UtimesNanoAt(unix.AT_FDCWD, p, []unix.Timespec{ts, ts}, unix.AT_SYMLINK_NOFOLLOW)
	}))
}
