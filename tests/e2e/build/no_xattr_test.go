package build

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestNoXattr checks that xattr support needs no switch: an image without
// xattrs answers EOPNOTSUPP (so the kernel stops asking), any other image
// serves its xattrs, and the builder's internal trusted.nydus.no_xattr
// marker on the root is neither honoured from the source nor exposed.
func TestNoXattr(t *testing.T) {
	t.Parallel()
	nydus := env.Nydus(t)

	t.Run("RemovedOption", func(t *testing.T) {
		t.Parallel()
		out, err := exec.Command(nydus, "fuse", "--mountpoint", t.TempDir(), "--no-xattr").CombinedOutput()
		require.Error(t, err)
		require.Contains(t, string(out), "unexpected argument '--no-xattr'")
		// clap lists every environment binding in the help, so this also
		// proves NYDUS_FUSE_NO_XATTR is not read.
		out, err = exec.Command(nydus, "fuse", "--help").CombinedOutput()
		require.NoError(t, err, "%s", out)
		require.NotContains(t, string(out), "--no-xattr")
		require.NotContains(t, string(out), "NYDUS_FUSE_NO_XATTR")
	})

	layout, err := fixture.LayoutByName("zstd")
	require.NoError(t, err)
	for _, tc := range []struct {
		name  string
		path  string
		key   string
		value []byte
	}{
		{name: "None"},
		{name: "File", path: "file", key: "user.test", value: []byte("value")},
		{name: "EmptyValue", path: "file", key: "user.empty", value: []byte{}},
		{name: "Root", path: ".", key: "user.root", value: []byte("root")},
		{name: "Directory", path: "nested", key: "user.dir", value: []byte("directory")},
		{name: "NonRootInternalName", path: "file", key: "trusted.nydus.no_xattr", value: []byte("1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env.RequireRoot(t)
			dir := env.WorkDir(t)
			src := filepath.Join(dir, "source")
			require.NoError(t, os.MkdirAll(filepath.Join(src, "nested"), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(src, "file"), []byte("payload"), 0o644))
			if tc.key != "" {
				require.NoError(t, unix.Setxattr(filepath.Join(src, tc.path), tc.key, tc.value, 0))
			}
			// A stale marker in the source must not switch xattrs off.
			require.NoError(t, unix.Setxattr(src, "trusted.nydus.no_xattr", []byte("stale"), 0))

			img := fixture.Image{
				Name:      tc.name,
				Layout:    layout,
				Bootstrap: filepath.Join(dir, "bootstrap"),
				BlobDir:   filepath.Join(dir, "blobs"),
				Source:    src,
			}
			blob, _ := fixture.BuildInto(t, img.BlobDir, img.Bootstrap, src, layout)
			img.Blobs = []string{blob}

			for _, mode := range []mount.Mode{mount.Blob, mount.Cold} {
				t.Run(string(mode), func(t *testing.T) {
					m := mount.Mount(t, mount.FUSE{}, img, mount.Options{Mode: mode})
					data, err := os.ReadFile(m.Path("file"))
					require.NoError(t, err)
					require.Equal(t, []byte("payload"), data)
					// Twice: the answer must not depend on what was cached.
					for attempt := 0; attempt < 2; attempt++ {
						if tc.key == "" {
							_, err = unix.Lgetxattr(m.Path("file"), "user.absent", nil)
							require.ErrorIs(t, err, unix.EOPNOTSUPP)
							_, err = unix.Llistxattr(m.Root, nil)
							require.ErrorIs(t, err, unix.EOPNOTSUPP)
							continue
						}
						require.Equal(t, tc.value, oracle.GetXattr(t, m.Path(tc.path), tc.key))
						require.Contains(t, oracle.ListXattr(t, m.Path(tc.path)), tc.key)
						_, err = unix.Lgetxattr(m.Root, "trusted.nydus.no_xattr", nil)
						require.ErrorIs(t, err, unix.ENODATA)
						require.NotContains(t, oracle.ListXattr(t, m.Root), "trusted.nydus.no_xattr")
					}
				})
			}
		})
	}
}
