package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestAutomaticNoXattr(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root for FUSE and trusted xattr fixtures")
	}
	nydusBin := mustLookupExecutable(t, "nydus")

	t.Run("RemovedOption", func(t *testing.T) {
		output, err := exec.Command(nydusBin, "fuse", "--mountpoint", t.TempDir(), "--no-xattr").CombinedOutput()
		require.Error(t, err)
		require.Contains(t, string(output), "unexpected argument '--no-xattr'")
		output, err = exec.Command(nydusBin, "fuse", "--help").CombinedOutput()
		require.NoError(t, err)
		require.NotContains(t, string(output), "--no-xattr")
		require.NotContains(t, string(output), "NYDUS_FUSE_NO_XATTR")
	})

	for _, fixture := range []struct {
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
		t.Run(fixture.name, func(t *testing.T) {
			t.Setenv("NYDUS_FUSE_NO_XATTR", "true")
			root := t.TempDir()
			source := filepath.Join(root, "source")
			require.NoError(t, os.MkdirAll(filepath.Join(source, "nested"), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(source, "file"), []byte("payload"), 0o644))
			if fixture.key != "" {
				require.NoError(t, unix.Setxattr(filepath.Join(source, fixture.path), fixture.key, fixture.value, 0))
			}
			require.NoError(t, unix.Setxattr(source, "trusted.nydus.no_xattr", []byte("stale"), 0))
			blobDir := filepath.Join(root, "blobs")
			bootstrap := filepath.Join(root, "bootstrap")
			output, err := exec.Command(nydusBin, "build", "--blob-dir", blobDir, "--bootstrap", bootstrap, source).CombinedOutput()
			require.NoError(t, err, "%s", output)
			entries, err := os.ReadDir(blobDir)
			require.NoError(t, err)
			var blob string
			for _, entry := range entries {
				if sha256FilenamePattern.MatchString(entry.Name()) {
					require.Empty(t, blob)
					blob = filepath.Join(blobDir, entry.Name())
				}
			}
			require.NotEmpty(t, blob)

			for _, layout := range []string{"blob", "bootstrap"} {
				t.Run(layout, func(t *testing.T) {
					mnt := filepath.Join(root, "mnt-"+layout)
					if layout == "blob" {
						t.Cleanup(mountNydus(t, nydusBin, "", blob, mnt))
					} else {
						t.Cleanup(mountNydusBootstrap(t, nydusBin, bootstrap, blobDir, mnt))
					}
					data, err := os.ReadFile(filepath.Join(mnt, "file"))
					require.NoError(t, err)
					require.Equal(t, []byte("payload"), data)
					for attempt := 0; attempt < 2; attempt++ {
						if fixture.key == "" {
							_, err = unix.Getxattr(filepath.Join(mnt, "file"), "user.absent", nil)
							require.ErrorIs(t, err, unix.EOPNOTSUPP)
							_, err = unix.Listxattr(mnt, nil)
							require.ErrorIs(t, err, unix.EOPNOTSUPP)
						} else {
							require.Equal(t, fixture.value, roGetXattr(t, filepath.Join(mnt, fixture.path), fixture.key))
							require.Contains(t, roListXattr(t, filepath.Join(mnt, fixture.path)), fixture.key)
							_, err = unix.Getxattr(mnt, "trusted.nydus.no_xattr", nil)
							require.ErrorIs(t, err, unix.ENODATA)
							require.NotContains(t, roListXattr(t, mnt), "trusted.nydus.no_xattr")
						}
					}
				})
			}
		})
	}
}
