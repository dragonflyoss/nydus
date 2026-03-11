package tool

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
)

func TestMkMounts(t *testing.T) {
	require.Nil(t, mkMounts(nil))

	single := mkMounts([]string{"/layers/0"})
	require.Len(t, single, 1)
	require.Equal(t, "/layers/0", single[0].Source)
	require.Equal(t, "bind", single[0].Type)
	require.Equal(t, []string{"ro", "rbind"}, single[0].Options)

	multiple := mkMounts([]string{"/layers/1", "/layers/0"})
	require.Len(t, multiple, 1)
	require.Equal(t, "overlay", multiple[0].Type)
	require.Equal(t, []string{"lowerdir=/layers/1:/layers/0"}, multiple[0].Options)
}

func TestCheckImageType(t *testing.T) {
	require.Equal(t, "unknown", CheckImageType(&parser.Parsed{}))
	require.Equal(t, "oci", CheckImageType(&parser.Parsed{OCIImage: &parser.Image{}}))
	require.Equal(t, "nydus", CheckImageType(&parser.Parsed{NydusImage: &parser.Image{}}))
}

func TestImageMountErrors(t *testing.T) {
	workDir := t.TempDir()
	rootfsFile := filepath.Join(workDir, "rootfs-file")
	require.NoError(t, os.WriteFile(rootfsFile, []byte("x"), 0644))

	image := &Image{Rootfs: rootfsFile}
	err := image.Mount()
	require.ErrorContains(t, err, "create rootfs dir")
}

func TestImageUmount(t *testing.T) {
	t.Run("missing rootfs", func(t *testing.T) {
		image := &Image{Rootfs: filepath.Join(t.TempDir(), "missing")}
		require.NoError(t, image.Umount())
	})

	t.Run("stat rootfs failed", func(t *testing.T) {
		workDir := t.TempDir()
		parentFile := filepath.Join(workDir, "file")
		require.NoError(t, os.WriteFile(parentFile, []byte("x"), 0644))

		image := &Image{Rootfs: filepath.Join(parentFile, "child")}
		err := image.Umount()
		require.ErrorContains(t, err, "stat rootfs")
	})

	t.Run("umount failed", func(t *testing.T) {
		rootfs := filepath.Join(t.TempDir(), "rootfs")
		require.NoError(t, os.MkdirAll(rootfs, 0755))

		image := &Image{Rootfs: rootfs}
		err := image.Umount()
		require.ErrorContains(t, err, "umount rootfs")
	})
}
