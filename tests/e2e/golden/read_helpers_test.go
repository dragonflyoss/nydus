package golden

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/goldenpolicy"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/stretchr/testify/require"
)

// testdata holds one directory per released version, written by
// cmd/golden-gen.
const testdata = "testdata"

// versionDirs returns the version directories in testdata: those with a
// manifest. Anything else (the README) is ignored.
func versionDirs(t *testing.T) []string {
	t.Helper()
	root := os.Getenv("NYDUS_E2E_GOLDEN_DIR")
	if root == "" {
		root = testdata
	}
	dirs, err := goldenpolicy.Versions(root, os.Getenv("NYDUS_E2E_GOLDEN_REQUIRED"),
		os.Getenv("NYDUS_E2E_GOLDEN_VERSIONS"), os.Getenv("NYDUS_E2E_GOLDEN_DIR") != "")
	require.NoError(t, err)
	return dirs
}

// copyVersion copies a version directory into the test's work directory,
// so nothing a reader writes can touch the committed images.
func copyVersion(t *testing.T, dir string) string {
	t.Helper()
	dst := filepath.Join(env.WorkDir(t), filepath.Base(dir))
	fixture.Run(t, "cp", "-a", dir, dst)
	return dst
}

// image turns a manifest image under the version directory dir into the
// fixture the mount adapters serve.
func image(dir string, m *Manifest, img Image) fixture.Image {
	var blobs []string
	for _, b := range img.Blobs {
		blobs = append(blobs, filepath.Join(dir, b))
	}
	return fixture.Image{
		Name:      img.Name,
		Layout:    fixture.Layout{Name: img.Layout, Args: img.Args, Native: img.Native, Tar: img.Tar},
		Corpus:    m.Version + "/" + img.Tree,
		Bootstrap: filepath.Join(dir, img.Bootstrap),
		BlobDir:   filepath.Join(dir, img.BlobDir),
		Blobs:     blobs,
		Merged:    img.Merged,
		Want:      m.Trees[img.Tree],
	}
}

// readImage runs every read path of the nydus under test over img: `check`
// of each blob and of the bootstrap, FUSE mounts of the blob, of the
// bootstrap with a cold cache and with a warm one, a fileio mount, and
// `export`. Each must reproduce the image's tree exactly.
func readImage(t *testing.T, img fixture.Image) {
	t.Helper()
	nydus := env.Nydus(t)

	t.Run("Check", func(t *testing.T) {
		t.Parallel()
		for _, blob := range img.Blobs {
			fixture.Run(t, nydus, "check", "--blob", blob)
		}
		fixture.Run(t, nydus, "check", "--bootstrap", img.Bootstrap, "--blob-dir", img.BlobDir)
	})

	for _, mode := range mount.Modes {
		if mode == mount.Blob && img.Merged {
			continue
		}
		t.Run("FUSE/"+string(mode), func(t *testing.T) {
			t.Parallel()
			m := mount.Mount(t, mount.FUSE{}, img, mount.Options{Mode: mode})
			oracle.VerifyMount(t, m.Root, img.Want, img.Compare())
		})
	}

	t.Run("Fileio", func(t *testing.T) {
		t.Parallel()
		m := mount.Mount(t, mount.Fileio{}, img, mount.Options{Mode: mount.Cold})
		oracle.VerifyMount(t, m.Root, img.Want, img.Compare())
	})

	if !img.Merged {
		t.Run("Export", func(t *testing.T) {
			t.Parallel()
			oracle.VerifyExport(t, nydus, img.Blob(), img.Want)
		})
	}
}

// nydusVersion returns the `nydus --version` line of bin, for the log.
func nydusVersion(bin string) string {
	out, err := exec.Command(bin, "--version").CombinedOutput()
	if err != nil {
		return "unknown version: " + err.Error()
	}
	return strings.TrimSpace(string(out))
}
