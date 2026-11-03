package compatibility

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
)

func TestRead(t *testing.T) {
	t.Parallel()
	if *update {
		updateImages(t)
		return
	}

	dirs := versionDirs(t)
	if len(dirs) == 0 {
		t.Log("no versions in testdata yet; the first is committed at the v3.0.0 release")
		return
	}

	env.RequireRoot(t)
	t.Logf("reader: %s", nydusVersion(t, env.Nydus(t)))

	for _, dir := range dirs {
		m, err := loadManifest(dir)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		t.Run(m.Version, func(t *testing.T) {
			t.Parallel()
			t.Logf("built by: %s", m.Builder)
			copied := copyVersion(t, dir)

			for _, img := range m.Images {
				t.Run(img.Name, func(t *testing.T) {
					t.Parallel()
					runReadCases(t, m.toFixture(copied, img))
				})
			}
		})
	}
}

func TestVersions(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dirs, err := versions(root, "", false, false)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.Empty(t, dirs) {
		t.FailNow()
	}

	for _, tc := range []struct {
		name                 string
		supported            string
		required, configured bool
	}{
		{name: "RequiredWithoutVersions", required: true},
		{name: "ConfiguredWithoutVersions", configured: true},
		{name: "SupportedVersionMissing", supported: "v3.0.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := versions(root, tc.supported, tc.required, tc.configured)
			assert.Error(t, err)
		})
	}

	version := filepath.Join(root, "v3.0.0")
	if !assert.NoError(t, os.Mkdir(version, 0o755)) {
		t.FailNow()
	}

	_, err = versions(root, "", false, false)
	if !assert.Error(t, err) {
		t.FailNow()
	}
	if !assert.NoError(t, os.WriteFile(filepath.Join(version, manifestName), []byte("{}"), 0o644)) {
		t.FailNow()
	}

	dirs, err = versions(root, "v3.0.0", true, true)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.Equal(t, []string{version}, dirs)
}

func copyVersion(t *testing.T, dir string) string {
	t.Helper()
	dst := filepath.Join(env.WorkDir(t), filepath.Base(dir))
	env.Run(t, "cp", "-a", dir, dst)

	return dst
}

func runReadCases(t *testing.T, img fixture.Image) {
	t.Helper()
	nydus := env.Nydus(t)

	t.Run("Check", func(t *testing.T) {
		t.Parallel()
		for _, blob := range img.Blobs {
			env.Run(t, nydus, "check", "--blob", blob)
		}

		env.Run(t, nydus, "check", "--bootstrap", img.Bootstrap, "--blob-dir", img.BlobDir)
	})

	for _, mode := range mount.Modes {
		if mode == mount.Blob && img.Merged {
			continue
		}

		t.Run("FUSE/"+string(mode), func(t *testing.T) {
			t.Parallel()
			m := mount.Mount(t, mount.FUSE{}, img, mount.Options{Mode: mode})
			fstest.VerifyMount(t, m.Root, img.Want, img.Compare())
		})
	}

	t.Run("Fileio", func(t *testing.T) {
		t.Parallel()
		m := mount.Mount(t, mount.Fileio{}, img, mount.Options{Mode: mount.Cold})
		fstest.VerifyMount(t, m.Root, img.Want, img.Compare())
	})

	if !img.Merged {
		t.Run("Export", func(t *testing.T) {
			t.Parallel()
			fstest.VerifyExport(t, nydus, img.Blob(t), img.Want)
		})
	}
}

func nydusVersion(t testing.TB, bin string) string {
	t.Helper()
	return strings.TrimSpace(env.Run(t, bin, "--version"))
}

func versionDirs(t *testing.T) []string {
	t.Helper()
	root, configured := imageRoot()
	dirs, err := versions(root, os.Getenv("NYDUS_E2E_COMPATIBILITY_VERSIONS"), env.Strict(), configured)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return dirs
}

func versions(root, supported string, required, configured bool) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	var dirs []string

	for _, e := range entries {
		dir := filepath.Join(root, e.Name())

		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			if _, err := os.Stat(filepath.Join(dir, manifestName)); err != nil {
				return nil, fmt.Errorf("version directory %s has no manifest: %w", dir, err)
			}

			dirs = append(dirs, dir)
		}
	}

	slices.Sort(dirs)

	if len(dirs) == 0 && (required || configured) {
		return nil, fmt.Errorf("compatibility images were required but %s has no versions", root)
	}

	for _, version := range strings.Fields(supported) {
		if !slices.ContainsFunc(dirs, func(dir string) bool { return filepath.Base(dir) == version }) {
			return nil, fmt.Errorf("supported version %s is missing from %s", version, root)
		}
	}

	return dirs, nil
}
