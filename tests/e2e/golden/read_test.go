package golden

import (
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/stretchr/testify/require"
)

// TestRead reads the golden images of every released version in testdata
// with the nydus under test, so an on-disk format change a released
// version's images do not survive fails here. The images are built at each
// release by cmd/golden-gen. Before the first supported release an empty
// default testdata is deliberate; required/configured goldens may never be empty.
func TestRead(t *testing.T) {
	t.Parallel()
	dirs := versionDirs(t)
	if len(dirs) == 0 {
		t.Log("no golden versions in testdata yet; the first is committed at the v3.0.0 release")
		return
	}
	env.RequireRoot(t)
	t.Logf("reader: %s", nydusVersion(env.Nydus(t)))

	for _, dir := range dirs {
		m, err := Load(dir)
		require.NoError(t, err)
		t.Run(m.Version, func(t *testing.T) {
			t.Parallel()
			t.Logf("built by: %s", m.Builder)
			copied := copyVersion(t, dir)
			for _, img := range m.Images {
				t.Run(img.Name, func(t *testing.T) {
					t.Parallel()
					readImage(t, image(copied, m, img))
				})
			}
		})
	}
}
