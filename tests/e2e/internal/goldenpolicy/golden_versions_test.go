package goldenpolicy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGoldenVersions(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dirs, err := Versions(root, "", false, false)
	require.NoError(t, err)
	require.Empty(t, dirs, "first-release checkout deliberately has no historical fixtures")
	for _, tc := range []struct {
		supported            string
		required, configured bool
	}{{"", true, false}, {"", false, true}, {"v3.0.0", false, false}} {
		_, err := Versions(root, tc.supported, tc.required, tc.configured)
		require.Error(t, err)
	}
	version := filepath.Join(root, "v3.0.0")
	require.NoError(t, os.Mkdir(version, 0o755))
	_, err = Versions(root, "", false, false)
	require.Error(t, err, "partial fixture directory is not a golden version")
	require.NoError(t, os.WriteFile(filepath.Join(version, ManifestName), []byte("{}"), 0o644))
	dirs, err = Versions(root, "v3.0.0", true, true)
	require.NoError(t, err)
	require.Equal(t, []string{version}, dirs)
}
