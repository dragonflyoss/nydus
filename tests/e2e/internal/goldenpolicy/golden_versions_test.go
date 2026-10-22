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
	dirs, err := Versions(root, "", "", false)
	require.NoError(t, err)
	require.Empty(t, dirs, "first-release checkout deliberately has no historical fixtures")
	for _, tc := range []struct {
		required, supported string
		configured          bool
	}{{"1", "", false}, {"", "", true}, {"", "v3.0.0", false}, {"true", "", false}} {
		_, err := Versions(root, tc.required, tc.supported, tc.configured)
		require.Error(t, err)
	}
	version := filepath.Join(root, "v3.0.0")
	require.NoError(t, os.Mkdir(version, 0o755))
	_, err = Versions(root, "", "", false)
	require.Error(t, err, "partial fixture directory is not a golden version")
	require.NoError(t, os.WriteFile(filepath.Join(version, ManifestName), []byte("{}"), 0o644))
	dirs, err = Versions(root, "1", "v3.0.0", true)
	require.NoError(t, err)
	require.Equal(t, []string{version}, dirs)
}
