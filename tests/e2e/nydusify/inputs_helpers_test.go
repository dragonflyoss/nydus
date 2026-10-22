package nydusify

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/require"
)

func inputTree(t env.TB, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(data), 0o640))
		stamp := time.Unix(1700000000, 0)
		require.NoError(t, os.Chtimes(path, stamp, stamp))
	}
	return dir
}

func bootstrapEntries(t env.TB, img v1.Image) map[string][]byte {
	t.Helper()
	layers, err := img.Layers()
	require.NoError(t, err)
	require.NotEmpty(t, layers)
	r, err := layers[len(layers)-1].Compressed()
	require.NoError(t, err)
	defer func() { require.NoError(t, r.Close()) }()
	gz, err := gzip.NewReader(r)
	require.NoError(t, err)
	defer func() { require.NoError(t, gz.Close()) }()
	tr := tar.NewReader(gz)
	entries := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return entries
		}
		require.NoError(t, err)
		data, err := io.ReadAll(tr)
		require.NoError(t, err)
		entries[h.Name] = data
	}
}
