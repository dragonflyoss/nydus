package archive

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/containerd/continuity/fs"
	"github.com/stretchr/testify/require"
)

func tarEntryNames(t *testing.T, data []byte) []string {
	t.Helper()

	reader := tar.NewReader(bytes.NewReader(data))
	var names []string
	for {
		hdr, err := reader.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		names = append(names, hdr.Name)
	}
	sort.Strings(names)
	return names
}

func TestCopyBuffered(t *testing.T) {
	var buf bytes.Buffer
	written, err := copyBuffered(context.Background(), &buf, strings.NewReader("nydus"))
	require.NoError(t, err)
	require.EqualValues(t, 5, written)
	require.Equal(t, "nydus", buf.String())
}

func TestCopyBufferedCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var buf bytes.Buffer
	written, err := copyBuffered(ctx, &buf, strings.NewReader("nydus"))
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, written)
	require.Empty(t, buf.String())
}

func TestHandleChangeDeleteWritesWhiteout(t *testing.T) {
	var buf bytes.Buffer
	sourceDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(sourceDir, "dir"), 0o755))
	cw := NewChangeWriter(&buf, sourceDir)
	require.NoError(t, cw.HandleChange(fs.ChangeKindDelete, "/dir/file.txt", nil, nil))
	require.NoError(t, cw.Close())

	require.Equal(t, []string{"dir/", "dir/.wh.file.txt"}, tarEntryNames(t, buf.Bytes()))
}

func TestHandleChangeAddRegularFileIncludesParents(t *testing.T) {
	sourceDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(sourceDir, "sub"), 0o755))
	filePath := filepath.Join(sourceDir, "sub", "file.txt")
	require.NoError(t, os.WriteFile(filePath, []byte("payload"), 0o644))

	info, err := os.Stat(filePath)
	require.NoError(t, err)

	var buf bytes.Buffer
	cw := NewChangeWriter(&buf, sourceDir)
	require.NoError(t, cw.HandleChange(fs.ChangeKindAdd, "/sub/file.txt", info, nil))
	require.NoError(t, cw.Close())

	require.Equal(t, []string{"sub/", "sub/file.txt"}, tarEntryNames(t, buf.Bytes()))
}

func TestHandleChangeUnmodifiedRegularFileSkipped(t *testing.T) {
	sourceDir := t.TempDir()
	filePath := filepath.Join(sourceDir, "plain.txt")
	require.NoError(t, os.WriteFile(filePath, []byte("payload"), 0o644))

	info, err := os.Stat(filePath)
	require.NoError(t, err)

	var buf bytes.Buffer
	cw := NewChangeWriter(&buf, sourceDir)
	require.NoError(t, cw.HandleChange(fs.ChangeKindUnmodified, "/plain.txt", info, nil))
	require.NoError(t, cw.Close())
	require.Empty(t, tarEntryNames(t, buf.Bytes()))
}
