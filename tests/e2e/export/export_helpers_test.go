// Package export tests `nydus export`: an image exports as the OCI layer it
// reproduces, and building that layer again is a fixed point.
package export

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/stretchr/testify/require"
)

var blobName = regexp.MustCompile(`^[0-9a-f]{64}$`)

// rebuild streams `nydus export` of blob into `nydus build --source-type tar`
// with layout's arguments, and returns the new image in a directory of its
// own.
func rebuild(t env.TB, blob string, layout fixture.Layout) fixture.Image {
	t.Helper()
	nydus := env.Nydus(t)
	dir := env.WorkDir(t)
	img := fixture.Image{
		Name:      layout.Name,
		Layout:    layout,
		Bootstrap: filepath.Join(dir, "image.bootstrap"),
		BlobDir:   filepath.Join(dir, "blobs"),
	}
	require.NoError(t, os.MkdirAll(img.BlobDir, 0o755))

	pr, pw, err := os.Pipe()
	require.NoError(t, err)
	var exportErr, buildOut bytes.Buffer
	export := exec.Command(nydus, "export", blob)
	export.Stdout, export.Stderr = pw, &exportErr
	args := append([]string{"build", "--blob-dir", img.BlobDir, "--bootstrap", img.Bootstrap}, layout.Args...)
	build := exec.Command(nydus, append(args, "--source-type", "tar", "/dev/stdin")...)
	build.Stdin, build.Stdout, build.Stderr = pr, &buildOut, &buildOut
	require.NoError(t, export.Start())
	if err := build.Start(); err != nil {
		_ = export.Process.Kill()
		_ = export.Wait()
		t.Fatalf("start nydus build: %v", err)
	}
	_ = pw.Close()
	_ = pr.Close()
	buildErr := build.Wait()
	if buildErr != nil {
		// Do not leave the exporter blocked on a pipe nobody reads.
		_ = export.Process.Kill()
	}
	exportWait := export.Wait()
	require.NoError(t, buildErr, "nydus build from the export of %s: %s", blob, buildOut.String())
	require.NoError(t, exportWait, "nydus export %s: %s", blob, exportErr.String())

	entries, err := os.ReadDir(img.BlobDir)
	require.NoError(t, err)
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
		if blobName.MatchString(entry.Name()) {
			img.Blobs = append(img.Blobs, filepath.Join(img.BlobDir, entry.Name()))
		}
	}
	require.Len(t, img.Blobs, 1, "build output %v", names)
	wantFiles := 1
	if !layout.Native {
		wantFiles = 2
		require.FileExists(t, img.Blob()+".blob.meta")
	}
	require.Len(t, names, wantFiles, "build output %v", names)
	require.Equal(t, filepath.Base(img.Blob()), fileSHA256(t, img.Blob()), "the blob is named by its SHA256")
	return img
}

func fileSHA256(t env.TB, path string) string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	h := sha256.New()
	_, err = io.Copy(h, f)
	require.NoError(t, err)
	return hex.EncodeToString(h.Sum(nil))
}
