//go:build manual

package hugetar

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// goTarTestdata locates Go's archive/tar corpus: GO_TAR_TESTDATA, else the
// testdata of the Go toolchain on PATH.
func goTarTestdata(t *testing.T) string {
	t.Helper()
	if dir := os.Getenv("GO_TAR_TESTDATA"); dir != "" {
		return dir
	}
	goBin := env.RequireTool(t, "go")
	goroot, err := exec.Command(goBin, "env", "GOROOT").Output()
	require.NoError(t, err, "go env GOROOT")
	dir := filepath.Join(strings.TrimSpace(string(goroot)), "src", "archive", "tar", "testdata")
	_, err = os.Stat(dir)
	env.Require(t, err == nil, "Go archive/tar testdata: %v (set GO_TAR_TESTDATA)", err)
	return dir
}

// obscuredSuffix marks corpus archives newer Go toolchains store base64
// encoded so they read as text.
const obscuredSuffix = ".base64"

// corpusArchive returns the path of the named corpus archive, which newer Go
// toolchains store obscured.
func corpusArchive(testdata, name string) string {
	path := filepath.Join(testdata, name)
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return path + obscuredSuffix
}

// readCorpusArchive returns the archive at path, decoded if obscured.
func readCorpusArchive(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	if strings.HasSuffix(path, obscuredSuffix) {
		data, err = io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(data)))
		require.NoError(t, err)
	}
	return data
}

// packLayer streams r through `nydus build --source-type tar` into blob,
// with the arguments nydusify passes.
func packLayer(t *testing.T, r io.Reader, blob string) error {
	t.Helper()
	cmd := exec.Command(env.Nydus(t), "build", "/dev/stdin", "--source-type", "tar", "--blob", blob,
		"--chunk-size", "2097152", "--compressor", "zstd", "--log-level", "warn")
	cmd.Stdin = r
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nydus build: %w: %s", err, stderr.Bytes())
	}
	return nil
}

// compareStreamed checks every regular file of the archive against the
// mount block by block as Go reads it, reading the mount only where Go
// yields data and at every 1024th zero block.
func compareStreamed(t *testing.T, data []byte, mnt string) {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(data))
	want, got := make([]byte, 1<<20), make([]byte, 1<<20)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return
		}
		require.NoError(t, err)
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeGNUSparse {
			continue
		}
		// Rooting the name first clamps ".." the way Apply does.
		compareStreamedFile(t, tr, filepath.Join(mnt, filepath.Join("/", hdr.Name)), hdr, want, got)
	}
}

// compareStreamedFile checks one member against the mounted file at path,
// closing it before the mount is torn down even when a check fails.
func compareStreamedFile(t *testing.T, tr *tar.Reader, path string, hdr *tar.Header, want, got []byte) {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	require.NoError(t, unix.Fstat(int(f.Fd()), &st))
	require.Equal(t, hdr.Size, st.Size, "%s: size", hdr.Name)
	for off, block := int64(0), 0; ; off, block = off+int64(len(want)), block+1 {
		n, err := io.ReadFull(tr, want)
		if n == 0 {
			return
		}
		if bytes.Count(want[:n], []byte{0}) != n || block%1024 == 0 {
			m, rerr := f.ReadAt(got[:n], off)
			if !errors.Is(rerr, io.EOF) {
				require.NoError(t, rerr)
			}
			require.Equal(t, n, m, "%s: short read at %d", hdr.Name, off)
			require.True(t, bytes.Equal(want[:n], got[:n]), "%s: content differs at %d", hdr.Name, off)
		}
		if err != nil {
			return
		}
	}
}
