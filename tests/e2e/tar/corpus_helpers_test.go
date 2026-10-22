package tar

import (
	"bytes"
	"compress/bzip2"
	"encoding/base64"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/stretchr/testify/require"
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
// encoded, as internal/obscuretestdata does, so they read as text.
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

// readCorpusArchive returns the archive at path, decoded and decompressed
// the way Go's own tests read it.
func readCorpusArchive(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	if name, ok := strings.CutSuffix(path, obscuredSuffix); ok {
		data, err = io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(data)))
		require.NoError(t, err)
		path = name
	}
	if strings.HasSuffix(path, ".bz2") {
		data, err = io.ReadAll(bzip2.NewReader(bytes.NewReader(data)))
		require.NoError(t, err)
	}
	return data
}
