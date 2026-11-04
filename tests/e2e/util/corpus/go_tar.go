package corpus

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

	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
)

// ObscuredSuffix marks the archives newer Go toolchains store base64
// encoded.
const ObscuredSuffix = ".base64"

// GoTarHugeArchives are the archives of Go's archive/tar corpus that expand
// to gigabytes of sparse data, kept out of the default suites.
var GoTarHugeArchives = []string{"gnu-sparse-big.tar", "pax-sparse-big.tar"}

// GoTarTestdata locates Go's archive/tar corpus: NYDUS_E2E_GO_TAR_TESTDATA,
// else the testdata of the Go toolchain on PATH.
func GoTarTestdata(t testing.TB) string {
	t.Helper()
	if dir := os.Getenv("NYDUS_E2E_GO_TAR_TESTDATA"); dir != "" {
		return dir
	}

	goBin := env.LookPath(t, "go")
	goroot, err := exec.Command(goBin, "env", "GOROOT").Output()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	dir := filepath.Join(strings.TrimSpace(string(goroot)), "src", "archive", "tar", "testdata")
	_, err = os.Stat(dir)
	if err != nil {
		env.Skipf(t, "Go archive/tar testdata: %v (set NYDUS_E2E_GO_TAR_TESTDATA)", err)
	}

	return dir
}

// GoTarArchive returns the path of the named corpus archive, which newer Go
// toolchains store obscured.
func GoTarArchive(testdata, name string) string {
	path := filepath.Join(testdata, name)
	if _, err := os.Stat(path); err == nil {
		return path
	}

	return path + ObscuredSuffix
}

// ReadGoTarArchive returns the archive at path, decoded and decompressed
// the way Go's own tests read it.
func ReadGoTarArchive(t testing.TB, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	if name, ok := strings.CutSuffix(path, ObscuredSuffix); ok {
		data, err = io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(data)))
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		path = name
	}

	if strings.HasSuffix(path, ".bz2") {
		data, err = io.ReadAll(bzip2.NewReader(bytes.NewReader(data)))
		if !assert.NoError(t, err) {
			t.FailNow()
		}
	}

	return data
}
