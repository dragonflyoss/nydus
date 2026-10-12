package tar

import (
	"archive/tar"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
	"github.com/dragonflyoss/nydus/tests/e2e"
	"github.com/stretchr/testify/require"
)

// goTarCorpusBudget bounds the bytes a corpus archive may expand to: the
// sparse samples declare tens of gigabytes that both the oracle and the
// image would materialize on disk.
const goTarCorpusBudget = 1 << 30

// tarLayout selects the blob layout a conversion builds; the zero value is
// nydusify's default.
type tarLayout struct {
	compressor string
	chunkSize  uint32
}

// TestGoTarCorpus converts every archive of Go's archive/tar test corpus
// through nydus build, the streaming layer conversion nydusify uses, and
// checks the FUSE-mounted result against the reference tree containerd
// applies from the same archive. Archives Go or the reference rejects must
// be rejected by the conversion too, never turned into an image.
func TestGoTarCorpus(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root: the reference tree restores ownership and device nodes")
	}
	t.Parallel()
	nydusBin := e2e.MustLookupExecutable(t, "nydus")
	testdata := goTarTestdata(t)
	archives, err := filepath.Glob(filepath.Join(testdata, "*.tar*"))
	require.NoError(t, err)
	require.NotEmpty(t, archives, "no archives in %s", testdata)

	for _, path := range archives {
		t.Run(strings.TrimSuffix(filepath.Base(path), obscuredSuffix), func(t *testing.T) {
			t.Parallel()
			checkTarConversion(t, nydusBin, readCorpusArchive(t, path), tarLayout{})
		})
	}
}

// checkTarConversion converts data through nydus build and asserts the mount
// reproduces the reference tree extractReference applies from it, or that
// the conversion fails cleanly when Go or the reference rejects the archive.
// data may be gzipped, which nydus build accepts too. It reports whether the
// archive was converted and compared rather than rejected.
func checkTarConversion(t *testing.T, nydusBin string, data []byte, layout tarLayout) bool {
	t.Helper()
	layer, goErr := gunzipLayer(data)
	var expanded int64
	if goErr == nil {
		expanded, goErr = scanGoTar(layer)
	}
	if goErr == nil && expanded > goTarCorpusBudget {
		t.Skipf("expands to %d bytes, over the %d-byte budget", expanded, goTarCorpusBudget)
	}

	work := t.TempDir()
	blob := filepath.Join(work, "layer.blob")
	packErr := packLayer(t, nydusBin, bytes.NewReader(data), blob, layout)
	if goErr != nil {
		requireRejected(t, packErr, "Go rejects the archive (%v)", goErr)
		return false
	}

	reference := filepath.Join(work, "reference")
	require.NoError(t, os.Mkdir(reference, 0o755))
	if err := extractReference(layer, reference); err != nil {
		if errors.Is(err, errTarUnsupported) {
			t.Skipf("no reference: %v", err)
		}
		requireRejected(t, packErr, "containerd rejects the archive (%v)", err)
		return false
	}
	require.NoError(t, packErr, "nydus build")

	mnt := filepath.Join(work, "mnt")
	defer e2e.MountNydus(t, nydusBin, "", blob, mnt)()
	e2e.DiffTree(t, reference, mnt, true)
	return true
}

// requireRejected asserts the builder refused the archive with an error
// exit, not a panic (exit 101) or a signal.
func requireRejected(t *testing.T, packErr error, format string, args ...any) {
	t.Helper()
	require.Error(t, packErr, append([]any{format + " but nydus build accepted it"}, args...)...)
	var exitErr *exec.ExitError
	if errors.As(packErr, &exitErr) {
		code := exitErr.ExitCode()
		require.True(t, code != 101 && code != -1,
			append([]any{format + " and the builder crashed: %v"}, append(args, packErr)...)...)
	}
}

// goTarTestdata locates the corpus: GO_TAR_TESTDATA, else the testdata of
// the Go toolchain on PATH.
func goTarTestdata(t *testing.T) string {
	t.Helper()
	if dir := os.Getenv("GO_TAR_TESTDATA"); dir != "" {
		return dir
	}
	goroot, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Skipf("go toolchain not found: %v", err)
	}
	dir := filepath.Join(strings.TrimSpace(string(goroot)), "src", "archive", "tar", "testdata")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("Go archive/tar testdata not found: %v", err)
	}
	return dir
}

// obscuredSuffix marks corpus archives newer Go toolchains store base64
// encoded, as internal/obscuretestdata does, so they read as text.
const obscuredSuffix = ".base64"

// corpusArchive returns the path of the named corpus archive, which newer Go
// toolchains store obscured.
func corpusArchive(t *testing.T, testdata, name string) string {
	t.Helper()
	path := filepath.Join(testdata, name)
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return path + obscuredSuffix
}

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

// scanGoTar reads the archive with Go's archive/tar, returning the bytes its
// entries declare and the first error Go reports. Past the budget, data is
// skipped rather than read, so truncation is still reported.
func scanGoTar(data []byte) (int64, error) {
	tr := tar.NewReader(bytes.NewReader(data))
	var expanded int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return expanded, nil
		}
		if err != nil {
			return expanded, err
		}
		expanded += hdr.Size
		if expanded > goTarCorpusBudget {
			continue
		}
		if _, err := io.Copy(io.Discard, tr); err != nil {
			return expanded, err
		}
	}
}

// gunzipLayer returns the tar inside a gzipped layer, or data itself.
func gunzipLayer(data []byte) ([]byte, error) {
	if !bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
		return data, nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(zr)
}

// packLayer streams r through `nydus build` into blob.
func packLayer(t *testing.T, nydusBin string, r io.Reader, blob string, layout tarLayout) error {
	t.Helper()
	return nydus.RunNydusBuild(context.Background(), nydus.BuildOption{
		BuilderPath: nydusBin,
		SourceDir:   "/dev/stdin",
		SourceType:  "tar",
		Stdin:       r,
		BlobPath:    blob,
		ChunkSize:   layout.chunkSize,
		Compressor:  layout.compressor,
	})
}
