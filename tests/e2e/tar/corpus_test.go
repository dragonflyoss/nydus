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
	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/stretchr/testify/assert"
)

// maxExpandedSize bounds the bytes a corpus archive may expand to: the
// sparse samples declare tens of gigabytes that both the oracle and the
// image would materialize on disk.
const maxExpandedSize = 1 << 30

// obscuredSuffix marks corpus archives newer Go toolchains store base64
// encoded, as internal/obscuretestdata does, so they read as text.
const obscuredSuffix = ".base64"

// blobLayout selects the blob layout a conversion builds; the zero value is
// nydusify's default.
type blobLayout struct {
	// compressor is the blob compressor, empty for the default.
	compressor string

	// chunkSize is the chunk size in bytes, zero for the default.
	chunkSize uint32
}

// TestGoTarCorpus converts every archive of Go's archive/tar test corpus
// through nydus build, the streaming layer conversion nydusify uses, and
// checks the FUSE-mounted result against the reference tree containerd
// applies from the same archive. Archives Go or the reference rejects must
// be rejected by the conversion too, never turned into an image.
func TestGoTarCorpus(t *testing.T) {
	util.SkipUnlessRoot(t, "the reference tree restores ownership and device nodes")
	t.Parallel()
	assert := assert.New(t)

	// Locate the corpus archives.
	testdata := goTarTestdata(t)
	archives, err := filepath.Glob(filepath.Join(testdata, "*.tar*"))
	assert.NoError(err)
	assert.NotEmpty(archives, "no archives in %s", testdata)

	// Convert each archive and compare its mount with the reference tree.
	for _, path := range archives {
		t.Run(strings.TrimSuffix(filepath.Base(path), obscuredSuffix), func(t *testing.T) {
			t.Parallel()
			checkConversion(t, readCorpusArchive(t, path), blobLayout{})
		})
	}
}

// checkConversion converts data through nydus build and asserts the mount
// reproduces the reference tree extractReference applies from it, or that
// the conversion fails cleanly when Go or the reference rejects the archive.
// data may be gzipped, which nydus build accepts too. It reports whether the
// archive was converted and compared rather than rejected.
func checkConversion(t *testing.T, data []byte, layout blobLayout) bool {
	t.Helper()

	// Read the archive with Go first, skipping the ones over the budget.
	layer, goErr := gunzipLayer(data)
	var expandedSize int64
	if goErr == nil {
		expandedSize, goErr = scanGoTar(layer)
	}
	if goErr == nil && expandedSize > maxExpandedSize {
		t.Skipf("expands to %d bytes, over the %d-byte budget", expandedSize, maxExpandedSize)
	}

	// Convert the archive; what Go rejects the builder must reject too.
	workDir := t.TempDir()
	blob := filepath.Join(workDir, "layer.blob")
	packErr := packLayer(t, bytes.NewReader(data), blob, layout)
	if goErr != nil {
		assertRejected(t, packErr, "Go rejects the archive (%v)", goErr)
		return false
	}

	// Build the reference tree; what containerd rejects the builder must
	// reject too.
	reference := filepath.Join(workDir, "reference")
	assert.NoError(t, os.Mkdir(reference, 0o755))
	if err := extractReference(layer, reference); err != nil {
		if errors.Is(err, errNoReference) {
			t.Skipf("no reference: %v", err)
		}

		assertRejected(t, packErr, "containerd rejects the archive (%v)", err)
		return false
	}

	if !assert.NoError(t, packErr, "nydus build") {
		return false
	}

	// Mount the blob and compare it with the reference tree.
	mountpoint := filepath.Join(workDir, "mnt")
	defer util.MountNydusBlob(t, nydusBin, blob, mountpoint)()
	util.CheckDirectoryEqual(t, reference, mountpoint, true)

	return true
}

// assertRejected asserts the builder refused the archive with an error
// exit, not a panic (exit 101) or a signal.
func assertRejected(t *testing.T, packErr error, format string, args ...any) {
	t.Helper()
	assert.Errorf(t, packErr, format+" but nydus build accepted it", args...)

	var exitErr *exec.ExitError
	if errors.As(packErr, &exitErr) {
		code := exitErr.ExitCode()
		assert.Truef(t, code != 101 && code != -1, format+" and the builder crashed: %v", append(args, packErr)...)
	}
}

// goTarTestdata locates the corpus: NYDUS_E2E_GO_TAR_TESTDATA, else the testdata of
// the Go toolchain on PATH.
func goTarTestdata(t *testing.T) string {
	t.Helper()
	if dir := os.Getenv("NYDUS_E2E_GO_TAR_TESTDATA"); dir != "" {
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

// corpusArchivePath returns the path of the named corpus archive, which newer Go
// toolchains store obscured.
func corpusArchivePath(t *testing.T, testdata, name string) string {
	t.Helper()
	path := filepath.Join(testdata, name)
	if _, err := os.Stat(path); err == nil {
		return path
	}

	return path + obscuredSuffix
}

// readCorpusArchive reads the corpus archive at path, decoding the obscured
// ones and decompressing the bzip2 ones.
func readCorpusArchive(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	assert.NoError(t, err)

	if name, ok := strings.CutSuffix(path, obscuredSuffix); ok {
		data, err = io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(data)))
		assert.NoError(t, err)
		path = name
	}

	if strings.HasSuffix(path, ".bz2") {
		data, err = io.ReadAll(bzip2.NewReader(bytes.NewReader(data)))
		assert.NoError(t, err)
	}

	return data
}

// scanGoTar reads the archive with Go's archive/tar, returning the bytes its
// entries declare and the first error Go reports. Past the budget, data is
// skipped rather than read, so truncation is still reported.
func scanGoTar(data []byte) (int64, error) {
	tr := tar.NewReader(bytes.NewReader(data))
	var expandedSize int64

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return expandedSize, nil
		}
		if err != nil {
			return expandedSize, err
		}

		expandedSize += hdr.Size
		if expandedSize > maxExpandedSize {
			continue
		}

		if _, err := io.Copy(io.Discard, tr); err != nil {
			return expandedSize, err
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
func packLayer(t *testing.T, r io.Reader, blob string, layout blobLayout) error {
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
