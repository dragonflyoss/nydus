package tar

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/stretchr/testify/require"
)

// tarBudget bounds the bytes an archive may expand to: the reference tree
// materializes every byte, so a sparse member declaring tens of gigabytes
// would fill the disk.
const tarBudget = 1 << 30

// tarLayout selects the blob layout a conversion builds; the zero value is
// nydusify's default, zstd in 2 MiB chunks.
type tarLayout struct {
	compressor string
	chunkSize  uint32
}

// tarLayouts are the blob layouts besides the default that the edge-case
// matrix and the random layers are also converted into.
var tarLayouts = map[string]tarLayout{
	"none":       {compressor: "none"},
	"lz4":        {compressor: "lz4"},
	"zstd-64k":   {chunkSize: 64 << 10},
	"erofs-none": {compressor: "erofs-none"},
	"erofs-zstd": {compressor: "erofs-zstd"},
}

// tarOutcome is how checkTarConversion judged an archive.
type tarOutcome int

const (
	// tarConverted: the mount reproduced the reference tree.
	tarConverted tarOutcome = iota
	// tarRejected: Go or containerd refuses the archive, and so did the
	// builder, without crashing.
	tarRejected
	// tarOverBudget: the archive expands past tarBudget and was not
	// converted at all.
	tarOverBudget
	// tarUnjudged: the reference depends on the host filesystem, so only
	// that the builder did not crash was checked.
	tarUnjudged
)

// checkTarConversion converts data through nydus build, the streaming layer
// conversion nydusify uses, and asserts the FUSE mount of the blob
// reproduces the tree containerd's archive.Apply extracts from the same
// bytes. An archive Go or Apply rejects must be rejected by the builder too,
// never turned into an image. data may be gzipped, which nydus build accepts.
func checkTarConversion(t *testing.T, data []byte, layout tarLayout) tarOutcome {
	t.Helper()
	layer, goErr := gunzipLayer(data)
	var expanded int64
	if goErr == nil {
		expanded, goErr = scanGoTar(layer)
	}
	if goErr == nil && expanded > tarBudget {
		t.Logf("not converted: expands past the %d-byte budget", tarBudget)
		return tarOverBudget
	}

	work := t.TempDir()
	blob := filepath.Join(work, "layer.blob")
	packErr := packLayer(t, bytes.NewReader(data), blob, layout)
	if goErr != nil {
		requireRejected(t, packErr, "Go rejects the archive (%v)", goErr)
		return tarRejected
	}

	reference := filepath.Join(work, "reference")
	require.NoError(t, os.Mkdir(reference, 0o755))
	if err := extractReference(layer, reference); err != nil {
		if errors.Is(err, errTarUnsupported) {
			requireNoCrash(t, packErr)
			t.Logf("not judged: %v", err)
			return tarUnjudged
		}
		requireRejected(t, packErr, "containerd rejects the archive (%v)", err)
		return tarRejected
	}
	require.NoError(t, packErr, "nydus build")

	mnt := mount.Mount(t, mount.FUSE{}, blobImage(work, blob), mount.Options{Mode: mount.Blob})
	oracle.DiffTree(t, reference, mnt.Root, oracle.Options{})
	// Hundreds of conversions run in parallel; free the daemon now.
	mnt.Unmount()
	return tarConverted
}

// requireJudged fails a hand-written archive that checkTarConversion could
// not judge for its size: such an archive belongs in a dedicated test.
func requireJudged(t *testing.T, outcome tarOutcome) {
	t.Helper()
	require.NotEqual(t, tarOverBudget, outcome, "archive over budget")
}

// blobImage describes the single self-describing blob a conversion wrote,
// to be served with mount.Blob.
func blobImage(dir, blob string) fixture.Image {
	return fixture.Image{Name: "tar-layer", BlobDir: dir, Blobs: []string{blob}}
}

// packLayer streams r through `nydus build --source-type tar` into blob,
// with the arguments nydusify passes.
func packLayer(t env.TB, r io.Reader, blob string, layout tarLayout) error {
	t.Helper()
	compressor := layout.compressor
	if compressor == "" {
		compressor = "zstd"
	}
	chunkSize := layout.chunkSize
	if chunkSize == 0 {
		chunkSize = 2 << 20
	}
	cmd := exec.Command(env.Nydus(t), "build", "/dev/stdin", "--source-type", "tar", "--blob", blob,
		"--chunk-size", strconv.FormatUint(uint64(chunkSize), 10), "--compressor", compressor, "--log-level", "warn")
	cmd.Stdin = r
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nydus build: %w: %s", err, stderr.Bytes())
	}
	return nil
}

// requireRejected asserts the builder refused the archive with an error
// exit, not a panic or a signal.
func requireRejected(t *testing.T, packErr error, format string, args ...any) {
	t.Helper()
	require.Error(t, packErr, append([]any{format + " but nydus build accepted it"}, args...)...)
	requireNoCrash(t, packErr)
}

// requireNoCrash asserts nydus build did not panic (exit 101) or die of a
// signal (exit -1).
func requireNoCrash(t *testing.T, packErr error) {
	t.Helper()
	var exitErr *exec.ExitError
	if errors.As(packErr, &exitErr) {
		code := exitErr.ExitCode()
		require.True(t, code != 101 && code != -1, "nydus build crashed: %v", packErr)
	}
}

// scanGoTar reads the archive with Go's archive/tar, returning the bytes its
// entries expand to, saturating just past tarBudget, and the first error Go
// reports. Past the budget, data is skipped rather than read; the skip still
// reports truncation.
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
		// Go reads no data for these, whatever size they declare.
		switch hdr.Typeflag {
		case tar.TypeLink, tar.TypeSymlink, tar.TypeChar, tar.TypeBlock, tar.TypeDir, tar.TypeFifo:
			continue
		}
		// Saturating, so declared sizes cannot overflow back under budget.
		if expanded > tarBudget || hdr.Size > tarBudget-expanded {
			expanded = tarBudget + 1
			continue
		}
		expanded += hdr.Size
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
