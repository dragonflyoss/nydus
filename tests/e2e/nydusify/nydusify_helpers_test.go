// Package nydusify tests the nydusify image tool end to end against an
// in-process registry: convert, check, optimize, mount and the conversion
// back to OCI. Every converted image is also judged independently of
// nydusify, by pulling it and reading it with the nydus FUSE reader.
package nydusify

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/require"
)

// The nydus image format as nydusify writes it (nydusify/pkg/nydus).
const (
	nydusBlobMediaType       = "application/vnd.oci.image.layer.nydus.blob.v1"
	nydusBlobAnnotation      = "containerd.io/snapshot/nydus-blob"
	nydusOptimizedAnnotation = "containerd.io/snapshot/nydus-blob-optimized"
	nydusBootstrapAnnotation = "containerd.io/snapshot/nydus-bootstrap"
	bootstrapInLayer         = "image/image.boot"
)

// source is an OCI image pushed from directories, one layer each, lowest
// first, and the tree it holds.
type source struct {
	name string
	dirs []string
	want []oracle.Entry
}

func newSource(t env.TB, name string, dirs ...string) source {
	t.Helper()
	views := make([][]oracle.Entry, len(dirs))
	for i, dir := range dirs {
		views[i] = oracle.TarView(oracle.ScanSource(t, dir))
	}
	return source{name: name, dirs: dirs, want: oracle.Overlay(views...)}
}

// compare is how a mount of the source's image is judged: a multi-layer
// image keeps each layer's link count (KI-6), as Image.Compare explains.
func (s source) compare() oracle.CompareOptions {
	return oracle.CompareOptions{Nlink: len(s.dirs) == 1}
}

// corpusSources are the fixture corpora as source images: the standard
// corpus in one layer, and the three layers of the layers corpus, which
// exercise every whiteout form.
func corpusSources(t env.TB) []source {
	t.Helper()
	return []source{
		newSource(t, "single", fixture.Corpus(t, fixture.Standard)),
		newSource(t, "multi", fixture.LayerDirs(t)...),
	}
}

// nydusify runs a nydusify subcommand to completion and returns its output.
func nydusify(t env.TB, args ...string) string {
	t.Helper()
	out, err := tryNydusify(t, args...)
	require.NoError(t, err, "nydusify %s:\n%s", strings.Join(args, " "), out)
	return out
}

// tryNydusify runs nydusify with the nydus under test as its builder, plain
// HTTP to the test registry and, for check, a scratch work directory (it
// defaults to ./output).
func tryNydusify(t env.TB, args ...string) (string, error) {
	t.Helper()
	args = append(slices.Clone(args), "--builder", env.Nydus(t), "--target-plain-http")
	if args[0] != "mount" {
		args = append(args, "--source-plain-http")
	}
	if args[0] == "check" && !slices.Contains(args, "--work-dir") {
		args = append(args, "--work-dir", t.TempDir())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, env.Nydusify(t), args...).CombinedOutput()
	require.NoError(t, ctx.Err(), "nydusify command did not finish within 2m: %s", out)
	return string(out), err
}

// remoteImage fetches the manifest of ref (linux/amd64 from an index).
func remoteImage(t env.TB, ref string) v1.Image {
	t.Helper()
	parsed, err := name.ParseReference(ref, name.Insecure)
	require.NoError(t, err)
	img, err := remote.Image(parsed)
	require.NoError(t, err, "fetch %s", ref)
	return img
}

// pullNydus downloads the nydus image ref into a blob directory and checks
// its layout: the data blobs, named by their digest, then the bootstrap
// layer.
func pullNydus(t env.TB, ref string, want []oracle.Entry) fixture.Image {
	t.Helper()
	remoteImg := remoteImage(t, ref)
	manifest, err := remoteImg.Manifest()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(manifest.Layers), 2, "a nydus image has blob layers and a bootstrap layer")

	dir := env.WorkDir(t)
	img := fixture.Image{
		Name:      ref,
		Bootstrap: filepath.Join(dir, "image.boot"),
		BlobDir:   filepath.Join(dir, "blobs"),
		Want:      want,
	}
	require.NoError(t, os.MkdirAll(img.BlobDir, 0o755))
	last := len(manifest.Layers) - 1
	layers := 0
	for i, desc := range manifest.Layers {
		layer, err := remoteImg.LayerByDigest(desc.Digest)
		require.NoError(t, err)
		rc, err := layer.Compressed()
		require.NoError(t, err)
		if i == last {
			require.Contains(t, desc.Annotations, nydusBootstrapAnnotation, "the last layer is the bootstrap")
			extractBootstrap(t, rc, img.Bootstrap)
			continue
		}
		require.Equal(t, nydusBlobMediaType, string(desc.MediaType), "layer %d", i)
		require.Contains(t, desc.Annotations, nydusBlobAnnotation, "layer %d", i)
		if _, ok := desc.Annotations[nydusOptimizedAnnotation]; !ok {
			layers++
		}
		blob := filepath.Join(img.BlobDir, desc.Digest.Hex)
		writeFile(t, rc, blob)
		img.Blobs = append(img.Blobs, blob)
	}
	img.Merged = layers > 1
	return img
}

func extractBootstrap(t env.TB, layer io.ReadCloser, dst string) {
	t.Helper()
	defer func() { _ = layer.Close() }()
	gz, err := gzip.NewReader(layer)
	require.NoError(t, err, "the bootstrap layer is gzip")
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			t.Fatalf("bootstrap layer has no %s", bootstrapInLayer)
		}
		require.NoError(t, err)
		if hdr.Name == bootstrapInLayer {
			writeFile(t, io.NopCloser(tr), dst)
			return
		}
	}
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

func writeFile(t env.TB, r io.ReadCloser, dst string) {
	t.Helper()
	defer func() { _ = r.Close() }()
	f, err := os.Create(dst)
	require.NoError(t, err)
	_, err = io.Copy(f, r)
	require.NoError(t, err, "write %s", dst)
	require.NoError(t, f.Close())
}

// startMount runs `nydusify mount` of ref in the background until the test
// ends and returns the daemon, its mountpoint and its apiserver.
func startMount(t env.TB, ref string, prefetch bool) (*mount.Daemon, string, *mount.API) {
	t.Helper()
	mount.FUSE{}.Require(t)
	// The apiserver socket lives in the work directory, and a socket path
	// must fit in 108 bytes.
	work, err := os.MkdirTemp("", "nydusify-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(work) })
	dir := env.WorkDir(t)
	mnt := filepath.Join(dir, "mnt")
	t.Cleanup(func() {
		if mount.IsMountpoint(mnt) {
			mount.Unmount(mnt)
		}
	})
	args := []string{"mount", "--target", ref, "--mountpoint", mnt, "--work-dir", work,
		"--builder", env.Nydus(t), "--target-plain-http"}
	if prefetch {
		args = append(args, "--prefetch")
	}
	d := mount.StartDaemon(t, dir, "nydusify-mount", env.Nydusify(t), args...)
	d.WaitFor(t, time.Minute, "mount at "+mnt, func() bool { return mount.IsMountpoint(mnt) })
	// The daemon binds its apiserver only after mounting.
	socket := filepath.Join(work, "apiserver.sock")
	d.WaitFor(t, 10*time.Second, "apiserver at "+socket, func() bool {
		_, err := os.Stat(socket)
		return err == nil
	})
	return d, mnt, mount.NewAPI(socket)
}

// extractOCI runs `nydusify mount` of an OCI image, which extracts the root
// filesystem with containerd's layer applier, the reference implementation
// of OCI layer semantics.
func extractOCI(t env.TB, ref string) string {
	t.Helper()
	env.RequireRoot(t)
	rootfs := filepath.Join(env.WorkDir(t), "rootfs")
	nydusify(t, "mount", "--target", ref, "--mountpoint", rootfs)
	return rootfs
}

// traceLen returns the number of patterns in a /trace document.
func traceLen(t env.TB, raw []byte) int {
	t.Helper()
	var doc struct {
		Version  int               `json:"version"`
		Patterns []json.RawMessage `json:"patterns"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc), "trace: %s", raw)
	require.Equal(t, 1, doc.Version, "trace version")
	return len(doc.Patterns)
}

// waitRedirectFill waits until prefetch of the ondemand blob has filled the
// want traced chunk groups into their source blobs' caches.
func waitRedirectFill(t env.TB, api *mount.API, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		got := api.Metrics(t).Sum("nydus_cache_write_total", `type="redirect"`)
		if got >= float64(want) {
			return
		}
		require.True(t, time.Now().Before(deadline), "prefetch filled %v of %d traced chunk groups within a minute", got, want)
		time.Sleep(100 * time.Millisecond)
	}
}
