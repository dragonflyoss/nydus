package nydusify

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/stretchr/testify/assert"
)

type ref string

func (r ref) parse(t testing.TB) name.Reference {
	t.Helper()
	parsed, err := name.ParseReference(string(r), name.Insecure)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return parsed
}

func (r ref) assertAbsent(t testing.TB) {
	t.Helper()
	_, err := remote.Head(r.parse(t))

	var terr *transport.Error
	if !assert.ErrorAs(t, err, &terr) {
		t.FailNow()
	}

	assert.Equal(t, http.StatusNotFound, terr.StatusCode)
}

func (r ref) image(t testing.TB) v1.Image {
	t.Helper()
	img, err := remote.Image(r.parse(t))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return img
}

func (r ref) pull(t testing.TB, want []fstest.Entry) fixture.Image {
	t.Helper()
	remoteImg := r.image(t)
	manifest, err := remoteImg.Manifest()
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.GreaterOrEqual(t, len(manifest.Layers), 2) {
		t.FailNow()
	}

	dir := env.WorkDir(t)

	img := fixture.Image{
		Name:      string(r),
		Bootstrap: filepath.Join(dir, "image.boot"),
		BlobDir:   filepath.Join(dir, "blobs"),
		Want:      want,
	}

	if !assert.NoError(t, os.MkdirAll(img.BlobDir, 0o755)) {
		t.FailNow()
	}

	last := len(manifest.Layers) - 1
	layers := 0

	for i, desc := range manifest.Layers {
		if i == last {
			assert.Contains(t, desc.Annotations, nydusBootstrapAnnotation)
			entries := bootstrapEntries(t, remoteImg)
			if !assert.Contains(t, entries, bootstrapInLayer) {
				t.FailNow()
			}
			if !assert.NoError(t, os.WriteFile(img.Bootstrap, entries[bootstrapInLayer], 0o644)) {
				t.FailNow()
			}

			continue
		}

		if !assert.Equal(t, nydusBlobMediaType, string(desc.MediaType)) {
			t.FailNow()
		}
		if !assert.Contains(t, desc.Annotations, nydusBlobAnnotation) {
			t.FailNow()
		}

		if _, ok := desc.Annotations[nydusOptimizedAnnotation]; !ok {
			layers++
		}

		layer, err := remoteImg.LayerByDigest(desc.Digest)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		rc, err := layer.Compressed()
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		blob := filepath.Join(img.BlobDir, desc.Digest.Hex)
		writeFile(t, rc, blob)
		img.Blobs = append(img.Blobs, blob)
	}

	img.Merged = layers > 1

	return img
}

func bootstrapEntries(t testing.TB, img v1.Image) map[string][]byte {
	t.Helper()
	layers, err := img.Layers()
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.NotEmpty(t, layers) {
		t.FailNow()
	}

	r, err := layers[len(layers)-1].Compressed()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { assert.NoError(t, r.Close()) }()
	gz, err := gzip.NewReader(r)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { assert.NoError(t, gz.Close()) }()
	tr := tar.NewReader(gz)
	entries := map[string][]byte{}

	for {
		h, err := tr.Next()
		if err == io.EOF {
			return entries
		}
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		data, err := io.ReadAll(tr)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		entries[h.Name] = data
	}
}

func writeFile(t testing.TB, r io.ReadCloser, dst string) {
	t.Helper()
	defer func() { _ = r.Close() }()
	f, err := os.Create(dst)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	_, err = io.Copy(f, r)
	assert.NoError(t, err)
	assert.NoError(t, f.Close())
}

func (r ref) mount(t testing.TB, prefetch bool) (*mount.Daemon, string, *mount.API) {
	t.Helper()
	mount.FUSE{}.Require(t)

	dir := env.WorkDir(t)
	work := filepath.Join(dir, "work")
	mnt := filepath.Join(dir, "mnt")

	t.Cleanup(func() {
		if mount.IsMountpoint(mnt) {
			mount.Unmount(mnt)
		}
	})

	args := []string{"mount", "--target", string(r), "--mountpoint", mnt, "--work-dir", work,
		"--builder", env.Nydus(t), "--target-plain-http"}

	if prefetch {
		args = append(args, "--prefetch")
	}

	d := mount.StartDaemon(t, dir, "nydusify-mount", env.Nydusify(t), args...)
	d.WaitFor(t, time.Minute, "mount at "+mnt, func() bool { return mount.IsMountpoint(mnt) })

	socket := filepath.Join(work, "apiserver.sock")
	api := mount.NewAPI(socket)

	d.WaitFor(t, 10*time.Second, "apiserver at "+socket, func() bool {
		_, err := api.Get("/metrics")
		return err == nil
	})

	return d, mnt, api
}

func (r ref) extract(t testing.TB) string {
	t.Helper()
	env.RequireRoot(t)
	rootfs := filepath.Join(env.WorkDir(t), "rootfs")
	nydusify(t, "mount", "--target", string(r), "--mountpoint", rootfs)

	return rootfs
}
