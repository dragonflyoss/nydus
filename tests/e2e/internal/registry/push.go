package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// PushBlob uploads the file at path as a blob of repo and returns its hex
// digest. The nydus registry backend reads blobs by digest alone, so a raw
// nydus blob needs no manifest to be served.
func (r *Registry) PushBlob(t env.TB, repo, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		t.Fatalf("hash %s: %v", path, err)
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("rewind %s: %v", path, err)
	}

	resp, err := http.Post(fmt.Sprintf("%s/v2/%s/blobs/uploads/", r.URL, repo), "", nil)
	if err != nil {
		t.Fatalf("start upload: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("start upload: %s", resp.Status)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("upload location: %v", err)
	}
	q := loc.Query()
	q.Set("digest", "sha256:"+digest)
	loc.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodPut, loc.String(), f)
	if err != nil {
		t.Fatalf("upload request: %v", err)
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("upload %s: %v", path, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload %s: %s", path, resp.Status)
	}
	return digest
}

// PushBlobs uploads every blob of an image's blob directory to repo.
func (r *Registry) PushBlobs(t env.TB, repo string, blobs []string) {
	t.Helper()
	for _, b := range blobs {
		if got := r.PushBlob(t, repo, b); got != filepath.Base(b) {
			t.Fatalf("blob %s has digest %s", b, got)
		}
	}
}

// PushDirs pushes an OCI image (linux/amd64) with one gzip layer per
// directory, lowest first, as ref and returns the image. It is how tests
// get a source image for nydusify without docker.
func (r *Registry) PushDirs(t env.TB, ref string, dirs ...string) v1.Image {
	t.Helper()
	img := empty.Image
	for _, dir := range dirs {
		layerTar := filepath.Join(t.TempDir(), "layer.tar")
		f, err := os.Create(layerTar)
		if err != nil {
			t.Fatalf("create %s: %v", layerTar, err)
		}
		if err := oracle.WriteTar(f, dir); err != nil {
			t.Fatalf("tar %s: %v", dir, err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close %s: %v", layerTar, err)
		}
		layer, err := tarball.LayerFromFile(layerTar)
		if err != nil {
			t.Fatalf("layer from %s: %v", dir, err)
		}
		if img, err = mutate.AppendLayers(img, layer); err != nil {
			t.Fatalf("append layer: %v", err)
		}
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	cfg = cfg.DeepCopy()
	cfg.OS, cfg.Architecture = "linux", "amd64"
	if img, err = mutate.ConfigFile(img, cfg); err != nil {
		t.Fatalf("set config: %v", err)
	}

	parsed, err := name.ParseReference(ref, name.Insecure)
	if err != nil {
		t.Fatalf("parse %s: %v", ref, err)
	}
	if err := remote.Write(parsed, img); err != nil {
		t.Fatalf("push %s: %v", ref, err)
	}
	return img
}
