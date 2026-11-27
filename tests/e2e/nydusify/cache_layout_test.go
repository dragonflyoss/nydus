package nydusify

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

// Exercise real Rust cache layout encoding, registry publication and cache import
// across Full, Diff and compact, without any local encoded data blobs.
func TestConvertCacheLayoutLocalCache(t *testing.T) {
	mount.FUSE{}.Require(t)
	reg := registry.Start(t)
	dir := env.WorkDir(t)
	cache, emptyBlobs := filepath.Join(dir, "cache"), filepath.Join(dir, "empty-backend")
	require.NoError(t, os.Mkdir(cache, 0700))
	require.NoError(t, os.Mkdir(emptyBlobs, 0700))
	var parent, parentBoot string
	blobIDs := map[string]bool{}
	for generation := 0; generation < 3; generation++ {
		cacheLayout := filepath.Join(dir, fmt.Sprintf("layout-%d", generation))
		args := []string{"--cache-layout", "--output-dir", cacheLayout}
		if parentBoot != "" {
			args = append(args, "--bootstrap", parentBoot, "--blob-dir", emptyBlobs)
		}
		output, err := exec.Command(env.Writer(t), args...).CombinedOutput()
		require.NoError(t, err, "%s", output)
		target := reg.Ref("cache-layout", fmt.Sprintf("v%d", generation))
		convert := []string{"convert", "--cache-dir", cacheLayout, "--target", target, "--prune", "--work-dir", filepath.Join(cacheLayout, ".nydusify")}
		if parent != "" {
			convert = append(convert, "--parent-image", parent)
		}
		if generation == 2 {
			convert = append(convert, "--compact-max-layers", "1", "--parent-cache-dir", cache)
		}
		convertOutput, err := tryNydusify(t, convert...)
		require.NoError(t, err, "%s", convertOutput)
		var result struct {
			Version uint32              `json:"version"`
			Blob    *ocispec.Descriptor `json:"blob"`
			Image   *ocispec.Descriptor `json:"image"`
		}
		data, err := os.ReadFile(filepath.Join(cacheLayout, "image.json"))
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(data, &result))
		require.Equal(t, uint32(1), result.Version)
		require.NotNil(t, result.Blob)
		require.NotNil(t, result.Image)
		source, err := os.Stat(filepath.Join(cacheLayout, "cache.data"))
		require.NoError(t, err)
		decoded, err := os.Stat(filepath.Join(cacheLayout, result.Blob.Digest.Encoded()+".blob.data"))
		require.NoError(t, err)
		require.Equal(t, generation != 2, os.SameFile(source, decoded))
		blobIDs[result.Blob.Digest.String()] = true
		for _, suffix := range []string{".blob.data", ".blob.meta", ".group.map"} {
			name := result.Blob.Digest.Encoded() + suffix
			require.NoError(t, os.Link(filepath.Join(cacheLayout, name), filepath.Join(cache, name)))
		}
		require.NoFileExists(t, filepath.Join(cacheLayout, result.Blob.Digest.Encoded()))
		layoutDir := filepath.Join(cacheLayout, ".nydusify", "content")
		require.FileExists(t, filepath.Join(layoutDir, "oci-layout"))
		data, err = os.ReadFile(filepath.Join(layoutDir, "index.json"))
		require.NoError(t, err)
		var index ocispec.Index
		require.NoError(t, json.Unmarshal(data, &index))
		require.Len(t, index.Manifests, 1)
		require.Equal(t, result.Image.Digest, index.Manifests[0].Digest)
		require.NoFileExists(t, filepath.Join(layoutDir, "blobs", "sha256", result.Blob.Digest.Encoded()))

		// Pull the bootstrap only. The configured backend is the registry,
		// so a broken ready map cannot silently fall back to a local blob.
		remoteImage := ref(target).image(t)
		manifest, err := remoteImage.Manifest()
		require.NoError(t, err)
		wantLayers := 2
		if generation == 1 {
			wantLayers = 3
		}
		require.Len(t, manifest.Layers, wantLayers)
		entries := bootstrapEntries(t, remoteImage)
		bootstrap := filepath.Join(cacheLayout, "pulled.boot")
		require.NotEmpty(t, entries[bootstrapInLayer])
		require.NoError(t, os.WriteFile(bootstrap, entries[bootstrapInLayer], 0600))
		img := fixture.Image{Bootstrap: bootstrap, BlobDir: emptyBlobs}
		m := mount.Mount(t, mount.FUSE{}, img, mount.Options{
			CacheDir: cache,
			Config: func(config *mount.Config) {
				config.Backend = mount.RegistryBackend(mount.RegistryConfig{Addr: reg.URL, Repository: "cache-layout"})
			},
		})
		changed := "child changed\n"
		if generation == 0 {
			changed = "capture changed\n"
		}
		for name, want := range map[string]string{
			"changed": changed, "created": "child created\n", "unchanged": "capture unchanged\n",
		} {
			got, err := os.ReadFile(filepath.Join(m.Root, name))
			require.NoError(t, err)
			require.Equal(t, want, string(got))
		}
		require.Zero(t, m.API.Metrics(t).Sum("nydus_backend_read_total"))
		m.Unmount()
		require.Zero(t, reg.Faults.Count(func(r registry.Request) bool {
			return r.Method == http.MethodGet && r.Path == "/v2/cache-layout/blobs/"+result.Blob.Digest.String()
		}))
		parent, parentBoot = target, filepath.Join(cacheLayout, "image.boot")
	}
	require.Zero(t, reg.Faults.Count(func(r registry.Request) bool {
		const prefix = "/v2/cache-layout/blobs/"
		return r.Method == http.MethodGet && len(r.Path) > len(prefix) && r.Path[:len(prefix)] == prefix && blobIDs[r.Path[len(prefix):]]
	}))
}
