package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/platforms"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

type failingStore struct {
	content.Store
	at    int
	calls []string
	err   error
}

func (s *failingStore) hit(operation string) error {
	s.calls = append(s.calls, operation)
	if len(s.calls) == s.at {
		return s.err
	}
	return nil
}

func (s *failingStore) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	if err := s.hit("read"); err != nil {
		return nil, err
	}
	return s.Store.ReaderAt(ctx, desc)
}

func (s *failingStore) Info(ctx context.Context, dgst digest.Digest) (content.Info, error) {
	if err := s.hit("info"); err != nil {
		return content.Info{}, err
	}
	return s.Store.Info(ctx, dgst)
}

func (s *failingStore) Writer(ctx context.Context, opts ...content.WriterOpt) (content.Writer, error) {
	if err := s.hit("write"); err != nil {
		return nil, err
	}
	return s.Store.Writer(ctx, opts...)
}

func (s *failingStore) Update(ctx context.Context, info content.Info, fields ...string) (content.Info, error) {
	if err := s.hit("update"); err != nil {
		return content.Info{}, err
	}
	return s.Store.Update(ctx, info, fields...)
}

func TestPipelineStoreFailures(t *testing.T) {
	ctx := context.Background()
	blobDigest := digest.FromString("external blob")
	blob := ocispec.Descriptor{Digest: blobDigest, MediaType: nydus.MediaTypeNydusBlob, Size: 13,
		Annotations: map[string]string{nydus.LayerAnnotationNydusBlob: "true", nydus.LayerAnnotationUncompressed: blobDigest.String()}}
	meta := nydus.BlobMetaFile{Name: blobDigest.Encoded() + ".blob.meta", Data: []byte("metadata")}
	bootstrapPath := filepath.Join(t.TempDir(), "image.boot")
	require.NoError(t, os.WriteFile(bootstrapPath, []byte("bootstrap"), 0o600))
	previous := inspectBootstrapBlobDigests
	inspectBootstrapBlobDigests = func(context.Context, string, string) (map[digest.Digest]struct{}, error) {
		return map[digest.Digest]struct{}{blobDigest: {}}, nil
	}
	t.Cleanup(func() { inspectBootstrapBlobDigests = previous })

	for _, operation := range []string{"parent", "annotations", "converted-annotations", "artifact", "manifest", "index", "label-nydus", "label-source"} {
		t.Run(operation, func(t *testing.T) {
			run := func(t *testing.T, at int) []string {
				provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
				require.NoError(t, err)
				store := provider.ContentStore()
				require.NoError(t, content.WriteBlob(ctx, store, "blob", bytes.NewReader([]byte("external blob")), blob))
				boot, err := oci.WriteBootstrapLayer(ctx, store, []byte("bootstrap"), []nydus.BlobMetaFile{meta}, nil)
				require.NoError(t, err)
				config, err := oci.WriteJSON(ctx, store, ocispec.Image{RootFS: ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{blobDigest, digest.Digest(boot.Annotations[nydus.LayerAnnotationUncompressed])}}},
					ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig}, nil)
				require.NoError(t, err)
				manifest, err := oci.WriteJSON(ctx, store, ocispec.Manifest{Config: *config, Layers: []ocispec.Descriptor{blob, *boot}},
					ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, nil)
				require.NoError(t, err)
				index, err := oci.WriteJSON(ctx, store, ocispec.Index{Manifests: []ocispec.Descriptor{*manifest}},
					ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex}, nil)
				require.NoError(t, err)
				injected := errors.New("injected content store failure")
				fault := &failingStore{Store: store, at: at, err: injected}
				switch operation {
				case "parent":
					_, err = LoadParentNydusArtifact(ctx, fault, *index, platforms.All)
				case "annotations":
					_, err = rewriteNydusManifestAnnotations(ctx, fault, *manifest, map[string]string{"test": "value"})
				case "converted-annotations":
					_, err = convertManifest(ctx, fault, manifest, nydus.MergeOption{}, map[string]string{"test": "value"})
				case "artifact":
					_, err = ConvertNydusArtifacts(ctx, fault, ArtifactOption{BootstrapPath: bootstrapPath,
						ParentImages: []ParentImageMetadata{{Blobs: []ocispec.Descriptor{blob}, BlobMetas: []nydus.BlobMetaFile{meta}}}})
				case "manifest":
					_, err = writeNydusManifest(ctx, fault, []ocispec.Descriptor{blob}, *boot, nil,
						ocispec.Platform{OS: "linux", Architecture: "amd64"}, "test", nil)
				case "index":
					_, err = convertIndex(ctx, fault, index)
				case "label-nydus":
					err = labelNydusBlobDiffIDs(ctx, fault, *index, platforms.All)
				case "label-source":
					err = labelSourceLayerDiffIDs(ctx, fault, *index, platforms.All)
				}
				if at == 0 {
					require.NoError(t, err)
				} else {
					require.GreaterOrEqual(t, len(fault.calls), at, "injection must be reached")
					require.ErrorIs(t, err, injected, "store failures must not become successful descriptors")
				}
				return fault.calls
			}
			for i, name := range run(t, 0) {
				t.Run(fmt.Sprintf("%02d-%s", i+1, name), func(t *testing.T) { run(t, i+1) })
			}
		})
	}
}

func TestPipelineInputFailures(t *testing.T) {
	ctx := context.Background()
	store, err := local.NewStore(t.TempDir())
	require.NoError(t, err)
	work := t.TempDir()
	missing := filepath.Join(work, "missing")
	regular := filepath.Join(work, "data")
	require.NoError(t, os.WriteFile(regular, []byte("invalid metadata"), 0o600))
	for _, paths := range [][]string{{missing}, {work}, {regular, regular}} {
		_, err := validateAndReadAppendFiles(paths)
		require.Error(t, err)
	}
	for _, name := range []string{"image.boot", "digest.blob.meta"} {
		path := filepath.Join(work, name)
		require.NoError(t, os.WriteFile(path, nil, 0o600))
		_, err := validateAndReadAppendFiles([]string{path})
		require.ErrorContains(t, err, "reserved")
	}
	large := filepath.Join(work, "large")
	file, err := os.Create(large)
	require.NoError(t, err)
	require.NoError(t, file.Truncate(maxAppendFileSize+1))
	require.NoError(t, file.Close())
	_, err = validateAndReadAppendFiles([]string{large})
	require.ErrorContains(t, err, "too large")
	for _, paths := range [][]string{{missing}, {work}} {
		_, err := collectArtifactBlobPaths(paths, "")
		require.Error(t, err)
	}
	_, err = collectArtifactBlobPaths(nil, missing)
	require.ErrorContains(t, err, "read blob dir")
	for _, path := range []string{missing, regular, work} {
		_, _, err := describeArtifactBlob(path)
		require.Error(t, err)
	}
	for _, opt := range []MultiSourceOption{
		{}, {Sources: []Source{{}}, WorkDir: work},
		{Sources: []Source{{Dir: work, Image: &ocispec.Descriptor{}}}, WorkDir: work},
		{Sources: []Source{{Dir: work}}, WorkDir: regular},
		{Sources: []Source{{Dir: work}}, WorkDir: work, AppendInBootstrap: []string{missing}},
		{Sources: []Source{{Dir: work}}, WorkDir: work, BuilderPath: missing},
	} {
		_, err := ConvertMultiSource(ctx, store, opt)
		require.Error(t, err)
	}
	for _, opt := range []ArtifactOption{
		{}, {BootstrapPath: missing}, {BootstrapPath: regular},
		{BootstrapPath: regular, AppendInBootstrap: []string{missing}},
		{BootstrapPath: regular, BlobPaths: []string{missing}},
		{BootstrapPath: regular, ParentImages: make([]ParentImageMetadata, 2)},
		{BootstrapPath: regular, BlobPaths: []string{regular}, BuilderPath: missing},
	} {
		_, err := ConvertNydusArtifacts(ctx, store, opt)
		require.Error(t, err)
	}
	for _, input := range []string{`{`, `{"rootfs":true}`, `{"history":true}`} {
		_, err := rewriteBootstrapConfig(json.RawMessage(input), nil)
		require.Error(t, err)
	}
	invalidTime := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err = patchImageConfig(json.RawMessage(`{}`), nil, func([]ocispec.History, bool) ([]ocispec.History, bool) {
		return []ocispec.History{{Created: &invalidTime}}, true
	})
	require.ErrorContains(t, err, "marshal image config history")
	for _, bad := range []struct {
		blobs []ocispec.Descriptor
		boot  ocispec.Descriptor
		base  json.RawMessage
	}{
		{blobs: []ocispec.Descriptor{{}}},
		{},
		{boot: ocispec.Descriptor{Annotations: map[string]string{nydus.LayerAnnotationUncompressed: digest.FromString("boot").String()}}, base: json.RawMessage(`{`)},
	} {
		_, err := writeNydusManifest(ctx, store, bad.blobs, bad.boot, bad.base, ocispec.Platform{}, "test", nil)
		require.Error(t, err)
	}
}

func TestLayerLabelsAndPlatformSelection(t *testing.T) {
	ctx := context.Background()
	for _, state := range []string{"missing", "unlabeled", "already-labeled", "mismatched-config", "excluded-platform"} {
		t.Run(state, func(t *testing.T) {
			provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
			require.NoError(t, err)
			store := provider.ContentStore()
			data := []byte("layer")
			dgst := digest.FromBytes(data)
			layer := ocispec.Descriptor{MediaType: nydus.MediaTypeNydusBlob, Digest: dgst, Size: int64(len(data)),
				Annotations: map[string]string{nydus.LayerAnnotationNydusBlob: "true", nydus.LayerAnnotationUncompressed: dgst.String()}}
			if state != "missing" {
				labels := map[string]string{"keep": "value"}
				if state == "already-labeled" {
					labels[nydus.LayerAnnotationUncompressed] = dgst.String()
				}
				require.NoError(t, content.WriteBlob(ctx, store, "blob", bytes.NewReader(data), layer, content.WithLabels(labels)))
			}
			diffIDs := []digest.Digest{dgst}
			if state == "mismatched-config" {
				diffIDs = nil
			}
			config, err := oci.WriteJSON(ctx, store, ocispec.Image{RootFS: ocispec.RootFS{Type: "layers", DiffIDs: diffIDs}},
				ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig}, nil)
			require.NoError(t, err)
			manifest, err := oci.WriteJSON(ctx, store, ocispec.Manifest{Config: *config, Layers: []ocispec.Descriptor{layer}},
				ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, nil)
			require.NoError(t, err)
			manifest.Platform = &ocispec.Platform{OS: "linux", Architecture: "amd64"}
			if state == "excluded-platform" {
				manifest.Platform.Architecture = "arm64"
			}
			index, err := oci.WriteJSON(ctx, store, ocispec.Index{Manifests: []ocispec.Descriptor{*manifest}},
				ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex}, nil)
			require.NoError(t, err)
			matcher := platforms.Only(ocispec.Platform{OS: "linux", Architecture: "amd64"})
			require.NoError(t, labelSourceLayerDiffIDs(ctx, store, *index, matcher))
			if state == "mismatched-config" {
				info, err := store.Info(ctx, dgst)
				require.NoError(t, err)
				require.Empty(t, info.Labels[nydus.LayerAnnotationUncompressed], "do not invent a diff ID for a mismatched config")
			}
			require.NoError(t, labelNydusBlobDiffIDs(ctx, store, *index, matcher))
			if state != "missing" {
				info, err := store.Info(ctx, dgst)
				require.NoError(t, err)
				require.Equal(t, "value", info.Labels["keep"])
				if state == "excluded-platform" {
					require.Empty(t, info.Labels[nydus.LayerAnnotationUncompressed])
				} else {
					require.Equal(t, dgst.String(), info.Labels[nydus.LayerAnnotationUncompressed])
				}
			}
			require.NoError(t, labelSourceLayerDiffIDs(ctx, store, layer, matcher))
			require.NoError(t, labelNydusBlobDiffIDs(ctx, store, layer, matcher))
		})
	}
}
