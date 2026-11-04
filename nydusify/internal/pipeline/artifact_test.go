/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/platforms"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

var (
	mockBlobData = []byte("blob")

	mockBlobDigest = digest.FromBytes(mockBlobData)

	mockOtherBlobDigest = digest.FromString("other blob")

	mockStaleBlobDigest = digest.FromString("stale blob")

	mockBlobDesc = ocispec.Descriptor{
		MediaType: nydus.MediaTypeNydusBlob,
		Digest:    mockBlobDigest,
		Size:      int64(len(mockBlobData)),
		Annotations: map[string]string{
			nydus.LayerAnnotationUncompressed: mockBlobDigest.String(),
			nydus.LayerAnnotationNydusBlob:    "true",
		},
	}

	mockBlobMetaFile = nydus.BlobMetaFile{Name: mockBlobDigest.Encoded() + ".blob.meta", Data: []byte("blob metadata")}

	mockBootstrapData = []byte("bootstrap")

	mockParentAnnotations = map[string]string{
		"org.example.snapshot.backend": "parent-snapshotter",
		"org.example.snapshot.parent":  "retained",
	}

	mockParentBlobDesc = ocispec.Descriptor{
		MediaType:   nydus.MediaTypeNydusBlob,
		Digest:      mockOtherBlobDigest,
		Size:        int64(len("parent")),
		Annotations: map[string]string{nydus.LayerAnnotationUncompressed: mockOtherBlobDigest.String()},
	}

	mockParentBlobMetaFile = nydus.BlobMetaFile{Name: mockOtherBlobDigest.Encoded() + ".blob.meta", Data: []byte("parent metadata")}

	mockMergedBlobDigest = digest.FromString("merged")

	mockMergedBlobDesc = ocispec.Descriptor{
		MediaType: nydus.MediaTypeNydusBlob,
		Digest:    mockMergedBlobDigest,
		Size:      int64(len("merged")),
		Annotations: map[string]string{
			nydus.LayerAnnotationUncompressed: mockMergedBlobDigest.String(),
			nydus.LayerAnnotationNydusBlob:    "true",
		},
	}
)

func mockBlobFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".blob.meta", mockBlobMetaFile.Data, 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func mockBootstrapFile(t *testing.T) string {
	t.Helper()
	return mockFile(t, filepath.Join(t.TempDir(), "image.boot"), mockBootstrapData)
}

func mockParentArtifact(t *testing.T, cs content.Store) ArtifactOption {
	t.Helper()
	mockNydusManifest(t, cs)
	return ArtifactOption{
		BootstrapPath: mockBootstrapFile(t),
		ParentImages:  []ParentImageMetadata{{Blobs: []ocispec.Descriptor{mockBlobDesc}, BlobMetas: []nydus.BlobMetaFile{mockBlobMetaFile}}},
	}
}

func mockCompactPool(t *testing.T, cs content.Store, builder string) (string, ocispec.Descriptor) {
	t.Helper()
	ctx := context.Background()
	work := t.TempDir()
	var sources []Source
	for _, name := range []string{"a", "b"} {
		dir := filepath.Join(work, name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		mockFile(t, filepath.Join(dir, name), bytes.Repeat([]byte("data-"+name), 16384))
		sources = append(sources, Source{Dir: dir})
	}

	original, err := ConvertMultiSource(ctx, cs, MultiSourceOption{BuilderPath: builder, WorkDir: work, Sources: sources})
	if err != nil {
		t.Fatal(err)
	}

	manifest, _ := readManifest(t, cs, *original)
	blobs, _, _, err := nydus.SplitLayers(manifest.Layers)
	if err != nil {
		t.Fatal(err)
	}
	if len(blobs) != 2 {
		t.Fatalf("unexpected blob layers %v", blobs)
	}

	pool := filepath.Join(work, "blobs")
	if err := os.Mkdir(pool, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, desc := range blobs {
		data, err := content.ReadBlob(ctx, cs, desc)
		if err != nil {
			t.Fatal(err)
		}
		mockFile(t, filepath.Join(pool, desc.Digest.Encoded()), data)
	}
	for name, data := range readBootstrap(t, cs, manifest) {
		mockFile(t, filepath.Join(pool, filepath.Base(name)), data)
	}

	return pool, *original
}

func mockUnexpectedInspect(context.Context, string, string) (map[digest.Digest]struct{}, error) {
	return nil, errors.New("unexpected bootstrap inspection")
}

func mockRepack(report repackReport) func(context.Context, ArtifactOption, string, string, func(repackReport) error) (repackReport, error) {
	return func(_ context.Context, _ ArtifactOption, _, _ string, prepare func(repackReport) error) (repackReport, error) {
		return report, prepare(report)
	}
}

func mockPruneRepack(blobs ...string) func(context.Context, ArtifactOption, string, string, func(repackReport) error) (repackReport, error) {
	return func(_ context.Context, _ ArtifactOption, blobDir, output string, prepare func(repackReport) error) (repackReport, error) {
		report := repackReport{Pruned: true, Blobs: blobs}
		if err := prepare(report); err != nil {
			return report, err
		}

		entries, err := os.ReadDir(blobDir)
		if err != nil {
			return report, err
		}
		if len(entries) > 0 {
			return report, errors.New("prune staged blob data")
		}
		if err := os.MkdirAll(output, 0o700); err != nil {
			return report, err
		}

		return report, os.WriteFile(filepath.Join(output, "image.boot"), []byte("pruned"), 0o600)
	}
}

func mockCompactRepack(ctx context.Context, opt ArtifactOption, blobs, output string, prepare func(repackReport) error) (repackReport, error) {
	report := repackReport{Version: 1, Phase: "result", Blobs: []string{mockOtherBlobDigest.Encoded(), mockBlobDigest.Encoded()}}
	report.Compacted = opt.CompactMaxLayers > 0 && uint(len(report.Blobs)) > opt.CompactMaxLayers
	if err := prepare(report); err != nil || !report.Compacted {
		return report, err
	}

	bootstrap, err := os.ReadFile(opt.BootstrapPath)
	if err != nil {
		return report, err
	}
	if !bytes.Equal(mockBootstrapData, bootstrap) {
		return report, errors.New("compact read a rewritten bootstrap")
	}
	if _, err := os.Stat(filepath.Join(blobs, mockOtherBlobDigest.Encoded())); os.IsNotExist(err) {
		if _, err := os.Stat(filepath.Join(blobs, mockOtherBlobDigest.Encoded()+".descriptor.json")); err != nil {
			return report, err
		}

		reader, err := opt.OpenCompactBlob(ctx, ocispec.Descriptor{Digest: mockOtherBlobDigest}, "bytes=0-0")
		if err != nil {
			return report, err
		}
		if err := reader.Close(); err != nil {
			return report, err
		}
	}
	if _, err := os.Stat(filepath.Join(blobs, mockBlobDigest.Encoded())); err != nil {
		return report, err
	}

	if err := os.MkdirAll(filepath.Join(output, "cache"), 0o700); err != nil {
		return report, err
	}
	for name, data := range map[string]string{
		filepath.Join("cache", "decoded.blob.data"): "cache",
		"image.boot":                                  "compacted",
		mockMergedBlobDigest.Encoded():                "merged",
		mockMergedBlobDigest.Encoded() + ".blob.meta": "merged metadata",
	} {
		if err := os.WriteFile(filepath.Join(output, name), []byte(data), 0o600); err != nil {
			return report, err
		}
	}
	report.Blobs = []string{mockMergedBlobDigest.Encoded()}

	return report, nil
}

func TestConvertNydusArtifacts(t *testing.T) {
	builder := os.Getenv("NYDUS_TEST_BUILDER")
	inspect, run := inspectBootstrapBlobDigests, runArtifactRepack
	defer func() { inspectBootstrapBlobDigests, runArtifactRepack = inspect, run }()

	var fetched, downloaded atomic.Int64
	expectRepackFailure := func(message string) func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
		return func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
			assert := assert.New(t)
			assert.ErrorContains(err, message)
			assert.Nil(result)

			entries, err := os.ReadDir(opt.WorkDir)
			assert.NoError(err)
			assert.Empty(entries)

			data, err := os.ReadFile(opt.BootstrapPath)
			assert.NoError(err)
			assert.Equal(mockBootstrapData, data)
		}
	}
	expectStoreFailure := func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
		assert := assert.New(t)
		assert.ErrorIs(err, errMockStore)
		assert.Nil(result)
	}
	expectUncompacted := func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
		assert := assert.New(t)
		assert.NoError(err)
		assert.False(result.Compacted)

		manifest, _ := readManifest(t, cs, *result.Descriptor)
		assert.Equal("retained", manifest.Annotations["org.example.snapshot"])
		assert.Len(manifest.Layers, 3)

		data, err := os.ReadFile(result.BootstrapPath)
		assert.NoError(err)
		assert.Equal(mockBootstrapData, data)
		assert.Zero(fetched.Load())
	}
	compactOption := func(limit uint) func(t *testing.T, cs content.Store) ArtifactOption {
		return func(t *testing.T, cs content.Store) ArtifactOption {
			return ArtifactOption{
				BootstrapPath:    mockBootstrapFile(t),
				BlobPaths:        []string{mockBlobFile(t, mockBlobDigest.Encoded(), mockBlobData)},
				WorkDir:          t.TempDir(),
				CompactMaxLayers: limit,
				ParentImages: []ParentImageMetadata{{
					Blobs: []ocispec.Descriptor{mockParentBlobDesc, {
						MediaType:   nydus.MediaTypeNydusBlob,
						Digest:      mockStaleBlobDigest,
						Size:        int64(len("stale")),
						Annotations: map[string]string{nydus.LayerAnnotationUncompressed: mockStaleBlobDigest.String()},
					}},
					BlobMetas:   []nydus.BlobMetaFile{mockParentBlobMetaFile, {Name: mockStaleBlobDigest.Encoded() + ".blob.meta", Data: []byte("stale metadata")}},
					Annotations: map[string]string{"org.example.snapshot": "retained"},
				}},
				OpenCompactBlob: func(_ context.Context, desc ocispec.Descriptor, _ string) (io.ReadSeekCloser, error) {
					fetched.Add(1)
					if desc.Digest != mockOtherBlobDigest {
						return nil, errors.New("unexpected blob " + desc.Digest.String())
					}

					return mockBlobReader{Reader: bytes.NewReader([]byte("parent"))}, nil
				},
			}
		}
	}
	remoteOption := func(compressor string) func(t *testing.T, cs content.Store) ArtifactOption {
		return func(t *testing.T, cs content.Store) ArtifactOption {
			source := mockStore(t)
			pool, original := mockCompactPool(t, source, builder)
			parent, err := LoadParentNydusArtifact(context.Background(), source, original, platforms.All)
			if err != nil {
				t.Fatal(err)
			}

			return ArtifactOption{
				BootstrapPath:     filepath.Join(pool, "image.boot"),
				BuilderPath:       builder,
				WorkDir:           t.TempDir(),
				CompactMaxLayers:  1,
				CompactCompressor: compressor,
				ParentImages:      []ParentImageMetadata{parent},
				OpenCompactBlob: func(_ context.Context, desc ocispec.Descriptor, byteRange string) (io.ReadSeekCloser, error) {
					if strings.HasPrefix(byteRange, "bytes=-") {
						return nil, fmt.Errorf("metadata must be reused, not fetched: %s", byteRange)
					}

					file, err := os.Open(filepath.Join(pool, desc.Digest.Encoded()))
					if err != nil {
						return nil, err
					}

					return mockCountedBlobReader{ReadSeekCloser: file, read: &downloaded}, nil
				},
			}
		}
	}
	expectRemote := func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
		assert := assert.New(t)
		assert.NoError(err)
		assert.Len(result.LocalBlobs, 1)

		var total int64
		for _, parent := range opt.ParentImages {
			for _, desc := range parent.Blobs {
				total += desc.Size
			}
		}
		assert.Positive(downloaded.Load())
		assert.Less(downloaded.Load(), total)

		local, err := ConvertNydusArtifacts(context.Background(), cs, ArtifactOption{
			BootstrapPath:     opt.BootstrapPath,
			BlobDir:           filepath.Dir(opt.BootstrapPath),
			BuilderPath:       opt.BuilderPath,
			WorkDir:           t.TempDir(),
			CompactMaxLayers:  1,
			CompactCompressor: opt.CompactCompressor,
		})
		assert.NoError(err)

		localManifest, _ := readManifest(t, cs, *local.Descriptor)
		localBlobs, _, _, err := nydus.SplitLayers(localManifest.Layers)
		assert.NoError(err)
		manifest, _ := readManifest(t, cs, *result.Descriptor)
		blobs, _, _, err := nydus.SplitLayers(manifest.Layers)
		assert.NoError(err)
		assert.Equal(localBlobs, blobs)

		localBootstrap, err := os.ReadFile(local.BootstrapPath)
		assert.NoError(err)
		bootstrap, err := os.ReadFile(result.BootstrapPath)
		assert.NoError(err)
		assert.Equal(localBootstrap, bootstrap)

		output := filepath.Dir(result.BootstrapPath)
		assert.NoError(exec.Command(opt.BuilderPath, "check", "--bootstrap", filepath.Join(output, "image.boot"), "--blob-dir", output, "--output", "json").Run())
	}

	tests := []struct {
		name       string
		builder    bool
		referenced map[digest.Digest]struct{}
		inspect    func(ctx context.Context, builderPath, bootstrapPath string) (map[digest.Digest]struct{}, error)
		run        func(ctx context.Context, opt ArtifactOption, blobs, output string, prepare func(repackReport) error) (repackReport, error)
		failAt     int
		opt        func(t *testing.T, cs content.Store) ArtifactOption
		expect     func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error)
	}{
		{
			name: "prune unused parent blob",
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				return ArtifactOption{BootstrapPath: mockBootstrapFile(t), ParentImages: []ParentImageMetadata{{
					Blobs:     []ocispec.Descriptor{{Digest: mockStaleBlobDigest}},
					BlobMetas: []nydus.BlobMetaFile{{Name: mockStaleBlobDigest.Encoded() + ".blob.meta"}},
				}}}
			},
			expect: func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(result.ExternalBlobs)
				assert.Empty(result.LocalBlobs)

				manifest, _ := readManifest(t, cs, *result.Descriptor)
				assert.Len(manifest.Layers, 1)
				assert.True(slices.ContainsFunc(manifest.Layers, nydus.IsBootstrap))

				parent, err := LoadParentNydusArtifact(context.Background(), cs, *result.Descriptor, platforms.All)
				assert.NoError(err)
				assert.Empty(parent.Blobs)
				assert.Empty(parent.BlobMetas)
			},
		},
		{
			name: "package bootstrap only",
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				return ArtifactOption{BootstrapPath: mockBootstrapFile(t)}
			},
			expect: func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(result.ExternalBlobs)
				assert.Empty(result.LocalBlobs)

				manifest, _ := readManifest(t, cs, *result.Descriptor)
				assert.Len(manifest.Layers, 1)
				assert.True(slices.ContainsFunc(manifest.Layers, nydus.IsBootstrap))

				parent, err := LoadParentNydusArtifact(context.Background(), cs, *result.Descriptor, platforms.All)
				assert.NoError(err)
				assert.Empty(parent.Blobs)
				assert.Empty(parent.BlobMetas)
			},
		},
		{
			name: "ignore empty blob directory",
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				return ArtifactOption{BootstrapPath: mockBootstrapFile(t), BlobDir: t.TempDir()}
			},
			expect: func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(result.ExternalBlobs)
				assert.Empty(result.LocalBlobs)

				manifest, _ := readManifest(t, cs, *result.Descriptor)
				assert.Len(manifest.Layers, 1)
				assert.True(slices.ContainsFunc(manifest.Layers, nydus.IsBootstrap))

				parent, err := LoadParentNydusArtifact(context.Background(), cs, *result.Descriptor, platforms.All)
				assert.NoError(err)
				assert.Empty(parent.Blobs)
				assert.Empty(parent.BlobMetas)
			},
		},
		{
			name:       "reject missing referenced blob",
			referenced: map[digest.Digest]struct{}{mockStaleBlobDigest: {}},
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				return ArtifactOption{BootstrapPath: mockBootstrapFile(t)}
			},
			expect: func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "bootstrap references missing nydus blob")
				assert.Nil(result)
			},
		},
		{
			name:       "reject referenced blob absent from empty blob directory",
			referenced: map[digest.Digest]struct{}{mockStaleBlobDigest: {}},
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				return ArtifactOption{BootstrapPath: mockBootstrapFile(t), BlobDir: t.TempDir()}
			},
			expect: func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "bootstrap references missing nydus blob")
				assert.Nil(result)
			},
		},
		{
			name:       "package local blob with parent and snapshot annotations",
			referenced: map[digest.Digest]struct{}{mockBlobDigest: {}},
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				return ArtifactOption{
					BootstrapPath: mockBootstrapFile(t),
					BlobPaths:     []string{mockBlobFile(t, mockBlobDigest.Encoded(), mockBlobData)},
					ParentImages:  []ParentImageMetadata{{Annotations: mockParentAnnotations}},
					Platform:      mockPlatform,
					Annotations: map[string]string{
						"org.example.snapshot.backend":  "remote-snapshotter",
						"org.example.snapshot.digest":   "xxh3:0123456789abcdef",
						"org.example.snapshot.size":     "10737418240",
						"org.example.snapshot.encoding": "sparse-v1",
					},
				}
			},
			expect: func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]LocalBlob{{Path: opt.BlobPaths[0], Descriptor: mockBlobDesc}}, result.LocalBlobs)

				manifest, config := readManifest(t, cs, *result.Descriptor)
				blobs, _, _, err := nydus.SplitLayers(manifest.Layers)
				assert.NoError(err)
				assert.Equal([]ocispec.Descriptor{mockBlobDesc}, blobs)
				assert.Equal(map[string]string{
					"org.example.snapshot.backend":  "remote-snapshotter",
					"org.example.snapshot.digest":   "xxh3:0123456789abcdef",
					"org.example.snapshot.size":     "10737418240",
					"org.example.snapshot.encoding": "sparse-v1",
					"org.example.snapshot.parent":   "retained",
				}, manifest.Annotations)
				assert.Equal(map[string]string{
					"org.example.snapshot.backend": "parent-snapshotter",
					"org.example.snapshot.parent":  "retained",
				}, mockParentAnnotations)

				var diffIDs []digest.Digest
				for _, layer := range manifest.Layers {
					diffIDs = append(diffIDs, digest.Digest(layer.Annotations[nydus.LayerAnnotationUncompressed]))
				}
				assert.Equal(diffIDs, config.RootFS.DiffIDs)

				entries := readBootstrap(t, cs, manifest)
				assert.Equal(mockBootstrapData, entries[nydus.BootstrapFileNameInLayer])
				assert.Equal(mockBlobMetaFile.Data, entries["image/"+mockBlobMetaFile.Name])
			},
		},
		{
			name:       "keep referenced parent blob",
			referenced: map[digest.Digest]struct{}{mockBlobDigest: {}},
			opt:        mockParentArtifact,
			expect: func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]ocispec.Descriptor{mockBlobDesc}, result.ExternalBlobs)
				assert.Empty(result.LocalBlobs)
			},
		},
		{
			name:       "fail to open bootstrap writer",
			referenced: map[digest.Digest]struct{}{mockBlobDigest: {}},
			failAt:     1,
			opt:        mockParentArtifact,
			expect:     expectStoreFailure,
		},
		{
			name:       "fail to restore bootstrap labels",
			referenced: map[digest.Digest]struct{}{mockBlobDigest: {}},
			failAt:     2,
			opt:        mockParentArtifact,
			expect:     expectStoreFailure,
		},
		{
			name:       "fail to stat written bootstrap",
			referenced: map[digest.Digest]struct{}{mockBlobDigest: {}},
			failAt:     3,
			opt:        mockParentArtifact,
			expect:     expectStoreFailure,
		},
		{
			name:       "fail to open config writer",
			referenced: map[digest.Digest]struct{}{mockBlobDigest: {}},
			failAt:     4,
			opt:        mockParentArtifact,
			expect:     expectStoreFailure,
		},
		{
			name:       "fail to stat written config",
			referenced: map[digest.Digest]struct{}{mockBlobDigest: {}},
			failAt:     5,
			opt:        mockParentArtifact,
			expect:     expectStoreFailure,
		},
		{
			name:       "fail to open manifest writer",
			referenced: map[digest.Digest]struct{}{mockBlobDigest: {}},
			failAt:     6,
			opt:        mockParentArtifact,
			expect:     expectStoreFailure,
		},
		{
			name:       "fail to stat written manifest",
			referenced: map[digest.Digest]struct{}{mockBlobDigest: {}},
			failAt:     7,
			opt:        mockParentArtifact,
			expect:     expectStoreFailure,
		},
		{
			name: "reject missing bootstrap path",
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				return ArtifactOption{}
			},
			expect: func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "--bootstrap is required when packaging nydus artifacts")
				assert.Nil(result)
			},
		},
		{
			name:    "reject missing bootstrap file",
			inspect: bootstrapBlobDigestsFromNydusCheck,
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				return ArtifactOption{BootstrapPath: filepath.Join(t.TempDir(), "missing")}
			},
			expect: func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "with nydus check")
				assert.Nil(result)
			},
		},
		{
			name:    "reject invalid bootstrap file",
			inspect: bootstrapBlobDigestsFromNydusCheck,
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				return ArtifactOption{BootstrapPath: mockFile(t, filepath.Join(t.TempDir(), "data"), []byte("invalid metadata"))}
			},
			expect: func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "with nydus check")
				assert.Nil(result)
			},
		},
		{
			name: "reject missing append file",
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				return ArtifactOption{BootstrapPath: mockBootstrapFile(t), AppendInBootstrap: []string{filepath.Join(t.TempDir(), "missing")}}
			},
			expect: func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
				assert.Nil(result)
			},
		},
		{
			name: "reject missing blob path",
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				return ArtifactOption{BootstrapPath: mockBootstrapFile(t), BlobPaths: []string{filepath.Join(t.TempDir(), "missing")}}
			},
			expect: func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "stat blob")
				assert.Nil(result)
			},
		},
		{
			name: "reject multiple parent images",
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				return ArtifactOption{BootstrapPath: mockBootstrapFile(t), ParentImages: make([]ParentImageMetadata, 2)}
			},
			expect: func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "only one --parent-image is supported")
				assert.Nil(result)
			},
		},
		{
			name:    "reject missing builder",
			inspect: bootstrapBlobDigestsFromNydusCheck,
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				path := mockFile(t, filepath.Join(t.TempDir(), "data"), []byte("invalid metadata"))
				return ArtifactOption{BootstrapPath: path, BlobPaths: []string{path}, BuilderPath: "/nonexistent/nydus"}
			},
			expect: func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "with nydus check")
				assert.Nil(result)
			},
		},
		{
			name: "reject invalid repack references",
			run:  mockRepack(repackReport{Compacted: true, Blobs: []string{"invalid"}}),
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				return ArtifactOption{BootstrapPath: mockBootstrapFile(t), WorkDir: filepath.Join(t.TempDir(), "scratch"), Prune: true}
			},
			expect: expectRepackFailure("invalid repack blob digest"),
		},
		{
			name: "reject missing repack input",
			run:  mockRepack(repackReport{Compacted: true, Blobs: []string{mockBlobDigest.Encoded()}}),
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				return ArtifactOption{BootstrapPath: mockBootstrapFile(t), WorkDir: filepath.Join(t.TempDir(), "scratch"), Prune: true}
			},
			expect: expectRepackFailure("bootstrap references missing nydus blob"),
		},
		{
			name: "reject repack input without blob meta",
			run:  mockRepack(repackReport{Compacted: true, Blobs: []string{mockBlobDigest.Encoded()}}),
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				return ArtifactOption{
					BootstrapPath: mockBootstrapFile(t),
					WorkDir:       filepath.Join(t.TempDir(), "scratch"),
					Prune:         true,
					ParentImages:  []ParentImageMetadata{{Blobs: []ocispec.Descriptor{{Digest: mockBlobDigest, Size: int64(len(mockBlobData))}}}},
				}
			},
			expect: expectRepackFailure("missing blob meta"),
		},
		{
			name: "reject local repack input without blob meta",
			run:  mockRepack(repackReport{Compacted: true, Blobs: []string{mockBlobDigest.Encoded()}}),
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				return ArtifactOption{
					BootstrapPath: mockBootstrapFile(t),
					WorkDir:       filepath.Join(t.TempDir(), "scratch"),
					Prune:         true,
					BlobPaths:     []string{mockFile(t, filepath.Join(t.TempDir(), mockBlobDigest.Encoded()), mockBlobData)},
				}
			},
			expect: expectRepackFailure("inspect blob"),
		},
		{
			name: "reject conflicting repack input",
			run:  mockRepack(repackReport{Compacted: true, Blobs: []string{mockBlobDigest.Encoded()}}),
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				return ArtifactOption{
					BootstrapPath: mockBootstrapFile(t),
					WorkDir:       filepath.Join(t.TempDir(), "scratch"),
					Prune:         true,
					BlobPaths:     []string{mockBlobFile(t, mockBlobDigest.Encoded(), []byte("different"))},
					ParentImages:  []ParentImageMetadata{{Blobs: []ocispec.Descriptor{{Digest: mockBlobDigest, Size: int64(len(mockBlobData))}}}},
				}
			},
			expect: expectRepackFailure("conflicting descriptors for nydus blob"),
		},
		{
			name: "reject empty compact result",
			run:  mockRepack(repackReport{Compacted: true}),
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				return ArtifactOption{BootstrapPath: mockBootstrapFile(t), WorkDir: filepath.Join(t.TempDir(), "scratch"), Prune: true}
			},
			expect: expectRepackFailure("compact produced 0 blobs, expected one"),
		},
		{
			name: "reject missing compact result",
			run: func(_ context.Context, _ ArtifactOption, _, _ string, prepare func(repackReport) error) (repackReport, error) {
				report := repackReport{Compacted: true}
				if err := prepare(report); err != nil {
					return report, err
				}
				report.Blobs = []string{mockBlobDigest.Encoded()}

				return report, nil
			},
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				return ArtifactOption{BootstrapPath: mockBootstrapFile(t), WorkDir: filepath.Join(t.TempDir(), "scratch"), Prune: true}
			},
			expect: expectRepackFailure("open blob"),
		},
		{
			name: "reject invalid parent config",
			run:  mockPruneRepack(),
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				return ArtifactOption{
					BootstrapPath: mockBootstrapFile(t),
					WorkDir:       filepath.Join(t.TempDir(), "scratch"),
					Prune:         true,
					ParentImages:  []ParentImageMetadata{{Config: json.RawMessage(`invalid`)}},
				}
			},
			expect: expectRepackFailure("build image config"),
		},
		{
			name:    "prune every parent blob without fetching data",
			inspect: mockUnexpectedInspect,
			run:     mockPruneRepack(),
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				return ArtifactOption{
					BootstrapPath: mockBootstrapFile(t),
					WorkDir:       t.TempDir(),
					Prune:         true,
					ParentImages: []ParentImageMetadata{{
						Blobs: []ocispec.Descriptor{mockBlobDesc, {Digest: mockStaleBlobDigest, Size: 5, MediaType: nydus.MediaTypeNydusBlob}},
						BlobMetas: []nydus.BlobMetaFile{
							mockBlobMetaFile,
							{Name: mockStaleBlobDigest.Encoded() + ".blob.meta", Data: []byte("stale metadata")},
						},
					}},
					OpenCompactBlob: mockUnavailableBlob,
				}
			},
			expect: func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.True(result.Pruned)
				assert.False(result.Compacted)
				assert.Empty(result.ExternalBlobs)
				assert.Empty(result.LocalBlobs)

				data, err := os.ReadFile(result.BootstrapPath)
				assert.NoError(err)
				assert.Equal([]byte("pruned"), data)

				data, err = os.ReadFile(opt.BootstrapPath)
				assert.NoError(err)
				assert.Equal(mockBootstrapData, data)
			},
		},
		{
			name:    "prune dead parent blob without fetching data",
			inspect: mockUnexpectedInspect,
			run:     mockPruneRepack(mockBlobDigest.Encoded()),
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				return ArtifactOption{
					BootstrapPath: mockBootstrapFile(t),
					WorkDir:       t.TempDir(),
					Prune:         true,
					ParentImages: []ParentImageMetadata{{
						Blobs: []ocispec.Descriptor{mockBlobDesc, {Digest: mockStaleBlobDigest, Size: 5, MediaType: nydus.MediaTypeNydusBlob}},
						BlobMetas: []nydus.BlobMetaFile{
							mockBlobMetaFile,
							{Name: mockStaleBlobDigest.Encoded() + ".blob.meta", Data: []byte("stale metadata")},
						},
					}},
					OpenCompactBlob: mockUnavailableBlob,
				}
			},
			expect: func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.True(result.Pruned)
				assert.False(result.Compacted)
				assert.Equal([]ocispec.Descriptor{mockBlobDesc}, result.ExternalBlobs)
				assert.Empty(result.LocalBlobs)

				data, err := os.ReadFile(result.BootstrapPath)
				assert.NoError(err)
				assert.Equal([]byte("pruned"), data)

				data, err = os.ReadFile(opt.BootstrapPath)
				assert.NoError(err)
				assert.Equal(mockBootstrapData, data)
			},
		},
		{
			name:       "skip compaction without data layer limit",
			referenced: map[digest.Digest]struct{}{mockBlobDigest: {}, mockOtherBlobDigest: {}},
			run:        mockCompactRepack,
			opt:        compactOption(0),
			expect:     expectUncompacted,
		},
		{
			name:   "skip compaction at data layer limit",
			run:    mockCompactRepack,
			opt:    compactOption(2),
			expect: expectUncompacted,
		},
		{
			name: "compact above data layer limit",
			run:  mockCompactRepack,
			opt:  compactOption(1),
			expect: func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.True(result.Compacted)
				assert.Empty(result.ExternalBlobs)
				assert.Len(result.LocalBlobs, 1)
				for _, blob := range result.LocalBlobs {
					assert.FileExists(blob.Path)
				}

				manifest, _ := readManifest(t, cs, *result.Descriptor)
				assert.Equal("retained", manifest.Annotations["org.example.snapshot"])
				blobs, bootstrap, _, err := nydus.SplitLayers(manifest.Layers)
				assert.NoError(err)
				assert.Equal([]ocispec.Descriptor{mockMergedBlobDesc}, blobs)
				assert.NotNil(bootstrap)

				data, err := os.ReadFile(result.BootstrapPath)
				assert.NoError(err)
				assert.Equal([]byte("compacted"), data)

				output := filepath.Dir(result.BootstrapPath)
				assert.NoDirExists(filepath.Join(output, "cache"))
				assert.NoDirExists(filepath.Join(filepath.Dir(output), "blobs"))
				assert.Equal(int64(1), fetched.Load())
			},
		},
		{
			name: "compact with local copy of parent blob",
			run:  mockCompactRepack,
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				dir := t.TempDir()
				mockFile(t, filepath.Join(dir, mockBlobDigest.Encoded()), mockBlobData)
				mockFile(t, filepath.Join(dir, mockBlobMetaFile.Name), mockBlobMetaFile.Data)
				mockFile(t, filepath.Join(dir, mockOtherBlobDigest.Encoded()), []byte("parent"))
				mockFile(t, filepath.Join(dir, mockParentBlobMetaFile.Name), mockParentBlobMetaFile.Data)

				return ArtifactOption{
					BootstrapPath:    mockBootstrapFile(t),
					BlobDir:          dir,
					WorkDir:          t.TempDir(),
					CompactMaxLayers: 1,
					ParentImages: []ParentImageMetadata{{
						Blobs:     []ocispec.Descriptor{mockParentBlobDesc},
						BlobMetas: []nydus.BlobMetaFile{mockParentBlobMetaFile},
					}},
					OpenCompactBlob: mockUnavailableBlob,
				}
			},
			expect: func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(result.ExternalBlobs)
				assert.Len(result.LocalBlobs, 1)
			},
		},
		{
			name:    "compact local blobs with real builder",
			builder: true,
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				pool, _ := mockCompactPool(t, cs, builder)
				return ArtifactOption{
					BootstrapPath:    filepath.Join(pool, "image.boot"),
					BlobDir:          pool,
					BuilderPath:      builder,
					WorkDir:          t.TempDir(),
					CompactMaxLayers: 1,
				}
			},
			expect: func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Len(result.LocalBlobs, 1)
				assert.Empty(result.ExternalBlobs)

				manifest, _ := readManifest(t, cs, *result.Descriptor)
				assert.Len(manifest.Layers, 2)

				output := filepath.Dir(result.BootstrapPath)
				assert.NoError(exec.Command(opt.BuilderPath, "check", "--bootstrap", filepath.Join(output, "image.boot"), "--blob-dir", output, "--output", "json").Run())
			},
		},
		{
			name:    "compact decoded local blobs with real builder",
			builder: true,
			opt: func(t *testing.T, cs content.Store) ArtifactOption {
				pool, _ := mockCompactPool(t, cs, builder)
				return ArtifactOption{
					BootstrapPath:     filepath.Join(pool, "image.boot"),
					BlobDir:           pool,
					BuilderPath:       builder,
					WorkDir:           t.TempDir(),
					CompactMaxLayers:  1,
					CompactCompressor: "none",
				}
			},
			expect: func(t *testing.T, cs content.Store, opt ArtifactOption, result *ArtifactResult, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Len(result.LocalBlobs, 1)
			},
		},
		{
			name:    "compact remote parent blobs with real builder",
			builder: true,
			opt:     remoteOption(""),
			expect:  expectRemote,
		},
		{
			name:    "compact decoded remote parent blobs with real builder",
			builder: true,
			opt:     remoteOption("none"),
			expect:  expectRemote,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.builder && builder == "" {
				t.Skip("set NYDUS_TEST_BUILDER to run real builder compaction tests")
			}
			inspectBootstrapBlobDigests = func(context.Context, string, string) (map[digest.Digest]struct{}, error) {
				return tc.referenced, nil
			}
			if tc.inspect != nil {
				inspectBootstrapBlobDigests = tc.inspect
			}
			runArtifactRepack = run
			if tc.run != nil {
				runArtifactRepack = tc.run
			}
			fetched.Store(0)
			downloaded.Store(0)

			cs := mockStore(t)
			opt := tc.opt(t, cs)
			result, err := ConvertNydusArtifacts(context.Background(), &mockContentStore{Store: cs, failAt: tc.failAt}, opt)

			tc.expect(t, cs, opt, result, err)
		})
	}
}

func TestLoadParentNydusArtifact(t *testing.T) {
	tests := []struct {
		name     string
		manifest func(t *testing.T, cs content.Store) ocispec.Descriptor
		failAt   int
		expect   func(t *testing.T, parent ParentImageMetadata, err error)
	}{
		{
			name: "load blobs, blob metas and manifest annotations",
			manifest: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				ctx := context.Background()
				bootstrap, err := oci.WriteBootstrapLayer(ctx, cs, mockBootstrapData, []nydus.BlobMetaFile{mockBlobMetaFile}, nil)
				if err != nil {
					t.Fatal(err)
				}

				config, err := oci.WriteJSON(ctx, cs, ocispec.Image{
					Platform: mockPlatform,
					RootFS:   ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{mockBlobDigest}},
				}, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig}, nil)
				if err != nil {
					t.Fatal(err)
				}

				manifest, err := oci.WriteJSON(ctx, cs, ocispec.Manifest{
					MediaType:   ocispec.MediaTypeImageManifest,
					Config:      *config,
					Layers:      []ocispec.Descriptor{mockBlobDesc, *bootstrap},
					Annotations: mockParentAnnotations,
				}, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, nil)
				if err != nil {
					t.Fatal(err)
				}

				return *manifest
			},
			expect: func(t *testing.T, parent ParentImageMetadata, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]ocispec.Descriptor{mockBlobDesc}, parent.Blobs)
				assert.Equal([]nydus.BlobMetaFile{mockBlobMetaFile}, parent.BlobMetas)
				assert.Equal(mockParentAnnotations, parent.Annotations)
			},
		},
		{
			name: "reject oci layer",
			manifest: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockManifest(t, cs, mockGzipLayer)
			},
			expect: func(t *testing.T, parent ParentImageMetadata, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "is neither a nydus blob nor a nydus bootstrap")
				assert.Empty(parent)
			},
		},
		{
			name: "reject optimized blob",
			manifest: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockManifest(t, cs,
					mockBlob(t, cs, "data blob"),
					mockBlob(t, cs, "ondemand blob", nydus.LayerAnnotationNydusBlobOptimized),
					mockBootstrapLayer,
				)
			},
			expect: func(t *testing.T, parent ParentImageMetadata, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "--parent-image does not support optimized nydus blob layers")
				assert.Empty(parent)
			},
		},
		{
			name: "reject missing bootstrap",
			manifest: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockManifest(t, cs, mockBlob(t, cs, "data blob"))
			},
			expect: func(t *testing.T, parent ParentImageMetadata, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "parent image has no nydus bootstrap layer")
				assert.Empty(parent)
			},
		},
		{
			name: "load blobs and blob metas from index",
			manifest: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs, mockNydusManifest(t, cs))
			},
			expect: func(t *testing.T, parent ParentImageMetadata, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]ocispec.Descriptor{mockBlobDesc}, parent.Blobs)
				assert.Equal([]nydus.BlobMetaFile{mockBlobMetaFile}, parent.BlobMetas)
			},
		},
		{
			name: "reject missing blob meta",
			manifest: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				bootstrap, err := oci.WriteBootstrapLayer(context.Background(), cs, mockBootstrapData, nil, nil)
				if err != nil {
					t.Fatal(err)
				}

				return mockManifest(t, cs, mockBlobDesc, *bootstrap)
			},
			expect: func(t *testing.T, parent ParentImageMetadata, err error) {
				assert := assert.New(t)
				assert.EqualError(err, fmt.Sprintf("missing blob meta %q", mockBlobMetaFile.Name))
				assert.Empty(parent)
			},
		},
		{
			name: "fail to read index",
			manifest: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs, mockNydusManifest(t, cs))
			},
			failAt: 1,
			expect: func(t *testing.T, parent ParentImageMetadata, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
				assert.Empty(parent)
			},
		},
		{
			name: "fail to read manifest",
			manifest: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs, mockNydusManifest(t, cs))
			},
			failAt: 2,
			expect: func(t *testing.T, parent ParentImageMetadata, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
				assert.Empty(parent)
			},
		},
		{
			name: "fail to open bootstrap",
			manifest: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs, mockNydusManifest(t, cs))
			},
			failAt: 3,
			expect: func(t *testing.T, parent ParentImageMetadata, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
				assert.Empty(parent)
			},
		},
		{
			name: "fail to read config",
			manifest: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs, mockNydusManifest(t, cs))
			},
			failAt: 4,
			expect: func(t *testing.T, parent ParentImageMetadata, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
				assert.Empty(parent)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := mockStore(t)
			manifest := tc.manifest(t, cs)
			parent, err := LoadParentNydusArtifact(context.Background(), &mockContentStore{Store: cs, failAt: tc.failAt}, manifest, platforms.All)

			tc.expect(t, parent, err)
		})
	}
}

func TestDeduplicateArtifactBlobs(t *testing.T) {
	tests := []struct {
		name     string
		descs    []ocispec.Descriptor
		metas    []nydus.BlobMetaFile
		external []ocispec.Descriptor
		local    []LocalBlob
		expect   func(t *testing.T, descs []ocispec.Descriptor, metas []nydus.BlobMetaFile, external []ocispec.Descriptor, local []LocalBlob, err error)
	}{
		{
			name:     "prefer external blob over local copy",
			descs:    []ocispec.Descriptor{mockBlobDesc, mockBlobDesc},
			metas:    []nydus.BlobMetaFile{mockBlobMetaFile, mockBlobMetaFile},
			external: []ocispec.Descriptor{mockBlobDesc},
			local:    []LocalBlob{{Path: "/local/blob", Descriptor: mockBlobDesc}},
			expect: func(t *testing.T, descs []ocispec.Descriptor, metas []nydus.BlobMetaFile, external []ocispec.Descriptor, local []LocalBlob, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]ocispec.Descriptor{mockBlobDesc}, descs)
				assert.Equal([]nydus.BlobMetaFile{mockBlobMetaFile}, metas)
				assert.Equal([]ocispec.Descriptor{mockBlobDesc}, external)
				assert.Empty(local)
			},
		},
		{
			name: "reject conflicting descriptors",
			descs: []ocispec.Descriptor{mockBlobDesc, {
				MediaType:   mockBlobDesc.MediaType,
				Digest:      mockBlobDesc.Digest,
				Size:        mockBlobDesc.Size + 1,
				Annotations: mockBlobDesc.Annotations,
			}},
			expect: func(t *testing.T, descs []ocispec.Descriptor, metas []nydus.BlobMetaFile, external []ocispec.Descriptor, local []LocalBlob, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "conflicting descriptors for nydus blob "+mockBlobDigest.String())
			},
		},
		{
			name:  "reject conflicting blob metas",
			descs: []ocispec.Descriptor{mockBlobDesc},
			metas: []nydus.BlobMetaFile{mockBlobMetaFile, {Name: mockBlobMetaFile.Name, Data: []byte("different metadata")}},
			expect: func(t *testing.T, descs []ocispec.Descriptor, metas []nydus.BlobMetaFile, external []ocispec.Descriptor, local []LocalBlob, err error) {
				assert := assert.New(t)
				assert.EqualError(err, fmt.Sprintf("conflicting blob meta %q", mockBlobMetaFile.Name))
			},
		},
		{
			name:     "deduplicate external blobs",
			descs:    []ocispec.Descriptor{mockBlobDesc, mockBlobDesc},
			metas:    []nydus.BlobMetaFile{mockBlobMetaFile},
			external: []ocispec.Descriptor{mockBlobDesc, mockBlobDesc},
			expect: func(t *testing.T, descs []ocispec.Descriptor, metas []nydus.BlobMetaFile, external []ocispec.Descriptor, local []LocalBlob, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]ocispec.Descriptor{mockBlobDesc}, external)
				assert.Empty(local)
			},
		},
		{
			name:  "deduplicate local blobs",
			descs: []ocispec.Descriptor{mockBlobDesc, mockBlobDesc},
			metas: []nydus.BlobMetaFile{mockBlobMetaFile},
			local: []LocalBlob{{Descriptor: mockBlobDesc}, {Descriptor: mockBlobDesc}},
			expect: func(t *testing.T, descs []ocispec.Descriptor, metas []nydus.BlobMetaFile, external []ocispec.Descriptor, local []LocalBlob, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]LocalBlob{{Descriptor: mockBlobDesc}}, local)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			descs, metas, external, local, err := deduplicateArtifactBlobs(tc.descs, tc.metas, tc.external, tc.local)
			tc.expect(t, descs, metas, external, local, err)
		})
	}
}

func TestValidateArtifactBlobMetas(t *testing.T) {
	tests := []struct {
		name   string
		descs  []ocispec.Descriptor
		metas  []nydus.BlobMetaFile
		expect func(t *testing.T, err error)
	}{
		{
			name:  "accept matching descriptor and meta",
			descs: []ocispec.Descriptor{mockBlobDesc},
			metas: []nydus.BlobMetaFile{mockBlobMetaFile},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name:  "reject missing meta",
			descs: []ocispec.Descriptor{mockBlobDesc},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, fmt.Sprintf("missing blob meta %q", mockBlobMetaFile.Name))
			},
		},
		{
			name:  "reject unexpected meta",
			metas: []nydus.BlobMetaFile{mockBlobMetaFile},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, fmt.Sprintf("blob meta %q does not match any nydus blob layer", mockBlobMetaFile.Name))
			},
		},
		{
			name:  "reject mismatched meta",
			descs: []ocispec.Descriptor{mockBlobDesc},
			metas: []nydus.BlobMetaFile{{Name: mockOtherBlobDigest.Encoded() + ".blob.meta"}},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, fmt.Sprintf("blob meta %q does not match any nydus blob layer", mockOtherBlobDigest.Encoded()+".blob.meta"))
			},
		},
		{
			name:  "reject duplicate descriptor",
			descs: []ocispec.Descriptor{mockBlobDesc, mockBlobDesc},
			metas: []nydus.BlobMetaFile{mockBlobMetaFile},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "duplicate nydus blob layer "+mockBlobDigest.String())
			},
		},
		{
			name:  "reject duplicate meta",
			descs: []ocispec.Descriptor{mockBlobDesc},
			metas: []nydus.BlobMetaFile{mockBlobMetaFile, mockBlobMetaFile},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, fmt.Sprintf("duplicate blob meta %q", mockBlobMetaFile.Name))
			},
		},
		{
			name:  "reject non sha256 descriptor",
			descs: []ocispec.Descriptor{{Digest: digest.Digest("sha512:" + strings.Repeat("0", 128))}},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "nydus blob layer sha512:"+strings.Repeat("0", 128)+" is not a sha256 digest")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, validateArtifactBlobMetas(tc.descs, tc.metas))
		})
	}
}

func TestFilterArtifactBlobsByReferences(t *testing.T) {
	tests := []struct {
		name       string
		referenced map[digest.Digest]struct{}
		descs      []ocispec.Descriptor
		metas      []nydus.BlobMetaFile
		external   []ocispec.Descriptor
		expect     func(t *testing.T, descs []ocispec.Descriptor, metas []nydus.BlobMetaFile, external []ocispec.Descriptor, err error)
	}{
		{
			name:       "keep referenced descriptors",
			referenced: map[digest.Digest]struct{}{mockBlobDigest: {}, mockOtherBlobDigest: {}},
			descs:      []ocispec.Descriptor{{Digest: mockBlobDigest}, {Digest: mockOtherBlobDigest}},
			metas:      []nydus.BlobMetaFile{{Name: mockBlobMetaFile.Name}, {Name: mockOtherBlobDigest.Encoded() + ".blob.meta"}},
			expect: func(t *testing.T, descs []ocispec.Descriptor, metas []nydus.BlobMetaFile, external []ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]ocispec.Descriptor{{Digest: mockBlobDigest}, {Digest: mockOtherBlobDigest}}, descs)
				assert.Equal([]nydus.BlobMetaFile{{Name: mockBlobMetaFile.Name}, {Name: mockOtherBlobDigest.Encoded() + ".blob.meta"}}, metas)
				assert.Empty(external)
			},
		},
		{
			name:       "reject referenced blob without descriptor",
			referenced: map[digest.Digest]struct{}{mockBlobDigest: {}, mockOtherBlobDigest: {}},
			descs:      []ocispec.Descriptor{{Digest: mockBlobDigest}},
			metas:      []nydus.BlobMetaFile{{Name: mockBlobMetaFile.Name}},
			expect: func(t *testing.T, descs []ocispec.Descriptor, metas []nydus.BlobMetaFile, external []ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "bootstrap references missing nydus blob "+mockOtherBlobDigest.String())
			},
		},
		{
			name:       "filter unreferenced descriptor",
			referenced: map[digest.Digest]struct{}{mockBlobDigest: {}},
			descs:      []ocispec.Descriptor{{Digest: mockBlobDigest}, {Digest: mockStaleBlobDigest}},
			metas:      []nydus.BlobMetaFile{{Name: mockBlobMetaFile.Name}, {Name: mockStaleBlobDigest.Encoded() + ".blob.meta"}},
			expect: func(t *testing.T, descs []ocispec.Descriptor, metas []nydus.BlobMetaFile, external []ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]ocispec.Descriptor{{Digest: mockBlobDigest}}, descs)
				assert.Equal([]nydus.BlobMetaFile{{Name: mockBlobMetaFile.Name}}, metas)
				assert.Empty(external)
			},
		},
		{
			name:       "filter unreferenced external descriptor",
			referenced: map[digest.Digest]struct{}{mockBlobDigest: {}},
			descs:      []ocispec.Descriptor{{Digest: mockBlobDigest}, {Digest: mockStaleBlobDigest}},
			metas:      []nydus.BlobMetaFile{{Name: mockBlobMetaFile.Name}, {Name: mockStaleBlobDigest.Encoded() + ".blob.meta"}},
			external:   []ocispec.Descriptor{{Digest: mockBlobDigest}, {Digest: mockStaleBlobDigest}},
			expect: func(t *testing.T, descs []ocispec.Descriptor, metas []nydus.BlobMetaFile, external []ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]ocispec.Descriptor{{Digest: mockBlobDigest}}, descs)
				assert.Equal([]nydus.BlobMetaFile{{Name: mockBlobMetaFile.Name}}, metas)
				assert.Equal([]ocispec.Descriptor{{Digest: mockBlobDigest}}, external)
			},
		},
		{
			name:  "drop every descriptor when bootstrap has no device table",
			descs: []ocispec.Descriptor{{Digest: mockBlobDigest}},
			metas: []nydus.BlobMetaFile{{Name: mockBlobMetaFile.Name}},
			expect: func(t *testing.T, descs []ocispec.Descriptor, metas []nydus.BlobMetaFile, external []ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(descs)
				assert.Empty(metas)
				assert.Empty(external)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			descs, metas, external, _, err := filterArtifactBlobsByReferences(tc.referenced, tc.descs, tc.metas, tc.external, nil)
			tc.expect(t, descs, metas, external, err)
		})
	}
}

func TestBootstrapBlobDigestsFromNydusCheck(t *testing.T) {
	tests := []struct {
		name   string
		output string
		expect func(t *testing.T, referenced map[digest.Digest]struct{}, err error)
	}{
		{
			name:   "return referenced blobs",
			output: fmt.Sprintf(`{"blobs":[{"slot_sha256":%q}]}`, mockBlobDigest.Encoded()),
			expect: func(t *testing.T, referenced map[digest.Digest]struct{}, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(map[digest.Digest]struct{}{mockBlobDigest: {}}, referenced)
			},
		},
		{
			name:   "reject invalid blob digest",
			output: `{"blobs":[{"slot_sha256":"invalid"}]}`,
			expect: func(t *testing.T, referenced map[digest.Digest]struct{}, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `nydus check blob 1 has invalid sha256 "invalid"`)
				assert.Nil(referenced)
			},
		},
		{
			name:   "reject invalid json output",
			output: "not json",
			expect: func(t *testing.T, referenced map[digest.Digest]struct{}, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "parse nydus check json output")
				assert.Nil(referenced)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			builder := filepath.Join(t.TempDir(), "nydus")
			if err := os.WriteFile(builder, []byte("#!/bin/sh\nprintf '%s' '"+tc.output+"'\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			referenced, err := bootstrapBlobDigestsFromNydusCheck(context.Background(), builder, filepath.Join(t.TempDir(), "image.boot"))

			tc.expect(t, referenced, err)
		})
	}
}

func TestBlobMetaDigest(t *testing.T) {
	assert := assert.New(t)
	_, ok := blobMetaDigest("image.boot")
	assert.False(ok)
}

func TestCollectArtifactBlobPaths(t *testing.T) {
	tests := []struct {
		name   string
		input  func(dir string) ([]string, string)
		expect func(t *testing.T, dir string, paths []string, err error)
	}{
		{
			name: "skip empty and duplicate paths",
			input: func(dir string) ([]string, string) {
				path := filepath.Join(dir, mockBlobDigest.Encoded())
				return []string{"", path, path}, ""
			},
			expect: func(t *testing.T, dir string, paths []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{filepath.Join(dir, mockBlobDigest.Encoded())}, paths)
			},
		},
		{
			name: "reject missing path",
			input: func(dir string) ([]string, string) {
				return []string{filepath.Join(dir, "missing")}, ""
			},
			expect: func(t *testing.T, dir string, paths []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "stat blob")
			},
		},
		{
			name: "reject directory path",
			input: func(dir string) ([]string, string) {
				return []string{dir}, ""
			},
			expect: func(t *testing.T, dir string, paths []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "is a directory")
			},
		},
		{
			name: "reject missing blob directory",
			input: func(dir string) ([]string, string) {
				return nil, filepath.Join(dir, "missing")
			},
			expect: func(t *testing.T, dir string, paths []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read blob dir")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			mockFile(t, filepath.Join(dir, mockBlobDigest.Encoded()), mockBlobData)
			paths, err := collectArtifactBlobPaths(tc.input(dir))

			tc.expect(t, dir, paths, err)
		})
	}
}

func TestFilterArtifactBlobPaths(t *testing.T) {
	assert := assert.New(t)
	paths := []string{
		filepath.Join("somewhere", mockBlobDigest.Encoded()),
		filepath.Join("somewhere", mockOtherBlobDigest.Encoded()),
		filepath.Join("somewhere", "legacy-name"),
	}
	assert.Equal([]string{
		filepath.Join("somewhere", mockBlobDigest.Encoded()),
		filepath.Join("somewhere", "legacy-name"),
	}, filterArtifactBlobPaths(paths, map[digest.Digest]struct{}{mockBlobDigest: {}}))
}

func TestDescribeArtifactBlob(t *testing.T) {
	tests := []struct {
		name   string
		path   func(t *testing.T) string
		expect func(t *testing.T, desc ocispec.Descriptor, meta nydus.BlobMetaFile, err error)
	}{
		{
			name: "take digest from blob name without hashing data",
			path: func(t *testing.T) string {
				return mockBlobFile(t, mockBlobDigest.Encoded(), []byte("unhashed"))
			},
			expect: func(t *testing.T, desc ocispec.Descriptor, meta nydus.BlobMetaFile, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(ocispec.Descriptor{
					MediaType:   nydus.MediaTypeNydusBlob,
					Digest:      mockBlobDigest,
					Size:        int64(len("unhashed")),
					Annotations: mockBlobDesc.Annotations,
				}, desc)
				assert.Equal(mockBlobMetaFile, meta)
			},
		},
		{
			name: "hash data of legacy blob name",
			path: func(t *testing.T) string {
				return mockBlobFile(t, "legacy-name", mockBlobData)
			},
			expect: func(t *testing.T, desc ocispec.Descriptor, meta nydus.BlobMetaFile, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockBlobDesc, desc)
				assert.Equal(mockBlobMetaFile, meta)
			},
		},
		{
			name: "reject missing blob",
			path: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "missing")
			},
			expect: func(t *testing.T, desc ocispec.Descriptor, meta nydus.BlobMetaFile, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "open blob")
			},
		},
		{
			name: "reject blob without meta",
			path: func(t *testing.T) string {
				return mockFile(t, filepath.Join(t.TempDir(), mockBlobDigest.Encoded()), mockBlobData)
			},
			expect: func(t *testing.T, desc ocispec.Descriptor, meta nydus.BlobMetaFile, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read blob metadata")
			},
		},
		{
			name: "reject legacy blob without meta",
			path: func(t *testing.T) string {
				return mockFile(t, filepath.Join(t.TempDir(), "data"), []byte("invalid metadata"))
			},
			expect: func(t *testing.T, desc ocispec.Descriptor, meta nydus.BlobMetaFile, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read blob metadata")
			},
		},
		{
			name: "reject directory",
			path: func(t *testing.T) string {
				return t.TempDir()
			},
			expect: func(t *testing.T, desc ocispec.Descriptor, meta nydus.BlobMetaFile, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "hash non-digest-named blob")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			desc, meta, err := describeArtifactBlob(tc.path(t))
			tc.expect(t, desc, meta, err)
		})
	}
}
