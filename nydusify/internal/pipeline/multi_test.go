/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package pipeline

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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
	mockDataHistory = ocispec.History{CreatedBy: "Nydus Build", Comment: "Nydus Data Layer"}
)

func mockLabeledIndex(t *testing.T, cs content.Store, labels map[string]string, diffIDs []digest.Digest, platform ocispec.Platform) ocispec.Descriptor {
	t.Helper()
	ctx := context.Background()
	if labels != nil {
		if err := content.WriteBlob(ctx, cs, mockBlobDigest.String(), bytes.NewReader(mockBlobData), mockBlobDesc, content.WithLabels(labels)); err != nil {
			t.Fatal(err)
		}
	}

	config, err := oci.WriteJSON(ctx, cs, ocispec.Image{RootFS: ocispec.RootFS{Type: "layers", DiffIDs: diffIDs}},
		ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig}, nil)
	if err != nil {
		t.Fatal(err)
	}

	manifest, err := oci.WriteJSON(ctx, cs, ocispec.Manifest{Config: *config, Layers: []ocispec.Descriptor{mockBlobDesc}},
		ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Platform = &platform

	return mockIndex(t, cs, *manifest)
}

func TestConvertMultiSource(t *testing.T) {
	builder := os.Getenv("NYDUS_TEST_BUILDER")
	tests := []struct {
		name    string
		builder bool
		opt     func(t *testing.T, cs content.Store) MultiSourceOption
		expect  func(t *testing.T, cs content.Store, opt MultiSourceOption, desc *ocispec.Descriptor, err error)
	}{
		{
			name:    "inherit config from upper image source",
			builder: true,
			opt: func(t *testing.T, cs content.Store) MultiSourceOption {
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, "base"), []byte("directory source"), 0o644); err != nil {
					t.Fatal(err)
				}

				image := mockImage(t, cs, mockPlatform)
				return MultiSourceOption{Sources: []Source{{Dir: dir}, {Image: &image}}}
			},
			expect: func(t *testing.T, cs content.Store, opt MultiSourceOption, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				manifest, config := readManifest(t, cs, *desc)
				blobs, bootstrap, _, err := nydus.SplitLayers(manifest.Layers)
				assert.NoError(err)
				assert.NotNil(bootstrap)
				assert.Len(blobs, 1+len(mockLayerNames))
				assert.Equal(mockManifestAnnotations, manifest.Annotations)
				assert.Equal(mockImageConfig.Env, config.Config.Env)
				assert.Len(config.RootFS.DiffIDs, len(manifest.Layers))
				assert.Equal([]ocispec.History{mockDataHistory, mockDataHistory, mockDataHistory, mockBootstrapHistory}, config.History)
			},
		},
		{
			name:    "reuse blobs of nydus image source",
			builder: true,
			opt: func(t *testing.T, cs content.Store) MultiSourceOption {
				image, err := Convert(context.Background(), cs, mockImage(t, cs, mockPlatform), Option{BuilderPath: builder, WorkDir: t.TempDir()})
				if err != nil {
					t.Fatal(err)
				}

				return MultiSourceOption{Sources: []Source{{Image: image}}}
			},
			expect: func(t *testing.T, cs content.Store, opt MultiSourceOption, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				source, _ := readManifest(t, cs, *opt.Sources[0].Image)
				sourceBlobs, _, _, err := nydus.SplitLayers(source.Layers)
				assert.NoError(err)
				manifest, config := readManifest(t, cs, *desc)
				blobs, bootstrap, _, err := nydus.SplitLayers(manifest.Layers)
				assert.NoError(err)
				assert.NotNil(bootstrap)
				assert.Equal(sourceBlobs, blobs)
				assert.Equal(mockImageConfig.Env, config.Config.Env)
			},
		},
		{
			name: "reject missing image source",
			opt: func(t *testing.T, cs content.Store) MultiSourceOption {
				return MultiSourceOption{Sources: []Source{{Image: &ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex, Digest: digest.FromString("missing index")}}}}
			},
			expect: func(t *testing.T, cs content.Store, opt MultiSourceOption, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "convert image source 0: label nydus blob diff ids")
				assert.Nil(desc)
			},
		},
		{
			name: "reject image source without matching platform",
			opt: func(t *testing.T, cs content.Store) MultiSourceOption {
				image := mockImage(t, cs, mockARM64Platform)
				return MultiSourceOption{Sources: []Source{{Image: &image}}}
			},
			expect: func(t *testing.T, cs content.Store, opt MultiSourceOption, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "image index has no manifests")
				assert.Nil(desc)
			},
		},
		{
			name: "reject misplaced bootstrap layer",
			opt: func(t *testing.T, cs content.Store) MultiSourceOption {
				bootstrap, err := oci.WriteBootstrapLayer(context.Background(), cs, mockBootstrapData, nil, nil)
				if err != nil {
					t.Fatal(err)
				}

				image := mockManifest(t, cs, *bootstrap, mockBlob(t, cs, "upper blob"))
				return MultiSourceOption{Sources: []Source{{Image: &image}}}
			},
			expect: func(t *testing.T, cs content.Store, opt MultiSourceOption, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unsupported layer in image source")
				assert.Nil(desc)
			},
		},
		{
			name: "reject image source without layers",
			opt: func(t *testing.T, cs content.Store) MultiSourceOption {
				image := mockManifest(t, cs)
				return MultiSourceOption{Sources: []Source{{Image: &image}}}
			},
			expect: func(t *testing.T, cs content.Store, opt MultiSourceOption, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "sources produced no nydus blob layers")
				assert.Nil(desc)
			},
		},
		{
			name: "reject invalid nydus blob",
			opt: func(t *testing.T, cs content.Store) MultiSourceOption {
				image := mockManifest(t, cs, mockBlob(t, cs, "invalid blob"))
				return MultiSourceOption{Sources: []Source{{Image: &image}}}
			},
			expect: func(t *testing.T, cs content.Store, opt MultiSourceOption, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "stage blob")
				assert.Nil(desc)
			},
		},
		{
			name: "reject empty sources",
			opt: func(t *testing.T, cs content.Store) MultiSourceOption {
				return MultiSourceOption{}
			},
			expect: func(t *testing.T, cs content.Store, opt MultiSourceOption, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "no sources given")
				assert.Nil(desc)
			},
		},
		{
			name: "reject source without dir or image",
			opt: func(t *testing.T, cs content.Store) MultiSourceOption {
				return MultiSourceOption{Sources: []Source{{}}}
			},
			expect: func(t *testing.T, cs content.Store, opt MultiSourceOption, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "source 0: exactly one of Dir or Image must be set")
				assert.Nil(desc)
			},
		},
		{
			name: "reject source with dir and image",
			opt: func(t *testing.T, cs content.Store) MultiSourceOption {
				return MultiSourceOption{Sources: []Source{{Dir: t.TempDir(), Image: &ocispec.Descriptor{}}}}
			},
			expect: func(t *testing.T, cs content.Store, opt MultiSourceOption, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "source 0: exactly one of Dir or Image must be set")
				assert.Nil(desc)
			},
		},
		{
			name: "reject regular file work directory",
			opt: func(t *testing.T, cs content.Store) MultiSourceOption {
				return MultiSourceOption{
					Sources: []Source{{Dir: t.TempDir()}},
					WorkDir: mockFile(t, filepath.Join(t.TempDir(), "data"), nil),
				}
			},
			expect: func(t *testing.T, cs content.Store, opt MultiSourceOption, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create merge scratch dir")
				assert.Nil(desc)
			},
		},
		{
			name: "reject missing append file",
			opt: func(t *testing.T, cs content.Store) MultiSourceOption {
				return MultiSourceOption{
					Sources:           []Source{{Dir: t.TempDir()}},
					AppendInBootstrap: []string{filepath.Join(t.TempDir(), "missing")},
				}
			},
			expect: func(t *testing.T, cs content.Store, opt MultiSourceOption, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
				assert.Nil(desc)
			},
		},
		{
			name: "reject missing builder",
			opt: func(t *testing.T, cs content.Store) MultiSourceOption {
				return MultiSourceOption{Sources: []Source{{Dir: t.TempDir()}}, BuilderPath: "/nonexistent/nydus"}
			},
			expect: func(t *testing.T, cs content.Store, opt MultiSourceOption, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "convert directory source")
				assert.Nil(desc)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.builder && builder == "" {
				t.Skip("set NYDUS_TEST_BUILDER to run real builder conversion tests")
			}
			cs := mockStore(t)
			opt := tc.opt(t, cs)
			opt.BuilderPath = cmp.Or(opt.BuilderPath, builder)
			opt.WorkDir = cmp.Or(opt.WorkDir, t.TempDir())
			opt.Platform = mockPlatform
			opt.Annotations = mockManifestAnnotations
			desc, err := ConvertMultiSource(context.Background(), cs, opt)

			tc.expect(t, cs, opt, desc, err)
		})
	}
}

func TestValidateAndReadAppendFiles(t *testing.T) {
	tests := []struct {
		name   string
		paths  func(t *testing.T, dir string) []string
		expect func(t *testing.T, files []nydus.AppendFile, err error)
	}{
		{
			name: "reject missing file",
			paths: func(t *testing.T, dir string) []string {
				return []string{filepath.Join(dir, "missing")}
			},
			expect: func(t *testing.T, files []nydus.AppendFile, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
				assert.Nil(files)
			},
		},
		{
			name: "reject directory",
			paths: func(t *testing.T, dir string) []string {
				return []string{dir}
			},
			expect: func(t *testing.T, files []nydus.AppendFile, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "is a directory, not a file")
				assert.Nil(files)
			},
		},
		{
			name: "reject duplicate basename",
			paths: func(t *testing.T, dir string) []string {
				path := mockFile(t, filepath.Join(dir, "data"), mockAppendFileData)
				return []string{path, path}
			},
			expect: func(t *testing.T, files []nydus.AppendFile, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `append-in-bootstrap duplicate basename "data"`)
				assert.Nil(files)
			},
		},
		{
			name: "reject reserved bootstrap name",
			paths: func(t *testing.T, dir string) []string {
				return []string{mockFile(t, filepath.Join(dir, "image.boot"), nil)}
			},
			expect: func(t *testing.T, files []nydus.AppendFile, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "reserved")
				assert.Nil(files)
			},
		},
		{
			name: "reject reserved blob meta name",
			paths: func(t *testing.T, dir string) []string {
				return []string{mockFile(t, filepath.Join(dir, "digest.blob.meta"), nil)}
			},
			expect: func(t *testing.T, files []nydus.AppendFile, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "reserved")
				assert.Nil(files)
			},
		},
		{
			name: "reject oversized file",
			paths: func(t *testing.T, dir string) []string {
				path := mockFile(t, filepath.Join(dir, "large"), nil)
				if err := os.Truncate(path, maxAppendFileSize+1); err != nil {
					t.Fatal(err)
				}

				return []string{path}
			},
			expect: func(t *testing.T, files []nydus.AppendFile, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "too large")
				assert.Nil(files)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			files, err := validateAndReadAppendFiles(tc.paths(t, t.TempDir()))

			tc.expect(t, files, err)
		})
	}
}

func TestWriteNydusManifest(t *testing.T) {
	tests := []struct {
		name      string
		blobs     []ocispec.Descriptor
		bootstrap func(t *testing.T, cs content.Store) ocispec.Descriptor
		base      json.RawMessage
		failAt    int
		expect    func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error)
	}{
		{
			name:      "write blob and bootstrap layers",
			blobs:     []ocispec.Descriptor{mockBlobDesc},
			bootstrap: mockBootstrap,
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				manifest, _ := readManifest(t, cs, *desc)
				assert.Equal([]ocispec.Descriptor{mockBlobDesc, mockBootstrap(t, cs)}, manifest.Layers)
			},
		},
		{
			name:      "fail to open config writer",
			blobs:     []ocispec.Descriptor{mockBlobDesc},
			bootstrap: mockBootstrap,
			failAt:    1,
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
				assert.Nil(desc)
			},
		},
		{
			name:      "fail to stat written config",
			blobs:     []ocispec.Descriptor{mockBlobDesc},
			bootstrap: mockBootstrap,
			failAt:    2,
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
				assert.Nil(desc)
			},
		},
		{
			name:      "fail to open manifest writer",
			blobs:     []ocispec.Descriptor{mockBlobDesc},
			bootstrap: mockBootstrap,
			failAt:    3,
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
				assert.Nil(desc)
			},
		},
		{
			name:      "fail to stat written manifest",
			blobs:     []ocispec.Descriptor{mockBlobDesc},
			bootstrap: mockBootstrap,
			failAt:    4,
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
				assert.Nil(desc)
			},
		},
		{
			name:      "reject blob without diff id",
			blobs:     []ocispec.Descriptor{{}},
			bootstrap: mockBootstrap,
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "missing "+nydus.LayerAnnotationUncompressed+" annotation")
				assert.Nil(desc)
			},
		},
		{
			name: "reject bootstrap without diff id",
			bootstrap: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return ocispec.Descriptor{}
			},
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "missing "+nydus.LayerAnnotationUncompressed+" annotation")
				assert.Nil(desc)
			},
		},
		{
			name:      "reject invalid base config",
			bootstrap: mockBootstrap,
			base:      json.RawMessage(`{`),
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "build image config")
				assert.Nil(desc)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := mockStore(t)
			bootstrap := tc.bootstrap(t, cs)
			desc, err := writeNydusManifest(context.Background(), &mockContentStore{Store: cs, failAt: tc.failAt}, tc.blobs, bootstrap, tc.base, mockPlatform, "Nydus Build", nil)

			tc.expect(t, cs, desc, err)
		})
	}
}

func TestLabelNydusBlobDiffIDs(t *testing.T) {
	tests := []struct {
		name   string
		root   func(t *testing.T, cs content.Store) ocispec.Descriptor
		failAt int
		expect func(t *testing.T, cs content.Store, err error)
	}{
		{
			name: "skip missing blob",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockLabeledIndex(t, cs, nil, []digest.Digest{mockBlobDigest}, mockPlatform)
			},
			expect: func(t *testing.T, cs content.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "label unlabeled blob",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockLabeledIndex(t, cs, map[string]string{"keep": "value"}, []digest.Digest{mockBlobDigest}, mockPlatform)
			},
			expect: func(t *testing.T, cs content.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				info, err := cs.Info(context.Background(), mockBlobDigest)
				assert.NoError(err)
				assert.Equal("value", info.Labels["keep"])
				assert.Equal(mockBlobDigest.String(), info.Labels[nydus.LayerAnnotationUncompressed])
			},
		},
		{
			name: "keep labeled blob",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockLabeledIndex(t, cs, map[string]string{"keep": "value", nydus.LayerAnnotationUncompressed: mockBlobDigest.String()}, []digest.Digest{mockBlobDigest}, mockPlatform)
			},
			expect: func(t *testing.T, cs content.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				info, err := cs.Info(context.Background(), mockBlobDigest)
				assert.NoError(err)
				assert.Equal("value", info.Labels["keep"])
				assert.Equal(mockBlobDigest.String(), info.Labels[nydus.LayerAnnotationUncompressed])
			},
		},
		{
			name: "label blob regardless of config diff ids",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockLabeledIndex(t, cs, map[string]string{"keep": "value"}, nil, mockPlatform)
			},
			expect: func(t *testing.T, cs content.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				info, err := cs.Info(context.Background(), mockBlobDigest)
				assert.NoError(err)
				assert.Equal("value", info.Labels["keep"])
				assert.Equal(mockBlobDigest.String(), info.Labels[nydus.LayerAnnotationUncompressed])
			},
		},
		{
			name: "skip excluded platform",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockLabeledIndex(t, cs, map[string]string{"keep": "value"}, []digest.Digest{mockBlobDigest}, mockARM64Platform)
			},
			expect: func(t *testing.T, cs content.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				info, err := cs.Info(context.Background(), mockBlobDigest)
				assert.NoError(err)
				assert.Equal("value", info.Labels["keep"])
				assert.Empty(info.Labels[nydus.LayerAnnotationUncompressed])
			},
		},
		{
			name: "skip layer descriptor",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockBlobDesc
			},
			expect: func(t *testing.T, cs content.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "fail to read index",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs, mockNydusManifest(t, cs))
			},
			failAt: 1,
			expect: func(t *testing.T, cs content.Store, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
			},
		},
		{
			name: "fail to read manifest",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs, mockNydusManifest(t, cs))
			},
			failAt: 2,
			expect: func(t *testing.T, cs content.Store, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
			},
		},
		{
			name: "fail to stat blob",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs, mockNydusManifest(t, cs))
			},
			failAt: 3,
			expect: func(t *testing.T, cs content.Store, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
			},
		},
		{
			name: "fail to label blob",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs, mockNydusManifest(t, cs))
			},
			failAt: 4,
			expect: func(t *testing.T, cs content.Store, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := mockStore(t)
			root := tc.root(t, cs)
			err := labelNydusBlobDiffIDs(context.Background(), &mockContentStore{Store: cs, failAt: tc.failAt}, root, platforms.Only(mockPlatform))

			tc.expect(t, cs, err)
		})
	}
}

func TestLabelSourceLayerDiffIDs(t *testing.T) {
	tests := []struct {
		name   string
		root   func(t *testing.T, cs content.Store) ocispec.Descriptor
		failAt int
		expect func(t *testing.T, cs content.Store, err error)
	}{
		{
			name: "skip missing layer",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockLabeledIndex(t, cs, nil, []digest.Digest{mockBlobDigest}, mockPlatform)
			},
			expect: func(t *testing.T, cs content.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "label unlabeled layer",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockLabeledIndex(t, cs, map[string]string{"keep": "value"}, []digest.Digest{mockBlobDigest}, mockPlatform)
			},
			expect: func(t *testing.T, cs content.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				info, err := cs.Info(context.Background(), mockBlobDigest)
				assert.NoError(err)
				assert.Equal("value", info.Labels["keep"])
				assert.Equal(mockBlobDigest.String(), info.Labels[nydus.LayerAnnotationUncompressed])
			},
		},
		{
			name: "keep labeled layer",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockLabeledIndex(t, cs, map[string]string{"keep": "value", nydus.LayerAnnotationUncompressed: mockBlobDigest.String()}, []digest.Digest{mockBlobDigest}, mockPlatform)
			},
			expect: func(t *testing.T, cs content.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				info, err := cs.Info(context.Background(), mockBlobDigest)
				assert.NoError(err)
				assert.Equal("value", info.Labels["keep"])
				assert.Equal(mockBlobDigest.String(), info.Labels[nydus.LayerAnnotationUncompressed])
			},
		},
		{
			name: "skip layers of mismatched config",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockLabeledIndex(t, cs, map[string]string{"keep": "value"}, nil, mockPlatform)
			},
			expect: func(t *testing.T, cs content.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				info, err := cs.Info(context.Background(), mockBlobDigest)
				assert.NoError(err)
				assert.Empty(info.Labels[nydus.LayerAnnotationUncompressed])
			},
		},
		{
			name: "skip excluded platform",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockLabeledIndex(t, cs, map[string]string{"keep": "value"}, []digest.Digest{mockBlobDigest}, mockARM64Platform)
			},
			expect: func(t *testing.T, cs content.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				info, err := cs.Info(context.Background(), mockBlobDigest)
				assert.NoError(err)
				assert.Equal("value", info.Labels["keep"])
				assert.Empty(info.Labels[nydus.LayerAnnotationUncompressed])
			},
		},
		{
			name: "skip layer descriptor",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockBlobDesc
			},
			expect: func(t *testing.T, cs content.Store, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "fail to read index",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs, mockNydusManifest(t, cs))
			},
			failAt: 1,
			expect: func(t *testing.T, cs content.Store, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
			},
		},
		{
			name: "fail to read manifest",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs, mockNydusManifest(t, cs))
			},
			failAt: 2,
			expect: func(t *testing.T, cs content.Store, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
			},
		},
		{
			name: "fail to read config",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs, mockNydusManifest(t, cs))
			},
			failAt: 3,
			expect: func(t *testing.T, cs content.Store, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
			},
		},
		{
			name: "fail to stat blob layer",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs, mockNydusManifest(t, cs))
			},
			failAt: 4,
			expect: func(t *testing.T, cs content.Store, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
			},
		},
		{
			name: "fail to label blob layer",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs, mockNydusManifest(t, cs))
			},
			failAt: 5,
			expect: func(t *testing.T, cs content.Store, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
			},
		},
		{
			name: "fail to stat bootstrap layer",
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return mockIndex(t, cs, mockNydusManifest(t, cs))
			},
			failAt: 6,
			expect: func(t *testing.T, cs content.Store, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errMockStore)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := mockStore(t)
			root := tc.root(t, cs)
			err := labelSourceLayerDiffIDs(context.Background(), &mockContentStore{Store: cs, failAt: tc.failAt}, root, platforms.Only(mockPlatform))

			tc.expect(t, cs, err)
		})
	}
}
