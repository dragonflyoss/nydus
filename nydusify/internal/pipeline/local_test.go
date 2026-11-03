/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package pipeline

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/platforms"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

var (
	mockSourceFileData = []byte("directory data")

	mockAppendFileData = []byte(`{"append":true}`)
)

func TestConvertLocalDir(t *testing.T) {
	builder := os.Getenv("NYDUS_TEST_BUILDER")
	tests := []struct {
		name       string
		builder    bool
		appendFile string
		expect     func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error)
	}{
		{
			name:       "moves append file from blob into bootstrap",
			builder:    true,
			appendFile: "append.json",
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					t.FailNow()
				}

				manifest, config := readMockManifest(t, cs, *desc)
				blobs, bootstrap, _, err := nydus.SplitLayers(manifest.Layers)
				if !assert.NoError(err) || !assert.NotNil(bootstrap) || !assert.Len(blobs, 1) {
					t.FailNow()
				}
				assert.Equal(mockManifestAnnotations, manifest.Annotations)
				assert.Equal(platforms.DefaultSpec().OS, config.OS)
				assert.Equal(platforms.DefaultSpec().Architecture, config.Architecture)

				entries := map[string][]byte{}
				assert.NoError(oci.WalkBootstrapLayer(context.Background(), cs, *bootstrap, func(hdr *tar.Header, tr *tar.Reader) error {
					data, err := io.ReadAll(tr)
					entries[hdr.Name] = data
					return err
				}))
				assert.Equal(mockAppendFileData, entries["image/append.json"])

				path, err := materializeBlob(context.Background(), cs, blobs[0], t.TempDir())
				if !assert.NoError(err) {
					t.FailNow()
				}

				var exported bytes.Buffer
				if !assert.NoError(nydus.RunNydusExport(context.Background(), nydus.ExportOption{BuilderPath: builder, BlobPath: path}, &exported)) {
					t.FailNow()
				}

				files := map[string][]byte{}
				tr := tar.NewReader(&exported)
				for {
					hdr, err := tr.Next()
					if err == io.EOF {
						break
					}
					if !assert.NoError(err) {
						t.FailNow()
					}

					data, err := io.ReadAll(tr)
					assert.NoError(err)
					files[filepath.Clean(hdr.Name)] = data
				}
				assert.Equal(mockSourceFileData, files["data"])
				assert.NotContains(files, "append.json")
			},
		},
		{
			name:       "rejects reserved append file name",
			appendFile: "image.boot",
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `append-in-bootstrap file basename "image.boot" conflicts with reserved bootstrap entry`)
				assert.Nil(desc)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.builder && builder == "" {
				t.Skip("set NYDUS_TEST_BUILDER to run real builder conversion tests")
			}
			source := t.TempDir()
			if !assert.NoError(t, os.WriteFile(filepath.Join(source, "data"), mockSourceFileData, 0o644)) {
				t.FailNow()
			}
			if !assert.NoError(t, os.WriteFile(filepath.Join(source, tc.appendFile), mockAppendFileData, 0o644)) {
				t.FailNow()
			}

			cs := newMockStore(t)
			desc, err := ConvertLocalDir(context.Background(), cs, LocalDirOption{
				BuilderPath:       builder,
				WorkDir:           t.TempDir(),
				SourceDir:         source,
				AppendInBootstrap: []string{filepath.Join(source, tc.appendFile)},
				Annotations:       mockManifestAnnotations,
			})
			tc.expect(t, cs, desc, err)
		})
	}
}
