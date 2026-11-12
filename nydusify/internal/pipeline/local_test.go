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
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
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
			name:       "move append file from blob into bootstrap",
			builder:    true,
			appendFile: "append.json",
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				manifest, config := readManifest(t, cs, *desc)
				blobs, _, _, err := nydus.SplitLayers(manifest.Layers)
				assert.NoError(err)
				assert.Len(blobs, 1)
				assert.Equal(mockManifestAnnotations, manifest.Annotations)
				assert.Equal("linux", config.OS)
				assert.Equal("s390x", config.Architecture)
				assert.Equal(mockAppendFileData, readBootstrap(t, cs, manifest)["image/append.json"])

				for _, blob := range blobs {
					path, err := materializeBlob(context.Background(), cs, blob, t.TempDir())
					assert.NoError(err)

					var exported bytes.Buffer
					assert.NoError(nydus.RunNydusExport(context.Background(), nydus.ExportOption{BuilderPath: builder, BlobPath: path}, &exported))

					files := map[string][]byte{}
					tr := tar.NewReader(&exported)
					for {
						hdr, err := tr.Next()
						if err != nil {
							assert.ErrorIs(err, io.EOF)
							break
						}

						data, err := io.ReadAll(tr)
						assert.NoError(err)
						files[filepath.Clean(hdr.Name)] = data
					}
					assert.Equal(mockSourceFileData, files["data"])
					assert.NotContains(files, "append.json")
				}
			},
		},
		{
			name:       "reject reserved append file name",
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
			if err := os.WriteFile(filepath.Join(source, "data"), mockSourceFileData, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(source, tc.appendFile), mockAppendFileData, 0o644); err != nil {
				t.Fatal(err)
			}

			cs := mockStore(t)
			desc, err := ConvertLocalDir(context.Background(), cs, LocalDirOption{
				BuilderPath:       builder,
				WorkDir:           t.TempDir(),
				SourceDir:         source,
				AppendInBootstrap: []string{filepath.Join(source, tc.appendFile)},
				Annotations:       mockManifestAnnotations,
				Platform:          ocispec.Platform{OS: "linux", Architecture: "s390x"},
			})

			tc.expect(t, cs, desc, err)
		})
	}
}
