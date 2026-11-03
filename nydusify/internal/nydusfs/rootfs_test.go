/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydusfs

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/plugins/content/local"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

func newMockTarLayer(t *testing.T, entries ...string) []byte {
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	for _, entry := range entries {
		name, data, _ := strings.Cut(entry, "=")
		header := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg, Uid: os.Getuid(), Gid: os.Getgid()}
		if strings.HasSuffix(name, "/") {
			header.Mode, header.Typeflag = 0o755, tar.TypeDir
		}
		if !assert.NoError(t, tw.WriteHeader(header)) {
			t.FailNow()
		}
		if _, err := tw.Write([]byte(data)); !assert.NoError(t, err) {
			t.FailNow()
		}
	}
	if !assert.NoError(t, tw.Close()) {
		t.FailNow()
	}
	return archive.Bytes()
}

func TestApplyOCIImage(t *testing.T) {
	tests := []struct {
		name   string
		layers func(t *testing.T, cs content.Store) []ocispec.Descriptor
		rootfs func(t *testing.T) string
		expect func(t *testing.T, rootfs string, err error)
	}{
		{
			name: "layers are merged with whiteouts",
			layers: func(t *testing.T, cs content.Store) []ocispec.Descriptor {
				return []ocispec.Descriptor{
					storeMockBlob(t, cs, ocispec.MediaTypeImageLayer, newMockTarLayer(t, "dir/", "dir/removed=old", "kept=lower", "replaced=lower")),
					storeMockBlob(t, cs, ocispec.MediaTypeImageLayer, newMockTarLayer(t, "dir/.wh.removed", "replaced=upper", "added=upper")),
				}
			},
			rootfs: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "rootfs")
			},
			expect: func(t *testing.T, rootfs string, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					t.FailNow()
				}
				for name, data := range map[string]string{"kept": "lower", "replaced": "upper", "added": "upper"} {
					got, err := os.ReadFile(filepath.Join(rootfs, name))
					assert.NoError(err)
					assert.Equal(data, string(got))
				}
				assert.DirExists(filepath.Join(rootfs, "dir"))
				assert.NoFileExists(filepath.Join(rootfs, "dir", "removed"))
				assert.NoFileExists(filepath.Join(rootfs, "dir", ".wh.removed"))
			},
		},
		{
			name: "rootfs path is a file",
			layers: func(t *testing.T, cs content.Store) []ocispec.Descriptor {
				return nil
			},
			rootfs: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "rootfs")
				assert.NoError(t, os.WriteFile(path, nil, 0o600))
				return path
			},
			expect: func(t *testing.T, rootfs string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create rootfs dir")
			},
		},
		{
			name: "missing layer blob",
			layers: func(t *testing.T, cs content.Store) []ocispec.Descriptor {
				return []ocispec.Descriptor{mockOCILayer}
			},
			rootfs: func(t *testing.T) string {
				return t.TempDir()
			},
			expect: func(t *testing.T, rootfs string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "apply layer "+mockOCILayer.Digest.String())
				assert.ErrorContains(err, "open layer")
			},
		},
		{
			name: "corrupt layer archive",
			layers: func(t *testing.T, cs content.Store) []ocispec.Descriptor {
				return []ocispec.Descriptor{
					storeMockBlob(t, cs, ocispec.MediaTypeImageLayer, newMockTarLayer(t, "applied=first")),
					storeMockBlob(t, cs, ocispec.MediaTypeImageLayer, []byte("not a tar archive")),
				}
			},
			rootfs: func(t *testing.T) string {
				return t.TempDir()
			},
			expect: func(t *testing.T, rootfs string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "apply layer "+digest.FromString("not a tar archive").String())
				assert.ErrorContains(err, "apply layer archive")
				assert.FileExists(filepath.Join(rootfs, "applied"))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs, err := local.NewStore(t.TempDir())
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			img := &Image{Manifest: ocispec.Manifest{Layers: tc.layers(t, cs)}}
			rootfs := tc.rootfs(t)
			tc.expect(t, rootfs, ApplyOCIImage(context.Background(), cs, img, rootfs))
		})
	}
}
