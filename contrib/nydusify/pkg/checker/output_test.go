// Copyright 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package checker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	modelspec "github.com/CloudNativeAI/model-spec/specs-go/v1"
	"github.com/agiledragon/gomonkey/v2"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/remote"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
)

func buildBootstrapLayer(t *testing.T) ([]byte, digest.Digest) {
	t.Helper()

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "image", Mode: 0o755, Typeflag: tar.TypeDir}))
	content := []byte("bootstrap-content")
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: utils.BootstrapFileNameInLayer, Mode: 0o644, Size: int64(len(content))}))
	_, err := tw.Write(content)
	require.NoError(t, err)
	require.NoError(t, tw.Close())

	var gzipBuf bytes.Buffer
	gw := gzip.NewWriter(&gzipBuf)
	_, err = gw.Write(tarBuf.Bytes())
	require.NoError(t, err)
	require.NoError(t, gw.Close())

	return gzipBuf.Bytes(), digest.SHA256.FromBytes(tarBuf.Bytes())
}

func TestPrettyDump(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.json")
	require.NoError(t, prettyDump(map[string]string{"hello": "world"}, path))
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(content), "hello")

	err = prettyDump(map[string]interface{}{"bad": make(chan int)}, path)
	require.Error(t, err)
}

func TestOutputWritesOCIArtifacts(t *testing.T) {
	checker := &Checker{}
	dir := filepath.Join(t.TempDir(), "dump")
	parsed := &parser.Parsed{
		Remote: &remote.Remote{Ref: "example.com/oci:latest"},
		Index:  &ocispec.Index{Manifests: []ocispec.Descriptor{{Digest: digest.FromString("oci")}}},
		OCIImage: &parser.Image{
			Manifest: ocispec.Manifest{Config: ocispec.Descriptor{Digest: digest.FromString("config")}},
			Config:   ocispec.Image{RootFS: ocispec.RootFS{DiffIDs: []digest.Digest{digest.FromString("layer")}}},
		},
	}

	err := checker.Output(context.Background(), parsed, dir)
	require.NoError(t, err)
	for _, file := range []string{"oci_index.json", "oci_manifest.json", "oci_config.json"} {
		_, err = os.Stat(filepath.Join(dir, file))
		require.NoError(t, err)
	}
}

func TestOutputNydusValidation(t *testing.T) {
	layerBytes, expectedDiffID := buildBootstrapLayer(t)
	checker := &Checker{sourceParser: &parser.Parser{}}
	baseParsed := &parser.Parsed{
		Remote: &remote.Remote{Ref: "example.com/nydus:latest"},
		NydusImage: &parser.Image{
			Manifest: ocispec.Manifest{
				Layers: []ocispec.Descriptor{{
					MediaType: ocispec.MediaTypeImageLayerGzip,
					Digest:    digest.FromString("bootstrap"),
					Annotations: map[string]string{
						utils.LayerAnnotationNydusBootstrap: "true",
					},
				}},
			},
			Config: ocispec.Image{RootFS: ocispec.RootFS{DiffIDs: []digest.Digest{digest.FromString("wrong")}}},
		},
	}

	patches := gomonkey.ApplyMethod(reflect.TypeOf(&parser.Parser{}), "PullNydusBootstrap", func(*parser.Parser, context.Context, *parser.Image) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(layerBytes)), nil
	})
	defer patches.Reset()

	err := checker.Output(context.Background(), baseParsed, "source")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid bootstrap layer diff id")

	baseParsed.NydusImage.Config.RootFS.DiffIDs = []digest.Digest{expectedDiffID}
	baseParsed.NydusImage.Manifest.ArtifactType = modelspec.ArtifactTypeModelManifest
	baseParsed.NydusImage.Manifest.Subject = nil
	err = checker.Output(context.Background(), baseParsed, "source")
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing subject in manifest")

	baseParsed.NydusImage.Manifest.Subject = &ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex}
	err = checker.Output(context.Background(), baseParsed, "source")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid subject media type")

	baseParsed.NydusImage.Manifest.Subject = &ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}
	err = checker.Output(context.Background(), baseParsed, "source")
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join("source", "nydus_bootstrap", utils.BootstrapFileNameInLayer))
	require.NoError(t, err)
	require.NoError(t, os.RemoveAll("source"))
}
