/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydusify/internal/registrytest"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

type registry struct {
	*registrytest.Registry
}

func newRegistry(t *testing.T) *registry {
	return &registry{registrytest.New(t)}
}

func (r *registry) storeOCIImage(t *testing.T, repo, tag string) {
	index := ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex}
	for _, arch := range []string{"amd64", "arm64"} {
		var layer bytes.Buffer
		tw := tar.NewWriter(&layer)
		header := &tar.Header{Name: "hello", Mode: 0o644, Uid: os.Getuid(), Gid: os.Getgid(), Size: int64(len(arch)), ModTime: time.Unix(1700000000, 0)}
		if !assert.NoError(t, tw.WriteHeader(header)) {
			t.FailNow()
		}
		_, err := tw.Write([]byte(arch))
		if !assert.NoError(t, err) || !assert.NoError(t, tw.Close()) {
			t.FailNow()
		}
		var compressed bytes.Buffer
		gw := gzip.NewWriter(&compressed)
		_, err = gw.Write(layer.Bytes())
		if !assert.NoError(t, err) || !assert.NoError(t, gw.Close()) {
			t.FailNow()
		}
		layerDesc := r.Store(repo, "", "", compressed.Bytes())
		layerDesc.MediaType = ocispec.MediaTypeImageLayerGzip
		config := ocispec.Image{
			Platform: ocispec.Platform{OS: "linux", Architecture: arch},
			RootFS:   ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{digest.FromBytes(layer.Bytes())}},
		}
		configDesc := r.StoreJSON(t, repo, "", "", config)
		configDesc.MediaType = ocispec.MediaTypeImageConfig
		manifest := ocispec.Manifest{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: ocispec.MediaTypeImageManifest,
			Config:    configDesc,
			Layers:    []ocispec.Descriptor{layerDesc},
		}
		manifestDesc := r.StoreJSON(t, repo, "", ocispec.MediaTypeImageManifest, manifest)
		manifestDesc.Platform = &config.Platform
		index.Manifests = append(index.Manifests, manifestDesc)
	}
	r.StoreJSON(t, repo, tag, ocispec.MediaTypeImageIndex, index)
}

func (r *registry) nydusManifest(t *testing.T, repo, reference string) ([]ocispec.Descriptor, ocispec.Descriptor) {
	var manifest ocispec.Manifest
	r.LoadJSON(t, repo, reference, &manifest)
	blobs, bootstrap, _, err := nydus.SplitLayers(manifest.Layers)
	if !assert.NoError(t, err) || !assert.NotNil(t, bootstrap) {
		t.FailNow()
	}
	return blobs, *bootstrap
}

func (r *registry) extractNydusImage(t *testing.T, repo, reference string) string {
	dir := t.TempDir()
	blobs, bootstrap := r.nydusManifest(t, repo, reference)
	for _, desc := range blobs {
		data, ok := r.Load(repo, desc.Digest.String())
		if !assert.True(t, ok) || !assert.NoError(t, os.WriteFile(filepath.Join(dir, desc.Digest.Encoded()), data, 0o600)) {
			t.FailNow()
		}
	}
	data, _ := r.Load(repo, bootstrap.Digest.String())
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	tr := tar.NewReader(gr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		file, err := os.Create(filepath.Join(dir, filepath.Base(header.Name)))
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		_, err = io.Copy(file, tr)
		if !assert.NoError(t, err) || !assert.NoError(t, file.Close()) {
			t.FailNow()
		}
	}
	return filepath.Join(dir, "image.boot")
}

func (r *registry) storeNydusImage(t *testing.T, repo, tag string) {
	args := []string{"convert", "--builder", requireBuilder(t), "--target-plain-http", "--target", r.Ref(repo, tag)}
	for _, name := range []string{"lower", "upper"} {
		dir := filepath.Join(t.TempDir(), name)
		if !assert.NoError(t, os.Mkdir(dir, 0o755)) || !assert.NoError(t, os.WriteFile(filepath.Join(dir, name), bytes.Repeat([]byte(name), 1<<15), 0o644)) {
			t.FailNow()
		}
		args = append(args, "--source", dir)
	}
	if !assert.NoError(t, runNydusify(args...)) {
		t.FailNow()
	}
}
