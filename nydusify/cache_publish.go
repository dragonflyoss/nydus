// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dragonflyoss/nydus/nydusify/internal/pipeline"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type cacheImageBlob struct {
	Digest digest.Digest `json:"digest"`
	Size   int64         `json:"size"`
}

type cacheImageResult struct {
	Version uint32              `json:"version"`
	Blob    *cacheImageBlob     `json:"blob,omitempty"`
	Image   *ocispec.Descriptor `json:"image"`
}

func writeCacheFile(path string, write func(*os.File) error) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".cache-output-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	defer func() { _ = file.Close() }()
	if err := write(file); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

func completeCachePublication(cacheDir, bootstrap, output, contentDir string, image ocispec.Descriptor, blobs []pipeline.UploadedBlob) error {
	local := filepath.Join(cacheDir, "image.boot")
	if filepath.Clean(bootstrap) != filepath.Clean(local) {
		if err := saveBootstrap(local, bootstrap); err != nil {
			return fmt.Errorf("save checkpoint bootstrap: %w", err)
		}
	}
	if output != "" && filepath.Clean(output) != filepath.Clean(local) {
		if err := saveBootstrap(output, local); err != nil {
			return fmt.Errorf("save published bootstrap: %w", err)
		}
	}
	// Expose the existing metadata blobs as an OCI layout, without copying
	// streamed data blobs into the local content store.
	if err := writeCacheFile(filepath.Join(contentDir, "oci-layout"), func(f *os.File) error {
		return json.NewEncoder(f).Encode(ocispec.ImageLayout{Version: ocispec.ImageLayoutVersion})
	}); err != nil {
		return err
	}
	if err := writeCacheFile(filepath.Join(contentDir, "index.json"), func(f *os.File) error {
		return json.NewEncoder(f).Encode(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex, Manifests: []ocispec.Descriptor{image}})
	}); err != nil {
		return err
	}
	result := cacheImageResult{Version: 1, Image: &image}
	if len(blobs) == 1 {
		result.Blob = &cacheImageBlob{Digest: blobs[0].Digest, Size: blobs[0].Size}
	}
	return writeCacheFile(filepath.Join(cacheDir, "image.json"), func(file *os.File) error {
		return json.NewEncoder(file).Encode(result)
	})
}
