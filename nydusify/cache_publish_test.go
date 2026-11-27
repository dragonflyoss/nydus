// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/nydusify/internal/pipeline"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestWriteCacheFilePreservesOutputOnWriteFailure(t *testing.T) {
	dir := t.TempDir()
	path := mockFile(t, filepath.Join(dir, "image.json"), "original")
	failure := errors.New("write failed")
	err := writeCacheFile(path, func(file *os.File) error { _, _ = file.WriteString("partial"); return failure })
	data, readErr := os.ReadFile(path)
	if !errors.Is(err, failure) || readErr != nil || string(data) != "original" {
		t.Fatal("output changed", err, readErr)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatal("temporary output leaked")
	}
}

func TestCompleteCachePublication(t *testing.T) {
	for _, mode := range []string{"unchanged", "pruned", "explicit output", "checkpoint failure", "layout failure"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			local := mockFile(t, filepath.Join(dir, "image.boot"), "original")
			contentDir := filepath.Join(dir, "content")
			if err := os.Mkdir(contentDir, 0700); err != nil {
				t.Fatal(err)
			}
			bootstrap, output, expected := local, "", "original"
			if mode == "pruned" {
				bootstrap = mockFile(t, filepath.Join(dir, "repacked.boot"), "pruned")
				expected = "pruned"
			}
			if mode == "explicit output" {
				output = filepath.Join(dir, "export.boot")
			}
			if mode == "checkpoint failure" {
				output = filepath.Join(dir, "absent", "export.boot")
			}
			if mode == "layout failure" {
				contentDir = filepath.Join(dir, "absent")
			}
			image := ocispec.Descriptor{Digest: digest.FromString("published"), Size: 8, MediaType: ocispec.MediaTypeImageManifest}
			blob := pipeline.UploadedBlob{Digest: digest.FromString("encoded"), Size: 7}
			err := completeCachePublication(dir, bootstrap, output, contentDir, image, []pipeline.UploadedBlob{blob})
			marker := filepath.Join(dir, "image.json")
			if strings.Contains(mode, "failure") {
				if _, statErr := os.Lstat(marker); err == nil || !os.IsNotExist(statErr) {
					t.Fatal("failed export marked published", err, statErr)
				}
				return
			}
			var result cacheImageResult
			if readErr := readCacheJSON(filepath.Join(dir, "image.json"), &result); readErr != nil {
				t.Fatal(readErr)
			}
			if err != nil || result.Image == nil || result.Image.Digest != image.Digest || result.Blob == nil || result.Blob.Digest != blob.Digest || result.Blob.Size != blob.Size {
				t.Fatal("missing publication marker", err)
			}
			for _, path := range []string{local, output} {
				if path == "" {
					continue
				}
				bytes, err := os.ReadFile(path)
				if err != nil || string(bytes) != expected {
					t.Fatal("invalid bootstrap", err)
				}
			}
			var index ocispec.Index
			if err := readCacheJSON(filepath.Join(contentDir, "index.json"), &index); err != nil {
				t.Fatal(err)
			}
			if index.SchemaVersion != 2 || len(index.Manifests) != 1 || index.Manifests[0].Digest != image.Digest {
				t.Fatal("invalid OCI index")
			}
			var layout ocispec.ImageLayout
			if err := readCacheJSON(filepath.Join(contentDir, "oci-layout"), &layout); err != nil || layout.Version != ocispec.ImageLayoutVersion {
				t.Fatal("invalid OCI layout", err)
			}
		})
	}
}

func readCacheJSON(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}
