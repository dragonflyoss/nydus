/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydusify/internal/registrytest"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

type mockTarEntry struct {
	header tar.Header
	data   string
}

var (
	mockImageConfig = ocispec.Image{
		Platform: ocispec.Platform{OS: "linux", Architecture: "amd64"},
		Config:   ocispec.ImageConfig{Env: []string{"PATH=/bin"}, Cmd: []string{"sh"}},
	}

	mockLayerEntries = []mockTarEntry{
		{header: tar.Header{Name: "etc/", Typeflag: tar.TypeDir, Mode: 0o755}},
		{header: tar.Header{Name: "etc/hostname", Typeflag: tar.TypeReg, Mode: 0o644}, data: "nydus\n"},
	}

	mockBootstrapEntries = []mockTarEntry{
		{header: tar.Header{Name: nydus.BootstrapFileNameInLayer, Typeflag: tar.TypeReg, Mode: 0o644}, data: "bootstrap"},
	}

	mockBuilderScript = "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$(dirname \"$0\")/args\"\n"
)

func mockTar(t *testing.T, entries []mockTarEntry) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, entry := range entries {
		header := entry.header
		header.Size = int64(len(entry.data))
		if !assert.NoError(t, tw.WriteHeader(&header)) {
			t.FailNow()
		}

		if _, err := tw.Write([]byte(entry.data)); !assert.NoError(t, err) {
			t.FailNow()
		}
	}

	if !assert.NoError(t, tw.Close()) {
		t.FailNow()
	}

	return buf.Bytes()
}

func mockBlob(t *testing.T, cs content.Store, mediaType string, data []byte) ocispec.Descriptor {
	desc := ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
	if !assert.NoError(t, content.WriteBlob(context.Background(), cs, desc.Digest.String(), bytes.NewReader(data), desc)) {
		t.FailNow()
	}

	return desc
}

func mockBuilder(t *testing.T, dir, body string) string {
	path := filepath.Join(dir, "nydus")
	if body == "" {
		return path
	}

	if !assert.NoError(t, os.WriteFile(path, []byte(mockBuilderScript+body), 0o700)) {
		t.FailNow()
	}

	return path
}

func mockBuilderArgs(t *testing.T, dir string) []string {
	data, err := os.ReadFile(filepath.Join(dir, "args"))
	if os.IsNotExist(err) {
		return nil
	}

	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

type registry struct {
	*registrytest.Registry
}

func newRegistry(t *testing.T) *registry {
	return &registry{registrytest.New(t)}
}

func (r *registry) storeImage(t *testing.T, repo string, config ocispec.Image, layers ...ocispec.Descriptor) {
	for _, layer := range layers {
		config.RootFS.DiffIDs = append(config.RootFS.DiffIDs, layer.Digest)
	}

	r.StoreJSON(t, repo, "latest", ocispec.MediaTypeImageManifest, ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    r.StoreJSON(t, repo, "", ocispec.MediaTypeImageConfig, config),
		Layers:    layers,
	})
}

func (r *registry) storeLayer(t *testing.T, repo, mediaType string, annotations map[string]string, entries []mockTarEntry) ocispec.Descriptor {
	layer := r.Store(repo, "", "", mockTar(t, entries))
	layer.MediaType = mediaType
	layer.Annotations = annotations
	return layer
}

func TestChecker_Check(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	reg := newRegistry(t)
	reg.storeImage(t, "oci", mockImageConfig, reg.storeLayer(t, "oci", ocispec.MediaTypeImageLayer, nil, mockLayerEntries))
	driftConfig := mockImageConfig
	driftConfig.Config.Env = []string{"PATH=/usr/bin"}
	reg.storeImage(t, "drift", driftConfig, reg.storeLayer(t, "drift", ocispec.MediaTypeImageLayer, nil, mockLayerEntries))
	blob := reg.Store("nydus", "", nydus.MediaTypeNydusBlob, []byte("blob"))
	reg.storeImage(t, "nydus", mockImageConfig, blob, reg.storeLayer(t, "nydus", ocispec.MediaTypeImageLayer,
		map[string]string{nydus.LayerAnnotationNydusBootstrap: "true"}, mockBootstrapEntries))

	tests := []struct {
		name    string
		source  string
		target  string
		builder string
		setup   func(t *testing.T, workDir string)
		expect  func(t *testing.T, dir string, err error)
	}{
		{
			name:   "export oci source metadata",
			source: "oci",
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					t.FailNow()
				}

				manifest, _ := reg.Load("oci", "latest")
				data, err := os.ReadFile(filepath.Join(dir, "work", "source", "manifest.json"))
				assert.NoError(err)
				assert.Equal(manifest, data)
				assert.FileExists(filepath.Join(dir, "work", "source", "config.json"))
				assert.NoFileExists(filepath.Join(dir, "work", "source", "index.json"))
				assert.NoDirExists(filepath.Join(dir, "work", "source", "bootstrap"))
				assert.Nil(mockBuilderArgs(t, dir))
			},
		},
		{
			name:    "export and check nydus target bootstrap",
			target:  "nydus",
			builder: "exit 0\n",
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					t.FailNow()
				}

				data, err := os.ReadFile(filepath.Join(dir, "work", "target", "bootstrap", "image", "image.boot"))
				assert.NoError(err)
				assert.Equal("bootstrap", string(data))
				args := mockBuilderArgs(t, dir)
				if !assert.Len(args, 3) {
					t.FailNow()
				}

				assert.Equal([]string{"check", "--bootstrap"}, args[:2])
				assert.True(strings.HasPrefix(args[2], filepath.Join(dir, "work", "scratch", "bootstrap-target-")))
				entries, err := os.ReadDir(filepath.Join(dir, "work", "scratch"))
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name:    "reject corrupted nydus bootstrap",
			target:  "nydus",
			builder: "echo 'invalid superblock' >&2\nexit 1\n",
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "bootstrap rule failed: target bootstrap: nydus check failed: invalid superblock")
			},
		},
		{
			name:   "reject occupied source export path",
			source: "oci",
			setup: func(t *testing.T, workDir string) {
				assert.NoError(t, os.WriteFile(filepath.Join(workDir, "source"), nil, 0o600))
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "export source: create export dir")
			},
		},
		{
			name:   "reject occupied target export path",
			target: "oci",
			setup: func(t *testing.T, workDir string) {
				assert.NoError(t, os.WriteFile(filepath.Join(workDir, "target"), nil, 0o600))
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "export target: create export dir")
			},
		},
		{
			name:   "reject config drift between source and target",
			source: "oci",
			target: "drift",
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "manifest rule failed: config consistency: image config")
				assert.NoDirExists(filepath.Join(dir, "work", "source"))
				assert.NoDirExists(filepath.Join(dir, "work", "target"))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			workDir := filepath.Join(dir, "work")
			if !assert.NoError(t, os.Mkdir(workDir, 0o755)) {
				t.FailNow()
			}

			if tc.setup != nil {
				tc.setup(t, workDir)
			}

			opt := Option{
				WorkDir:         workDir,
				BuilderPath:     mockBuilder(t, dir, tc.builder),
				SourcePlainHTTP: true,
				TargetPlainHTTP: true,
			}
			if tc.source != "" {
				opt.Source = reg.Ref(tc.source, "latest")
			}

			if tc.target != "" {
				opt.Target = reg.Ref(tc.target, "latest")
			}

			checker, err := New(opt)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			tc.expect(t, dir, checker.Check(context.Background()))
		})
	}
}
