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
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/platforms"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydusify/internal/registrytest"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

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

type mockTarEntry struct {
	header tar.Header
	data   string
}

func mockTar(t *testing.T, entries []mockTarEntry) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, entry := range entries {
		header := entry.header
		header.Size = int64(len(entry.data))
		if err := tw.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}

		if _, err := tw.Write([]byte(entry.data)); err != nil {
			t.Fatal(err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

func mockBlob(t *testing.T, cs content.Store, mediaType string, data []byte) ocispec.Descriptor {
	desc := ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
	if err := content.WriteBlob(context.Background(), cs, desc.Digest.String(), bytes.NewReader(data), desc); err != nil {
		t.Fatal(err)
	}

	return desc
}

func mockBuilder(t *testing.T, dir, body string) string {
	path := filepath.Join(dir, "nydus")
	if body == "" {
		return path
	}

	if err := os.WriteFile(path, []byte(mockBuilderScript+body), 0o700); err != nil {
		t.Fatal(err)
	}

	return path
}

func mockBuilderArgs(t *testing.T, dir string) []string {
	data, err := os.ReadFile(filepath.Join(dir, "args"))
	if os.IsNotExist(err) {
		return nil
	}

	if err != nil {
		t.Fatal(err)
	}

	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

func mockLayer(t *testing.T, reg *registrytest.Registry, repo, mediaType string, annotations map[string]string, entries []mockTarEntry) ocispec.Descriptor {
	layer := reg.Store(repo, "", "", mockTar(t, entries))
	layer.MediaType = mediaType
	layer.Annotations = annotations
	return layer
}

func TestNew(t *testing.T) {
	tests := []struct {
		name   string
		opt    Option
		expect func(t *testing.T, checker *Checker, err error)
	}{
		{
			name: "fill default platform and log level",
			opt:  Option{Source: "://invalid"},
			expect: func(t *testing.T, checker *Checker, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&Checker{opt: Option{Source: "://invalid", PlatformMC: platforms.Default(), LogLevel: "info"}}, checker)
			},
		},
		{
			name: "reject empty source and target",
			expect: func(t *testing.T, checker *Checker, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "at least one of source or target must be provided")
				assert.Nil(checker)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checker, err := New(tc.opt)
			tc.expect(t, checker, err)
		})
	}
}

func TestChecker_Check(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	reg := registrytest.New(t)

	ociLayer := mockLayer(t, reg, "oci", ocispec.MediaTypeImageLayer, nil, mockLayerEntries)
	ociConfig := mockImageConfig
	ociConfig.RootFS.DiffIDs = []digest.Digest{ociLayer.Digest}
	reg.StoreImage(t, "oci", "latest", ociConfig, ociLayer)

	driftLayer := mockLayer(t, reg, "drift", ocispec.MediaTypeImageLayer, nil, mockLayerEntries)
	driftConfig := mockImageConfig
	driftConfig.Config.Env = []string{"PATH=/usr/bin"}
	driftConfig.RootFS.DiffIDs = []digest.Digest{driftLayer.Digest}
	reg.StoreImage(t, "drift", "latest", driftConfig, driftLayer)

	nydusBlob := reg.Store("nydus", "", nydus.MediaTypeNydusBlob, []byte("blob"))
	nydusBootstrap := mockLayer(t, reg, "nydus", ocispec.MediaTypeImageLayer, map[string]string{nydus.LayerAnnotationNydusBootstrap: "true"}, mockBootstrapEntries)
	nydusConfig := mockImageConfig
	nydusConfig.RootFS.DiffIDs = []digest.Digest{nydusBlob.Digest, nydusBootstrap.Digest}
	reg.StoreImage(t, "nydus", "latest", nydusConfig, nydusBlob, nydusBootstrap)

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
			source: reg.Ref("oci", "latest"),
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
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
			target:  reg.Ref("nydus", "latest"),
			builder: "exit 0\n",
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, err := os.ReadFile(filepath.Join(dir, "work", "target", "bootstrap", "image", "image.boot"))
				assert.NoError(err)
				assert.Equal("bootstrap", string(data))
				assert.Regexp("^check --bootstrap "+regexp.QuoteMeta(filepath.Join(dir, "work", "scratch", "bootstrap-target-"))+`\S+$`, strings.Join(mockBuilderArgs(t, dir), " "))
				entries, err := os.ReadDir(filepath.Join(dir, "work", "scratch"))
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name:    "reject corrupted nydus bootstrap",
			target:  reg.Ref("nydus", "latest"),
			builder: "echo 'invalid superblock' >&2\nexit 1\n",
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "bootstrap rule failed: target bootstrap: nydus check failed: invalid superblock")
			},
		},
		{
			name:   "reject occupied content dir",
			source: reg.Ref("oci", "latest"),
			setup: func(t *testing.T, workDir string) {
				if err := os.WriteFile(filepath.Join(workDir, "content"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, fmt.Sprintf("create dir %q", filepath.Join(dir, "work", "content")))
			},
		},
		{
			name:   "reject occupied scratch dir",
			source: reg.Ref("oci", "latest"),
			setup: func(t *testing.T, workDir string) {
				if err := os.WriteFile(filepath.Join(workDir, "scratch"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, fmt.Sprintf("create dir %q", filepath.Join(dir, "work", "scratch")))
			},
		},
		{
			name:   "reject invalid source reference",
			source: "://invalid",
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `load source "://invalid"`)
			},
		},
		{
			name:   "reject invalid target reference",
			target: "://invalid",
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `load target "://invalid"`)
			},
		},
		{
			name:   "reject occupied source export path",
			source: reg.Ref("oci", "latest"),
			setup: func(t *testing.T, workDir string) {
				if err := os.WriteFile(filepath.Join(workDir, "source"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "export source: create export dir")
			},
		},
		{
			name:   "reject occupied target export path",
			target: reg.Ref("oci", "latest"),
			setup: func(t *testing.T, workDir string) {
				if err := os.WriteFile(filepath.Join(workDir, "target"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "export target: create export dir")
			},
		},
		{
			name:   "reject config drift between source and target",
			source: reg.Ref("oci", "latest"),
			target: reg.Ref("drift", "latest"),
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
			if err := os.Mkdir(workDir, 0o755); err != nil {
				t.Fatal(err)
			}

			if tc.setup != nil {
				tc.setup(t, workDir)
			}

			checker, err := New(Option{
				Source:          tc.source,
				Target:          tc.target,
				WorkDir:         workDir,
				BuilderPath:     mockBuilder(t, dir, tc.builder),
				SourcePlainHTTP: true,
				TargetPlainHTTP: true,
			})
			if err != nil {
				t.Fatal(err)
			}

			tc.expect(t, dir, checker.Check(context.Background()))
		})
	}
}
