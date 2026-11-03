/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import (
	"archive/tar"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/containerd/v2/plugins/content/local"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/nydusify/internal/nydusfs"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

func TestCheckerSetupFailures(t *testing.T) {
	_, err := New(Option{})
	require.ErrorContains(t, err, "at least one")
	for _, phase := range []string{"content", "scratch", "source", "target"} {
		t.Run(phase, func(t *testing.T) {
			work := t.TempDir()
			opt := Option{WorkDir: work, Source: "://invalid"}
			want := "create dir"
			if phase == "source" || phase == "target" {
				want = "load " + phase
				if phase == "target" {
					opt.Source, opt.Target = "", "://invalid"
				}
			} else {
				path := filepath.Join(work, phase)
				require.NoError(t, os.WriteFile(path, nil, 0o600))
			}
			checker, err := New(opt)
			require.NoError(t, err)
			require.NotNil(t, checker.opt.PlatformMC)
			require.Equal(t, "info", checker.opt.LogLevel)
			require.ErrorContains(t, checker.Check(context.Background()), want)
		})
	}
}

func TestMaterializationFailureCleanup(t *testing.T) {
	for _, phase := range []string{"scratch", "missing-bootstrap", "cache", "bootstrap", "blob", "oci"} {
		t.Run(phase, func(t *testing.T) {
			rule, img := mountRule(t, "")
			work := t.TempDir()
			rule.workDir = work
			want := ""
			switch phase {
			case "scratch":
				rule.workDir = filepath.Join(work, "file")
				require.NoError(t, os.WriteFile(rule.workDir, nil, 0o600))
				want = "create scratch dir"
			case "missing-bootstrap":
				img.Bootstrap = nil
				want = "missing its bootstrap"
			case "cache":
				require.NoError(t, os.WriteFile(filepath.Join(work, "cache"), nil, 0o600))
				_, _, err := rule.fuseMount(context.Background(), work, remote.Source, img)
				require.ErrorContains(t, err, "create dir")
				return
			case "bootstrap":
				img.Bootstrap.Digest = digest.FromString("absent bootstrap")
				want = "extract bootstrap"
			case "blob":
				img.Manifest.Layers = []ocispec.Descriptor{{Digest: digest.FromString("absent blob"), Size: 100,
					MediaType: nydus.MediaTypeNydusBlob, Annotations: map[string]string{nydus.LayerAnnotationNydusBlob: "true"}}}
				want = "inspect blob layers"
			case "oci":
				img.Kind = nydusfs.KindOCI
				img.Manifest.Layers = []ocispec.Descriptor{{Digest: digest.FromString("absent layer"), MediaType: ocispec.MediaTypeImageLayer}}
				want = "apply oci image"
			}
			root, cleanup, err := rule.mount(context.Background(), "source", remote.Source, img)
			require.ErrorContains(t, err, want)
			require.Empty(t, root)
			require.Nil(t, cleanup)
			paths, err := filepath.Glob(filepath.Join(work, "fs-source-*"))
			require.NoError(t, err)
			require.Empty(t, paths, "failed materialization must remove its scratch directory")
		})
	}
}

func TestBootstrapRuleFailures(t *testing.T) {
	for _, phase := range []string{"source", "target", "scratch", "extract"} {
		t.Run(phase, func(t *testing.T) {
			fs, img := mountRule(t, "")
			rule := bootstrapRule{cs: fs.cs, workDir: t.TempDir(), source: img}
			want := "source bootstrap"
			switch phase {
			case "source":
				img.Bootstrap = nil
			case "target":
				img.Bootstrap = nil
				rule.source, rule.target = nil, img
				want = "target bootstrap"
			case "scratch":
				rule.workDir = filepath.Join(rule.workDir, "missing")
				want = "create scratch dir"
			case "extract":
				img.Bootstrap.Digest = digest.FromString("absent bootstrap")
				want = "extract bootstrap"
			}
			require.ErrorContains(t, rule.Validate(context.Background()), want)
		})
	}
}

func TestExportImageFailures(t *testing.T) {
	for _, stage := range []string{"success", "index", "manifest", "config", "bootstrap", "output", "bootstrap output"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			rule, img := mountRule(t, "")
			config, err := oci.WriteJSON(ctx, rule.cs, ocispec.Image{}, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig}, nil)
			require.NoError(t, err)
			img.Manifest = ocispec.Manifest{Config: *config, Layers: []ocispec.Descriptor{*img.Bootstrap}}
			manifest, err := oci.WriteJSON(ctx, rule.cs, img.Manifest, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, nil)
			require.NoError(t, err)
			img.Desc = *manifest
			index, err := oci.WriteJSON(ctx, rule.cs, ocispec.Index{Manifests: []ocispec.Descriptor{*manifest}},
				ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex}, nil)
			require.NoError(t, err)
			img.Root = *index
			dest := filepath.Join(t.TempDir(), "export")
			missing := digest.FromString("not in content store")
			switch stage {
			case "index":
				img.Root.Digest = missing
			case "manifest":
				img.Desc.Digest = missing
			case "config":
				img.Manifest.Config.Digest = missing
			case "bootstrap":
				img.Bootstrap.Digest = missing
			case "output":
				require.NoError(t, os.WriteFile(dest, nil, 0o600))
			case "bootstrap output":
				require.NoError(t, os.MkdirAll(filepath.Join(dest, "bootstrap", "image", "image.boot"), 0o700))
			}

			err = exportImage(ctx, rule.cs, img, dest)
			switch stage {
			case "success":
				require.NoError(t, err)
				for _, path := range []string{"index.json", "manifest.json", "config.json", "bootstrap/image/image.boot"} {
					data, err := os.ReadFile(filepath.Join(dest, path))
					require.NoError(t, err)
					require.NotEmpty(t, data)
				}
			case "index", "manifest", "config":
				require.ErrorContains(t, err, "write "+stage+".json")
			case "bootstrap", "bootstrap output":
				require.ErrorContains(t, err, "extract bootstrap layer")
			case "output":
				require.ErrorContains(t, err, "create export dir")
			}
		})
	}
}

func TestExportImage(t *testing.T) {
	tests := []struct {
		name   string
		kind   nydusfs.ImageKind
		setup  func(t *testing.T, dest string)
		expect func(t *testing.T, dest string, err error)
	}{
		{
			name: "export oci manifest without index",
			kind: nydusfs.KindOCI,
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				config, err := os.ReadFile(filepath.Join(dest, "config.json"))
				assert.NoError(err)
				assert.JSONEq(`{"architecture":"amd64","os":"linux","config":{"Env":["PATH=/bin"],"Cmd":["sh"]},"rootfs":{"type":"","diff_ids":null}}`, string(config))
				assert.FileExists(filepath.Join(dest, "manifest.json"))
				assert.NoFileExists(filepath.Join(dest, "index.json"))
				assert.NoDirExists(filepath.Join(dest, "bootstrap"))
			},
		},
		{
			name: "reject nydus image without bootstrap",
			kind: nydusfs.KindNydus,
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "nydus image is missing its bootstrap layer")
			},
		},
		{
			name: "report unwritable manifest file",
			kind: nydusfs.KindOCI,
			setup: func(t *testing.T, dest string) {
				assert.NoError(t, os.MkdirAll(filepath.Join(dest, "manifest.json"), 0o755))
			},
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "write manifest.json: write")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs, err := local.NewStore(t.TempDir())
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			configData, err := json.Marshal(mockImageConfig)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			manifest := ocispec.Manifest{Config: mockBlob(t, cs, ocispec.MediaTypeImageConfig, configData)}
			manifestData, err := json.Marshal(manifest)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			desc := mockBlob(t, cs, ocispec.MediaTypeImageManifest, manifestData)
			dest := filepath.Join(t.TempDir(), "export")
			if tc.setup != nil {
				tc.setup(t, dest)
			}

			img := &nydusfs.Image{Root: desc, Desc: desc, Manifest: manifest, Kind: tc.kind}
			tc.expect(t, dest, exportImage(context.Background(), cs, img, dest))
		})
	}
}

func TestExtractBootstrapTree(t *testing.T) {
	tests := []struct {
		name   string
		layer  func(t *testing.T) []byte
		setup  func(t *testing.T, dest string)
		expect func(t *testing.T, dest string, err error)
	}{
		{
			name: "extract nested entries and skip links",
			layer: func(t *testing.T) []byte {
				return mockTar(t, []mockTarEntry{
					{header: tar.Header{Name: "image/", Typeflag: tar.TypeDir, Mode: 0o755}},
					{header: tar.Header{Name: "image/image.boot", Typeflag: tar.TypeReg, Mode: 0o644}, data: "bootstrap"},
					{header: tar.Header{Name: "image/meta/layer.blob.meta", Typeflag: tar.TypeReg, Mode: 0o644}, data: "meta"},
					{header: tar.Header{Name: "image/link", Typeflag: tar.TypeSymlink, Linkname: "image.boot"}},
				})
			},
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, err := os.ReadFile(filepath.Join(dest, "image", "image.boot"))
				assert.NoError(err)
				assert.Equal("bootstrap", string(data))
				data, err = os.ReadFile(filepath.Join(dest, "image", "meta", "layer.blob.meta"))
				assert.NoError(err)
				assert.Equal("meta", string(data))
				_, err = os.Lstat(filepath.Join(dest, "image", "link"))
				assert.ErrorIs(err, os.ErrNotExist)
			},
		},
		{
			name: "reject path traversal",
			layer: func(t *testing.T) []byte {
				return mockTar(t, []mockTarEntry{
					{header: tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0o644}, data: "escape"},
				})
			},
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `invalid tar entry path "../escape"`)
				assert.NoFileExists(filepath.Join(filepath.Dir(dest), "escape"))
			},
		},
		{
			name: "reject corrupt archive",
			layer: func(t *testing.T) []byte {
				return []byte("not a tar archive")
			},
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read bootstrap tar")
			},
		},
		{
			name: "reject directory entry over file",
			layer: func(t *testing.T) []byte {
				return mockTar(t, []mockTarEntry{{header: tar.Header{Name: "image/", Typeflag: tar.TypeDir, Mode: 0o755}}})
			},
			setup: func(t *testing.T, dest string) {
				assert.NoError(t, os.MkdirAll(dest, 0o755))
				assert.NoError(t, os.WriteFile(filepath.Join(dest, "image"), nil, 0o600))
			},
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create dir")
			},
		},
		{
			name: "reject file entry under file",
			layer: func(t *testing.T) []byte {
				return mockTar(t, mockBootstrapEntries)
			},
			setup: func(t *testing.T, dest string) {
				assert.NoError(t, os.MkdirAll(dest, 0o755))
				assert.NoError(t, os.WriteFile(filepath.Join(dest, "image"), nil, 0o600))
			},
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create parent dir")
			},
		},
		{
			name: "reject occupied destination",
			layer: func(t *testing.T) []byte {
				return mockTar(t, mockBootstrapEntries)
			},
			setup: func(t *testing.T, dest string) {
				assert.NoError(t, os.WriteFile(dest, nil, 0o600))
			},
			expect: func(t *testing.T, dest string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create bootstrap dir")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs, err := local.NewStore(t.TempDir())
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			desc := mockBlob(t, cs, ocispec.MediaTypeImageLayer, tc.layer(t))
			dest := filepath.Join(t.TempDir(), "bootstrap")
			if tc.setup != nil {
				tc.setup(t, dest)
			}

			tc.expect(t, dest, extractBootstrapTree(context.Background(), cs, desc, dest))
		})
	}
}

func TestSafeJoin(t *testing.T) {
	tests := []struct {
		name   string
		entry  string
		expect func(t *testing.T, target string, err error)
	}{
		{
			name:  "nested entry",
			entry: "image/image.boot",
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("/base/image/image.boot", target)
			},
		},
		{
			name:  "absolute entry stays inside base",
			entry: "/image/image.boot",
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("/base/image/image.boot", target)
			},
		},
		{
			name:  "dot dot prefixed name",
			entry: "..image",
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("/base/..image", target)
			},
		},
		{
			name:  "parent entry",
			entry: "..",
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `invalid tar entry path ".."`)
				assert.Empty(target)
			},
		},
		{
			name:  "nested escaping entry",
			entry: "image/../../escape",
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `invalid tar entry path "image/../../escape"`)
				assert.Empty(target)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target, err := safeJoin("/base", tc.entry)
			tc.expect(t, target, err)
		})
	}
}
