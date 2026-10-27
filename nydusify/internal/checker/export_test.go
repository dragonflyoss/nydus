/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
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
