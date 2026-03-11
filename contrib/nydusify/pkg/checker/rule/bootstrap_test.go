// Copyright 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/containerd/nydus-snapshotter/pkg/label"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/checker/tool"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/remote"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
)

func TestBootstrapRuleValidate(t *testing.T) {
	workDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(workDir, "source", "nydus_bootstrap", filepath.Dir(utils.BootstrapFileNameInLayer)), 0o755))
	parsed := &parser.Parsed{
		Remote: &remote.Remote{Ref: "example.com/nydus:latest"},
		NydusImage: &parser.Image{
			Manifest: ocispec.Manifest{Layers: []ocispec.Descriptor{
				{Digest: digest.FromString("blob1")},
				{Digest: digest.FromString("bootstrap"), Annotations: map[string]string{utils.LayerAnnotationNydusBootstrap: "true"}},
			}},
		},
	}
	rule := &BootstrapRule{WorkDir: workDir, NydusImagePath: "/usr/bin/nydus-image"}

	patches := gomonkey.ApplyMethod(reflect.TypeOf(&tool.Builder{}), "Check", func(_ *tool.Builder, option tool.BuilderOption) error {
		if err := os.MkdirAll(filepath.Dir(option.DebugOutputPath), 0o755); err != nil {
			return err
		}
		payload, err := json.Marshal(output{Blobs: []string{digest.FromString("blob1").Hex()}})
		if err != nil {
			return err
		}
		return os.WriteFile(option.DebugOutputPath, payload, 0o644)
	})
	defer patches.Reset()

	err := rule.validate(parsed, "source")
	require.NoError(t, err)

	patches.Reset()
	patches = gomonkey.ApplyMethod(reflect.TypeOf(&tool.Builder{}), "Check", func(_ *tool.Builder, option tool.BuilderOption) error {
		if err := os.MkdirAll(filepath.Dir(option.DebugOutputPath), 0o755); err != nil {
			return err
		}
		payload, err := json.Marshal(output{Blobs: []string{digest.FromString("missing").Hex()}})
		if err != nil {
			return err
		}
		return os.WriteFile(option.DebugOutputPath, payload, 0o644)
	})
	defer patches.Reset()

	err = rule.validate(parsed, "source")
	require.Error(t, err)
	require.Contains(t, err.Error(), "should all appear in the layers")

	parsed.NydusImage.Manifest.Layers[0].Annotations = map[string]string{label.NydusRefLayer: "true"}
	patches.Reset()
	patches = gomonkey.ApplyMethod(reflect.TypeOf(&tool.Builder{}), "Check", func(_ *tool.Builder, option tool.BuilderOption) error {
		if err := os.MkdirAll(filepath.Dir(option.DebugOutputPath), 0o755); err != nil {
			return err
		}
		payload, err := json.Marshal(output{Blobs: []string{digest.FromString("blob1").Hex()}})
		if err != nil {
			return err
		}
		return os.WriteFile(option.DebugOutputPath, payload, 0o644)
	})
	defer patches.Reset()

	err = rule.validate(parsed, "source")
	require.NoError(t, err)
}

func TestBootstrapRuleValidateOutputErrors(t *testing.T) {
	workDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(workDir, "target", "nydus_bootstrap", filepath.Dir(utils.BootstrapFileNameInLayer)), 0o755))
	parsed := &parser.Parsed{
		Remote: &remote.Remote{Ref: "example.com/nydus:latest"},
		NydusImage: &parser.Image{
			Manifest: ocispec.Manifest{Layers: []ocispec.Descriptor{{Digest: digest.FromString("bootstrap")}}},
		},
	}
	rule := &BootstrapRule{WorkDir: workDir, NydusImagePath: "/usr/bin/nydus-image"}

	patches := gomonkey.ApplyMethod(reflect.TypeOf(&tool.Builder{}), "Check", func(_ *tool.Builder, option tool.BuilderOption) error {
		if err := os.MkdirAll(filepath.Dir(option.DebugOutputPath), 0o755); err != nil {
			return err
		}
		return os.WriteFile(option.DebugOutputPath, []byte("not-json"), 0o644)
	})
	defer patches.Reset()

	err := rule.validate(parsed, "target")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unmarshal bootstrap output JSON")

	patches.Reset()
	patches = gomonkey.ApplyMethod(reflect.TypeOf(&tool.Builder{}), "Check", func(_ *tool.Builder, option tool.BuilderOption) error {
		if err := os.MkdirAll(filepath.Dir(option.DebugOutputPath), 0o755); err != nil {
			return err
		}
		_ = os.Remove(option.DebugOutputPath)
		return nil
	})
	defer patches.Reset()

	err = rule.validate(parsed, "target")
	require.Error(t, err)
	require.Contains(t, err.Error(), "read bootstrap debug json")
}
