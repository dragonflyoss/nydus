/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/platforms"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"

	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/internal/registrytest"
)

func runNydusify(args ...string) error {
	app := &cli.App{Writer: io.Discard, ErrWriter: io.Discard,
		Commands: []*cli.Command{convertCommand(), checkCommand(), mountCommand(), optimizeCommand()}}
	return app.Run(append([]string{"nydusify"}, args...))
}

func requireBuilder(t *testing.T) string {
	builder := os.Getenv("NYDUS_TEST_BUILDER")
	if builder == "" {
		t.Skip("set NYDUS_TEST_BUILDER to run real builder conversions")
	}
	return builder
}

func TestCommandFailures(t *testing.T) {
	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocked")
	require.NoError(t, os.WriteFile(blocked, []byte("not a directory"), 0o600))
	missing := filepath.Join(dir, "missing")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"annotation", []string{"convert", "--source", dir, "--manifest-annotation", "bad"}, "expected key=value"},
		{"inputs", []string{"convert"}, "source"},
		{"prune-source", []string{"convert", "--source", dir, "--prune"}, "--prune requires --bootstrap"},
		{"compact-source", []string{"convert", "--source", dir, "--compact-max-layers", "1"}, "--compact-max-layers requires --bootstrap"},
		{"export-source", []string{"convert", "--source", dir, "--output-bootstrap", missing}, "--output-bootstrap requires --bootstrap"},
		{"compressor", []string{"convert", "--source", dir, "--compressor", "invalid"}, "unsupported --compressor"},
		{"oci-annotation", []string{"convert", "--source", dir, "--compressor", "oci-tar", "--manifest-annotation", "key=value"}, "only supported"},
		{"chunk-overflow", []string{"convert", "--source", dir, "--chunk-size", "4294967296"}, "fit uint32"},
		{"convert-platform", []string{"convert", "--source", dir, "--platform", "a/b/c/d"}, "invalid platform"},
		{"convert-work", []string{"convert", "--source", dir, "--work-dir", blocked}, "create work dir"},
		{"oci-artifact", []string{"convert", "--bootstrap", blocked, "--blob", blocked, "--compressor", "oci-tar"}, "artifacts back to OCI"},
		{"oci-directory", []string{"convert", "--source", dir, "--compressor", "oci-tar"}, "exactly one nydus image"},
		{"oci-pull", []string{"convert", "--source", "://bad", "--compressor", "oci-tar"}, "pull"},
		{"parent-reference", []string{"convert", "--bootstrap", blocked, "--parent-image", "://bad"}, "reference"},
		{"artifact-inspect", []string{"convert", "--bootstrap", blocked, "--blob", blocked, "--builder", missing}, "inspect bootstrap"},
		{"directory-build", []string{"convert", "--source", dir, "--builder", missing}, "convert"},
		{"image-pull", []string{"convert", "--source", "://bad"}, "pull"},
		{"check-platform", []string{"check", "--platform", "a/b/c/d"}, "invalid platform"},
		{"check-work", []string{"check", "--work-dir", blocked}, "create work dir"},
		{"mount-platform", []string{"mount", "--platform", "a/b/c/d"}, "invalid platform"},
		{"mount-point", []string{"mount", "--mountpoint", blocked}, "create mountpoint"},
		{"mount-work", []string{"mount", "--work-dir", blocked}, "create work dir"},
		{"optimize-platform", []string{"optimize", "--platform", "a/b/c/d"}, "invalid platform"},
		{"optimize-work", []string{"optimize", "--work-dir", blocked}, "create work dir"},
		{"optimize-reference", []string{"optimize", "--source", "://bad"}, "reference"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"nydusify", tc.args[0], "--target", "example.test/image:tag", "--work-dir", t.TempDir()}
			if tc.args[0] == "mount" {
				args = append(args, "--mountpoint", t.TempDir())
			}
			if tc.args[0] == "optimize" {
				args = append(args, "--source", "example.test/image:source", "--trace-file", blocked)
			}
			args = append(args, tc.args[1:]...)
			app := &cli.App{Writer: io.Discard, ErrWriter: io.Discard,
				Commands: []*cli.Command{convertCommand(), checkCommand(), mountCommand(), optimizeCommand()}}
			require.ErrorContains(t, app.Run(args), tc.want)
		})
	}
}

func TestParseManifestAnnotations(t *testing.T) {
	tests := []struct {
		name    string
		values  []string
		want    map[string]string
		wantErr bool
	}{
		{
			name:   "multiple annotations",
			values: []string{"backend=dragonfly-snapshotter", "digest=xxh3:0123456789abcdef", "empty="},
			want:   map[string]string{"backend": "dragonfly-snapshotter", "digest": "xxh3:0123456789abcdef", "empty": ""},
		},
		{
			name:   "value contains equals",
			values: []string{"key=value=tail"},
			want:   map[string]string{"key": "value=tail"},
		},
		{
			name:   "duplicate key uses last value",
			values: []string{"key=old", "key=new"},
			want:   map[string]string{"key": "new"},
		},
		{name: "missing equals", values: []string{"key"}, wantErr: true},
		{name: "empty key", values: []string{"=value"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseManifestAnnotations(tt.values)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseManifestAnnotations() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseManifestAnnotations() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestManifestAnnotationFlagPreservesCommas(t *testing.T) {
	var values []string
	annotationFlag := &manifestAnnotationValue{}
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.GenericFlag{Name: "manifest-annotation", Value: annotationFlag},
		},
		Action: func(c *cli.Context) error {
			values = manifestAnnotationValues(c)
			return nil
		},
	}

	const annotation = `io.cri-proxy.snapshot.vm-rootfs={"path":"rootfs.img","digest":"xxh3:0123456789abcdef"}`
	if err := app.Run([]string{
		"nydusify",
		"--manifest-annotation", annotation,
	}); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(values, []string{annotation}) {
		t.Fatalf("manifest annotation values = %q, want %q", values, []string{annotation})
	}
}

func TestManifestAnnotationFlagDoesNotChangeSliceFlags(t *testing.T) {
	annotationFlag := &manifestAnnotationValue{}
	var sources []string
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringSliceFlag{Name: "source"},
			&cli.GenericFlag{Name: "manifest-annotation", Value: annotationFlag},
		},
		Action: func(c *cli.Context) error {
			sources = c.StringSlice("source")
			return nil
		},
	}

	if err := app.Run([]string{"nydusify", "--source", "lower,upper"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sources, []string{"lower", "upper"}) {
		t.Fatalf("source values = %q, want %q", sources, []string{"lower", "upper"})
	}
}

func TestRunConvert(t *testing.T) {
	tests := []struct {
		name   string
		args   func(t *testing.T, r *registry, dir string) []string
		expect func(t *testing.T, r *registry, dir string, err error)
	}{
		{
			name: "convert oci image to nydus",
			args: func(t *testing.T, r *registry, _ string) []string {
				return []string{"--builder", requireBuilder(t), "--source", r.Ref("oci", "v1"), "--target", r.Ref("nydus", "v1")}
			},
			expect: func(t *testing.T, r *registry, _ string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				var index ocispec.Index
				r.LoadJSON(t, "nydus", "v1", &index)
				assert.Len(index.Manifests, 2)
				for _, desc := range index.Manifests {
					blobs, _ := r.nydusManifest(t, "nydus", desc.Digest.String())
					assert.Len(blobs, 1)
					_, ok := r.Load("nydus", blobs[0].Digest.String())
					assert.True(ok)
				}
			},
		},
		{
			name: "convert one platform of oci image",
			args: func(t *testing.T, r *registry, _ string) []string {
				return []string{"--builder", requireBuilder(t), "--source", r.Ref("oci", "v1"), "--target", r.Ref("nydus", "v1"), "--platform", "linux/arm64"}
			},
			expect: func(t *testing.T, r *registry, _ string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				var manifest ocispec.Manifest
				r.LoadJSON(t, "nydus", "v1", &manifest)
				var config ocispec.Image
				r.LoadJSON(t, "nydus", manifest.Config.Digest.String(), &config)
				assert.Equal("arm64", config.Architecture)
			},
		},
		{
			name: "merge directory and oci image sources",
			args: func(t *testing.T, r *registry, dir string) []string {
				return []string{"--builder", requireBuilder(t), "--source", dir, "--source", r.Ref("oci", "v1"), "--target", r.Ref("merged", "v1")}
			},
			expect: func(t *testing.T, r *registry, _ string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				blobs, _ := r.nydusManifest(t, "merged", "v1")
				assert.Len(blobs, 2)
			},
		},
		{
			name: "convert nydus image back to oci",
			args: func(t *testing.T, r *registry, _ string) []string {
				r.storeNydusImage(t, "base", "v1")
				return []string{"--builder", requireBuilder(t), "--source", r.Ref("base", "v1"), "--target", r.Ref("oci", "v2"), "--compressor", "oci-tar"}
			},
			expect: func(t *testing.T, r *registry, _ string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				var manifest ocispec.Manifest
				r.LoadJSON(t, "oci", "v2", &manifest)
				assert.Len(manifest.Layers, 2)
				for _, layer := range manifest.Layers {
					assert.Equal(ocispec.MediaTypeImageLayer, layer.MediaType)
				}
			},
		},
		{
			name: "mount parent blobs into another repository",
			args: func(t *testing.T, r *registry, _ string) []string {
				r.storeNydusImage(t, "base", "v1")
				return []string{"--builder", requireBuilder(t), "--bootstrap", r.extractNydusImage(t, "base", "v1"), "--parent-image", r.Ref("base", "v1"), "--target", r.Ref("child", "v1")}
			},
			expect: func(t *testing.T, r *registry, _ string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				blobs, _ := r.nydusManifest(t, "child", "v1")
				assert.Len(blobs, 2)
				for _, blob := range blobs {
					_, ok := r.Load("child", blob.Digest.String())
					assert.True(ok)
				}
			},
		},
		{
			name: "compact parent blobs into one blob",
			args: func(t *testing.T, r *registry, dir string) []string {
				r.storeNydusImage(t, "base", "v1")
				return []string{"--builder", requireBuilder(t), "--bootstrap", r.extractNydusImage(t, "base", "v1"), "--parent-image", r.Ref("base", "v1"), "--target", r.Ref("child", "v1"),
					"--compact-max-layers", "1", "--output-bootstrap", filepath.Join(dir, "image.boot")}
			},
			expect: func(t *testing.T, r *registry, dir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				blobs, _ := r.nydusManifest(t, "child", "v1")
				assert.Len(blobs, 1)
				_, ok := r.Load("child", blobs[0].Digest.String())
				assert.True(ok)
				pushed, err := os.ReadFile(r.extractNydusImage(t, "child", "v1"))
				assert.NoError(err)
				saved, err := os.ReadFile(filepath.Join(dir, "image.boot"))
				assert.NoError(err)
				assert.Equal(pushed, saved)
			},
		},
		{
			name: "upload local blobs",
			args: func(t *testing.T, r *registry, dir string) []string {
				r.storeNydusImage(t, "base", "v1")
				bootstrap := r.extractNydusImage(t, "base", "v1")
				return []string{"--builder", requireBuilder(t), "--bootstrap", bootstrap, "--blob-dir", filepath.Dir(bootstrap), "--target", r.Ref("local", "v1"),
					"--output-bootstrap", filepath.Join(dir, "image.boot")}
			},
			expect: func(t *testing.T, r *registry, dir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				blobs, _ := r.nydusManifest(t, "local", "v1")
				assert.Len(blobs, 2)
				for _, blob := range blobs {
					_, ok := r.Load("local", blob.Digest.String())
					assert.True(ok)
				}
				pushed, err := os.ReadFile(r.extractNydusImage(t, "local", "v1"))
				assert.NoError(err)
				saved, err := os.ReadFile(filepath.Join(dir, "image.boot"))
				assert.NoError(err)
				assert.Equal(pushed, saved)
			},
		},
		{
			name: "target registry rejects nydus image",
			args: func(t *testing.T, r *registry, _ string) []string {
				return []string{"--builder", requireBuilder(t), "--source", r.Ref("oci", "v1"), "--target", registrytest.Forbidding(t) + "/nydus:v1"}
			},
			expect: func(t *testing.T, r *registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "403 Forbidden")
			},
		},
		{
			name: "target registry rejects oci image",
			args: func(t *testing.T, r *registry, _ string) []string {
				r.storeNydusImage(t, "base", "v1")
				return []string{"--builder", requireBuilder(t), "--source", r.Ref("base", "v1"), "--target", registrytest.Forbidding(t) + "/oci:v2", "--compressor", "oci-tar"}
			},
			expect: func(t *testing.T, r *registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "403 Forbidden")
			},
		},
		{
			name: "target registry rejects local blobs",
			args: func(t *testing.T, r *registry, _ string) []string {
				r.storeNydusImage(t, "base", "v1")
				bootstrap := r.extractNydusImage(t, "base", "v1")
				return []string{"--builder", requireBuilder(t), "--bootstrap", bootstrap, "--blob-dir", filepath.Dir(bootstrap), "--target", registrytest.Forbidding(t) + "/local:v1"}
			},
			expect: func(t *testing.T, r *registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "push local artifact blob")
			},
		},
		{
			name: "parent image on another registry",
			args: func(t *testing.T, r *registry, _ string) []string {
				r.storeNydusImage(t, "base", "v1")
				return []string{"--builder", requireBuilder(t), "--bootstrap", r.extractNydusImage(t, "base", "v1"), "--parent-image", r.Ref("base", "v1"), "--target", registrytest.Forbidding(t) + "/child:v1"}
			},
			expect: func(t *testing.T, r *registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "must use the same registry")
			},
		},
		{
			name: "output bootstrap directory missing",
			args: func(t *testing.T, r *registry, dir string) []string {
				r.storeNydusImage(t, "base", "v1")
				bootstrap := r.extractNydusImage(t, "base", "v1")
				return []string{"--builder", requireBuilder(t), "--bootstrap", bootstrap, "--blob-dir", filepath.Dir(bootstrap), "--target", r.Ref("local", "v1"),
					"--output-bootstrap", filepath.Join(dir, "missing", "image.boot")}
			},
			expect: func(t *testing.T, r *registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "save published bootstrap")
				r.nydusManifest(t, "local", "v1")
			},
		},
		{
			name: "convert nydus image back to oci without builder",
			args: func(t *testing.T, r *registry, dir string) []string {
				r.storeNydusImage(t, "base", "v1")
				return []string{"--builder", filepath.Join(dir, "missing"), "--source", r.Ref("base", "v1"), "--target", r.Ref("oci", "v2"), "--compressor", "oci-tar"}
			},
			expect: func(t *testing.T, r *registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "convert to oci")
			},
		},
		{
			name: "convert oci image without builder",
			args: func(t *testing.T, r *registry, dir string) []string {
				return []string{"--builder", filepath.Join(dir, "missing"), "--source", r.Ref("oci", "v1"), "--target", r.Ref("nydus", "v1")}
			},
			expect: func(t *testing.T, r *registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "convert: ")
				_, ok := r.Load("nydus", "v1")
				assert.False(ok)
			},
		},
		{
			name: "merge sources without builder",
			args: func(t *testing.T, r *registry, dir string) []string {
				return []string{"--builder", filepath.Join(dir, "missing"), "--source", dir, "--source", r.Ref("oci", "v1"), "--target", r.Ref("merged", "v1")}
			},
			expect: func(t *testing.T, r *registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "convert multiple sources")
			},
		},
		{
			name: "merge missing image source",
			args: func(t *testing.T, r *registry, dir string) []string {
				return []string{"--source", dir, "--source", r.Ref("missing", "v1"), "--target", r.Ref("merged", "v1")}
			},
			expect: func(t *testing.T, r *registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "pull \""+r.Ref("missing", "v1"))
			},
		},
		{
			name: "parent image missing",
			args: func(t *testing.T, r *registry, dir string) []string {
				return []string{"--bootstrap", filepath.Join(dir, "image.boot"), "--parent-image", r.Ref("missing", "v1"), "--target", r.Ref("child", "v1")}
			},
			expect: func(t *testing.T, r *registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "pull parent metadata")
			},
		},
		{
			name: "parent image is not nydus",
			args: func(t *testing.T, r *registry, dir string) []string {
				return []string{"--bootstrap", filepath.Join(dir, "image.boot"), "--parent-image", r.Ref("oci", "v1"), "--target", r.Ref("child", "v1")}
			},
			expect: func(t *testing.T, r *registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "load parent metadata")
			},
		},
		{
			name: "work dir holds a file named content",
			args: func(t *testing.T, r *registry, dir string) []string {
				assert.NoError(t, os.WriteFile(filepath.Join(dir, "content"), nil, 0o600))
				return []string{"--source", r.Ref("oci", "v1"), "--target", r.Ref("nydus", "v1"), "--work-dir", dir}
			},
			expect: func(t *testing.T, r *registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create dir")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRegistry(t)
			r.storeOCIImage(t, "oci", "v1")
			dir := t.TempDir()
			args := append([]string{"convert", "--source-plain-http", "--target-plain-http"}, tc.args(t, r, dir)...)
			tc.expect(t, r, dir, runNydusify(args...))
		})
	}
}

func TestRunCheck(t *testing.T) {
	tests := []struct {
		name   string
		args   func(t *testing.T, r *registry, dir string) []string
		expect func(t *testing.T, dir string, err error)
	}{
		{
			name: "no image",
			args: func(t *testing.T, r *registry, dir string) []string {
				return []string{"--work-dir", dir}
			},
			expect: func(t *testing.T, _ string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "at least one of --source or --target must be provided")
			},
		},
		{
			name: "check one platform of oci image",
			args: func(t *testing.T, r *registry, dir string) []string {
				return []string{"--target", r.Ref("oci", "v1"), "--platform", "linux/arm64", "--work-dir", dir}
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, err := os.ReadFile(filepath.Join(dir, "target", "config.json"))
				assert.NoError(err)
				assert.Contains(string(data), `"architecture":"arm64"`)
			},
		},
		{
			name: "check nydus image",
			args: func(t *testing.T, r *registry, dir string) []string {
				r.storeNydusImage(t, "base", "v1")
				return []string{"--builder", requireBuilder(t), "--target", r.Ref("base", "v1"), "--work-dir", dir}
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.FileExists(filepath.Join(dir, "target", "bootstrap", "image", "image.boot"))
			},
		},
		{
			name: "default work dir",
			args: func(t *testing.T, r *registry, dir string) []string {
				t.Chdir(dir)
				return []string{"--target", r.Ref("missing", "v1"), "--work-dir", ""}
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "load target")
				assert.DirExists(filepath.Join(dir, "output", "content"))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRegistry(t)
			r.storeOCIImage(t, "oci", "v1")
			dir := t.TempDir()
			args := append([]string{"check", "--source-plain-http", "--target-plain-http"}, tc.args(t, r, dir)...)
			tc.expect(t, dir, runNydusify(args...))
		})
	}
}

func TestRunMount(t *testing.T) {
	tests := []struct {
		name   string
		args   func(r *registry, dir string) []string
		expect func(t *testing.T, dir string, err error)
	}{
		{
			name: "extract one platform of oci image",
			args: func(r *registry, dir string) []string {
				return []string{"--target", r.Ref("oci", "v1"), "--platform", "linux/arm64", "--mountpoint", filepath.Join(dir, "rootfs")}
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, err := os.ReadFile(filepath.Join(dir, "rootfs", "hello"))
				assert.NoError(err)
				assert.Equal("arm64", string(data))
			},
		},
		{
			name: "empty target",
			args: func(r *registry, dir string) []string {
				return []string{"--target", "", "--mountpoint", dir}
			},
			expect: func(t *testing.T, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "target must be provided")
			},
		},
		{
			name: "image missing",
			args: func(r *registry, dir string) []string {
				return []string{"--target", r.Ref("missing", "v1"), "--mountpoint", dir}
			},
			expect: func(t *testing.T, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "load target")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRegistry(t)
			r.storeOCIImage(t, "oci", "v1")
			dir := t.TempDir()
			args := append([]string{"mount", "--target-plain-http"}, tc.args(r, dir)...)
			tc.expect(t, dir, runNydusify(args...))
		})
	}
}

func TestRunOptimize(t *testing.T) {
	tests := []struct {
		name   string
		args   func(r *registry, dir string) []string
		expect func(t *testing.T, err error)
	}{
		{
			name: "empty trace file",
			args: func(r *registry, dir string) []string {
				return []string{"--source", r.Ref("oci", "v1"), "--target", r.Ref("optimized", "v1"), "--trace-file", ""}
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "trace file must be provided")
			},
		},
		{
			name: "source is not nydus",
			args: func(r *registry, dir string) []string {
				return []string{"--source", r.Ref("oci", "v1"), "--target", r.Ref("optimized", "v1"), "--trace-file", filepath.Join(dir, "trace.json"), "--platform", "linux/arm64"}
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "is not a nydus image")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRegistry(t)
			r.storeOCIImage(t, "oci", "v1")
			args := append([]string{"optimize", "--source-plain-http", "--target-plain-http"}, tc.args(r, t.TempDir())...)
			tc.expect(t, runNydusify(args...))
		})
	}
}

func TestScratchWorkDir(t *testing.T) {
	tests := []struct {
		name   string
		args   func(t *testing.T, dir string) []string
		expect func(t *testing.T, dir string, workDir string, cleanup func(), err error)
	}{
		{
			name: "keep explicit work dir",
			args: func(t *testing.T, dir string) []string {
				return []string{"--work-dir", filepath.Join(dir, "work")}
			},
			expect: func(t *testing.T, dir string, workDir string, cleanup func(), err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(filepath.Join(dir, "work"), workDir)
				cleanup()
				assert.DirExists(workDir)
			},
		},
		{
			name: "remove temporary work dir",
			args: func(t *testing.T, dir string) []string {
				t.Setenv("TMPDIR", dir)
				return nil
			},
			expect: func(t *testing.T, dir string, workDir string, cleanup func(), err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(dir, filepath.Dir(workDir))
				assert.DirExists(workDir)
				cleanup()
				assert.NoDirExists(workDir)
			},
		},
		{
			name: "temporary dir unavailable",
			args: func(t *testing.T, dir string) []string {
				t.Setenv("TMPDIR", filepath.Join(dir, "missing"))
				return nil
			},
			expect: func(t *testing.T, _ string, _ string, _ func(), err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create work dir")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			var (
				workDir string
				cleanup func()
				err     error
			)
			app := &cli.App{
				Flags: []cli.Flag{&cli.StringFlag{Name: "work-dir"}},
				Action: func(c *cli.Context) error {
					workDir, cleanup, err = scratchWorkDir(c, "nydusify-test-")
					return nil
				},
			}
			assert.NoError(t, app.Run(append([]string{"nydusify"}, tc.args(t, dir)...)))
			tc.expect(t, dir, workDir, cleanup, err)
		})
	}
}

func TestTotalLayerSize(t *testing.T) {
	tests := []struct {
		name       string
		platformMC platforms.MatchComparer
		root       func(t *testing.T, cs content.Store) ocispec.Descriptor
		expect     func(t *testing.T, size uint64, err error)
	}{
		{
			name:       "sum manifest layers",
			platformMC: platforms.All,
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return writeManifest(t, cs, 3, 4)
			},
			expect: func(t *testing.T, size uint64, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(uint64(7), size)
			},
		},
		{
			name:       "resolve index for platform",
			platformMC: platforms.Only(ocispec.Platform{OS: "linux", Architecture: "arm64"}),
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				amd64 := writeManifest(t, cs, 1)
				amd64.Platform = &ocispec.Platform{OS: "linux", Architecture: "amd64"}
				arm64 := writeManifest(t, cs, 10, 20)
				arm64.Platform = &ocispec.Platform{OS: "linux", Architecture: "arm64"}
				return writeJSON(t, cs, ocispec.MediaTypeImageIndex, ocispec.Index{Manifests: []ocispec.Descriptor{amd64, arm64}})
			},
			expect: func(t *testing.T, size uint64, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(uint64(30), size)
			},
		},
		{
			name:       "no manifest for platform",
			platformMC: platforms.Only(ocispec.Platform{OS: "linux", Architecture: "arm64"}),
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				amd64 := writeManifest(t, cs, 1)
				amd64.Platform = &ocispec.Platform{OS: "linux", Architecture: "amd64"}
				return writeJSON(t, cs, ocispec.MediaTypeImageIndex, ocispec.Index{Manifests: []ocispec.Descriptor{amd64}})
			},
			expect: func(t *testing.T, _ uint64, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "no manifest matches the requested platform")
			},
		},
		{
			name:       "manifest missing from store",
			platformMC: platforms.All,
			root: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString("missing"), Size: 7}
			},
			expect: func(t *testing.T, _ uint64, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read manifest")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs, err := local.NewStore(t.TempDir())
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			size, err := totalLayerSize(context.Background(), cs, tc.root(t, cs), tc.platformMC)
			tc.expect(t, size, err)
		})
	}
}

func writeJSON(t *testing.T, cs content.Store, mediaType string, v any) ocispec.Descriptor {
	desc, err := oci.WriteJSON(context.Background(), cs, v, ocispec.Descriptor{MediaType: mediaType}, nil)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	return *desc
}

func writeManifest(t *testing.T, cs content.Store, sizes ...int64) ocispec.Descriptor {
	manifest := ocispec.Manifest{}
	for _, size := range sizes {
		manifest.Layers = append(manifest.Layers, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayerGzip, Digest: digest.FromString("layer"), Size: size})
	}
	return writeJSON(t, cs, ocispec.MediaTypeImageManifest, manifest)
}

func TestManifestAnnotationValues(t *testing.T) {
	tests := []struct {
		name   string
		flags  []cli.Flag
		args   []string
		expect func(t *testing.T, values []string)
	}{
		{
			name:  "flag not registered",
			flags: nil,
			args:  nil,
			expect: func(t *testing.T, values []string) {
				assert := assert.New(t)
				assert.Nil(values)
			},
		},
		{
			name:  "repeated flag",
			flags: []cli.Flag{&cli.GenericFlag{Name: "manifest-annotation", Value: &manifestAnnotationValue{}}},
			args:  []string{"--manifest-annotation", "a=1", "--manifest-annotation", "b=2"},
			expect: func(t *testing.T, values []string) {
				assert := assert.New(t)
				assert.Equal([]string{"a=1", "b=2"}, values)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var values []string
			app := &cli.App{
				Flags: tc.flags,
				Action: func(c *cli.Context) error {
					values = manifestAnnotationValues(c)
					return nil
				},
			}
			assert.NoError(t, app.Run(append([]string{"nydusify"}, tc.args...)))
			tc.expect(t, values)
		})
	}
}

func TestMainUsage(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		expect func(t *testing.T, output string)
	}{
		{
			name: "list commands",
			args: []string{"nydusify", "--help"},
			expect: func(t *testing.T, output string) {
				assert := assert.New(t)
				for _, command := range []string{"convert", "check", "mount", "optimize"} {
					assert.Contains(output, command)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			args, stdout := os.Args, os.Stdout
			os.Args, os.Stdout = tc.args, writer
			main()
			os.Args, os.Stdout = args, stdout
			assert.NoError(t, writer.Close())
			var output bytes.Buffer
			_, err = io.Copy(&output, reader)
			assert.NoError(t, err)
			tc.expect(t, output.String())
		})
	}
}
