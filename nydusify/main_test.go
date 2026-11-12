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
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/platforms"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"

	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/internal/registrytest"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

var (
	mockTargetRef = "example.test/image:tag"

	mockSourceRef = "example.test/image:source"

	mockAnnotation = `io.cri-proxy.snapshot.vm-rootfs={"path":"rootfs.img","digest":"xxh3:0123456789abcdef"}`
)

func mockApp() *cli.App {
	return &cli.App{
		Writer:    io.Discard,
		ErrWriter: io.Discard,
		Commands:  []*cli.Command{convertCommand(), checkCommand(), mountCommand(), optimizeCommand()},
	}
}

func builderPath(t *testing.T) string {
	builder := os.Getenv("NYDUS_TEST_BUILDER")
	if builder == "" {
		t.Skip("set NYDUS_TEST_BUILDER to run real builder conversions")
	}

	return builder
}

func mockBlockedFile(t *testing.T) string {
	path := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

// mockStallingRegistry starts a registry that answers 403 for the first blob
// it is asked about and leaves the requests for every other blob unanswered.
// It returns its host:port and a channel that reports, for each request left
// unanswered, whether the client gave it up.
func mockStallingRegistry(t *testing.T) (string, <-chan bool) {
	var (
		mu       sync.Mutex
		rejected string
	)

	abandoned := make(chan bool, 16)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, blob, _ := strings.Cut(r.URL.Path, "/blobs/")

		mu.Lock()
		if rejected == "" {
			rejected = blob
		}
		reject := rejected == blob
		mu.Unlock()

		if !reject {
			select {
			case <-r.Context().Done():
				abandoned <- true
			case <-time.After(5 * time.Second):
				abandoned <- false
			}
		}

		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)

	return strings.TrimPrefix(server.URL, "http://"), abandoned
}

// mockSilentRegistry starts a registry that leaves every request unanswered,
// creating the file at reached once the first one arrives. It returns its
// host:port and a channel that reports, for each request, whether the client
// gave it up.
func mockSilentRegistry(t *testing.T, reached string) (string, <-chan bool) {
	abandoned := make(chan bool, 16)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := os.WriteFile(reached, nil, 0o600); err != nil {
			t.Error(err)
		}

		select {
		case <-r.Context().Done():
			abandoned <- true
		case <-time.After(5 * time.Second):
			abandoned <- false
		}

		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)

	return strings.TrimPrefix(server.URL, "http://"), abandoned
}

// mockBuilder writes a builder that turns each layer into a blob of nothing
// but a valid footer, and runs the shell commands of merge as `nydus merge`.
func mockBuilder(t *testing.T, merge string) string {
	script := `#!/bin/sh
command=$1
blob=
while [ $# -gt 0 ]; do
	if [ "$1" = --blob ]; then blob=$2; fi
	shift
done
case $command in
build)
	cat > /dev/null
	{ printf 0123456789abcdef; printf NDFOOTER; head -c 64 /dev/zero; printf '\020'; head -c 4023 /dev/zero; } > "$blob"
	;;
merge)
	` + merge + `
	;;
esac
`
	path := filepath.Join(t.TempDir(), "nydus")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	return path
}

func mockOCIImage(t *testing.T, reg *registrytest.Registry, repo, tag string, archs ...string) {
	if len(archs) == 0 {
		archs = []string{"amd64", "arm64"}
	}

	index := ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex}
	for _, arch := range archs {
		var layer bytes.Buffer
		tw := tar.NewWriter(&layer)
		if err := tw.WriteHeader(&tar.Header{Name: "hello", Mode: 0o644, Uid: os.Getuid(), Gid: os.Getgid(), Size: int64(len(arch)), ModTime: time.Unix(1700000000, 0)}); err != nil {
			t.Fatal(err)
		}

		if _, err := tw.Write([]byte(arch)); err != nil {
			t.Fatal(err)
		}

		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}

		var compressed bytes.Buffer
		gw := gzip.NewWriter(&compressed)
		if _, err := gw.Write(layer.Bytes()); err != nil {
			t.Fatal(err)
		}

		if err := gw.Close(); err != nil {
			t.Fatal(err)
		}

		layerDesc := reg.Store(repo, "", "", compressed.Bytes())
		layerDesc.MediaType = ocispec.MediaTypeImageLayerGzip
		platform := ocispec.Platform{OS: "linux", Architecture: arch}
		manifestDesc := reg.StoreImage(t, repo, "", ocispec.Image{
			Platform: platform,
			RootFS:   ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{digest.FromBytes(layer.Bytes())}},
		}, layerDesc)
		manifestDesc.Platform = &platform
		index.Manifests = append(index.Manifests, manifestDesc)
	}

	reg.StoreJSON(t, repo, tag, ocispec.MediaTypeImageIndex, index)
}

func mockNydusImage(t *testing.T, reg *registrytest.Registry, repo, tag string) {
	args := []string{"nydusify", "convert", "--builder", builderPath(t), "--target-plain-http", "--target", reg.Ref(repo, tag)}
	for _, name := range []string{"lower", "upper"} {
		dir := filepath.Join(t.TempDir(), name)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(dir, name), bytes.Repeat([]byte(name), 1<<15), 0o644); err != nil {
			t.Fatal(err)
		}

		args = append(args, "--source", dir)
	}

	if err := mockApp().Run(args); err != nil {
		t.Fatal(err)
	}
}

func mockNydusLayers(t *testing.T, reg *registrytest.Registry, repo, reference string) ([]ocispec.Descriptor, ocispec.Descriptor) {
	var manifest ocispec.Manifest
	reg.LoadJSON(t, repo, reference, &manifest)
	blobs, bootstrap, _, err := nydus.SplitLayers(manifest.Layers)
	if err != nil {
		t.Fatal(err)
	}

	if bootstrap == nil {
		t.Fatalf("%s@%s has no nydus bootstrap", repo, reference)
	}

	return blobs, *bootstrap
}

func mockBootstrap(t *testing.T, reg *registrytest.Registry, repo, reference string) string {
	dir := t.TempDir()
	blobs, bootstrap := mockNydusLayers(t, reg, repo, reference)
	for _, blob := range blobs {
		data, ok := reg.Load(repo, blob.Digest.String())
		if !ok {
			t.Fatalf("%s@%s not found", repo, blob.Digest)
		}

		if err := os.WriteFile(filepath.Join(dir, blob.Digest.Encoded()), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	layer, _ := reg.Load(repo, bootstrap.Digest.String())
	gr, err := gzip.NewReader(bytes.NewReader(layer))
	if err != nil {
		t.Fatal(err)
	}

	tr := tar.NewReader(gr)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			t.Fatal(err)
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}

		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(dir, filepath.Base(header.Name)), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	return filepath.Join(dir, "image.boot")
}

func mockJSON(t *testing.T, cs content.Store, mediaType string, v any) ocispec.Descriptor {
	desc, err := oci.WriteJSON(context.Background(), cs, v, ocispec.Descriptor{MediaType: mediaType}, nil)
	if err != nil {
		t.Fatal(err)
	}

	return *desc
}

func mockManifest(t *testing.T, cs content.Store, sizes ...int64) ocispec.Descriptor {
	manifest := ocispec.Manifest{}
	for _, size := range sizes {
		manifest.Layers = append(manifest.Layers, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayerGzip, Digest: digest.FromString("layer"), Size: size})
	}

	return mockJSON(t, cs, ocispec.MediaTypeImageManifest, manifest)
}

func Test_main(t *testing.T) {
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
			if err != nil {
				t.Fatal(err)
			}

			args, stdout := os.Args, os.Stdout
			os.Args, os.Stdout = tc.args, writer
			main()
			os.Args, os.Stdout = args, stdout
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}

			var output bytes.Buffer
			if _, err := io.Copy(&output, reader); err != nil {
				t.Fatal(err)
			}

			tc.expect(t, output.String())
		})
	}
}

func TestManifestAnnotationValues(t *testing.T) {
	tests := []struct {
		name   string
		flags  []cli.Flag
		args   []string
		expect func(t *testing.T, c *cli.Context)
	}{
		{
			name: "flag not registered",
			expect: func(t *testing.T, c *cli.Context) {
				assert := assert.New(t)
				assert.Nil(manifestAnnotationValues(c))
			},
		},
		{
			name:  "repeated flag",
			flags: []cli.Flag{&cli.GenericFlag{Name: "manifest-annotation", Value: &manifestAnnotationValue{}}},
			args:  []string{"--manifest-annotation", "a=1", "--manifest-annotation", "b=2"},
			expect: func(t *testing.T, c *cli.Context) {
				assert := assert.New(t)
				assert.Equal([]string{"a=1", "b=2"}, manifestAnnotationValues(c))
			},
		},
		{
			name:  "keep commas in value",
			flags: []cli.Flag{&cli.GenericFlag{Name: "manifest-annotation", Value: &manifestAnnotationValue{}}},
			args:  []string{"--manifest-annotation", mockAnnotation},
			expect: func(t *testing.T, c *cli.Context) {
				assert := assert.New(t)
				assert.Equal([]string{mockAnnotation}, manifestAnnotationValues(c))
			},
		},
		{
			name: "keep splitting slice flags on commas",
			flags: []cli.Flag{
				&cli.StringSliceFlag{Name: "source"},
				&cli.GenericFlag{Name: "manifest-annotation", Value: &manifestAnnotationValue{}},
			},
			args: []string{"--source", "lower,upper"},
			expect: func(t *testing.T, c *cli.Context) {
				assert := assert.New(t)
				assert.Equal([]string{"lower", "upper"}, c.StringSlice("source"))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var ctx *cli.Context
			app := &cli.App{
				Flags: tc.flags,
				Action: func(c *cli.Context) error {
					ctx = c
					return nil
				},
			}
			if err := app.Run(append([]string{"nydusify"}, tc.args...)); err != nil {
				t.Fatal(err)
			}

			tc.expect(t, ctx)
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
			if err := app.Run(append([]string{"nydusify"}, tc.args(t, dir)...)); err != nil {
				t.Fatal(err)
			}

			tc.expect(t, dir, workDir, cleanup, err)
		})
	}
}

func TestParseManifestAnnotations(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		expect func(t *testing.T, annotations map[string]string, err error)
	}{
		{
			name:   "multiple annotations",
			values: []string{"backend=dragonfly-snapshotter", "digest=xxh3:0123456789abcdef", "empty="},
			expect: func(t *testing.T, annotations map[string]string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(map[string]string{"backend": "dragonfly-snapshotter", "digest": "xxh3:0123456789abcdef", "empty": ""}, annotations)
			},
		},
		{
			name:   "value contains equals",
			values: []string{"key=value=tail"},
			expect: func(t *testing.T, annotations map[string]string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(map[string]string{"key": "value=tail"}, annotations)
			},
		},
		{
			name:   "duplicate key uses last value",
			values: []string{"key=old", "key=new"},
			expect: func(t *testing.T, annotations map[string]string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(map[string]string{"key": "new"}, annotations)
			},
		},
		{
			name:   "missing equals",
			values: []string{"key"},
			expect: func(t *testing.T, annotations map[string]string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "expected key=value")
				assert.Nil(annotations)
			},
		},
		{
			name:   "empty key",
			values: []string{"=value"},
			expect: func(t *testing.T, annotations map[string]string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "key must not be empty")
				assert.Nil(annotations)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			annotations, err := parseManifestAnnotations(tc.values)

			tc.expect(t, annotations, err)
		})
	}
}

func TestRunConvert(t *testing.T) {
	blocked := mockBlockedFile(t)

	var abandoned <-chan bool

	tests := []struct {
		name   string
		args   func(t *testing.T, reg *registrytest.Registry, dir string) []string
		expect func(t *testing.T, reg *registrytest.Registry, dir string, err error)
	}{
		{
			name: "convert oci image to nydus",
			args: func(t *testing.T, reg *registrytest.Registry, _ string) []string {
				return []string{"--builder", builderPath(t), "--source", reg.Ref("oci", "v1"), "--target", reg.Ref("nydus", "v1")}
			},
			expect: func(t *testing.T, reg *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				var index ocispec.Index
				reg.LoadJSON(t, "nydus", "v1", &index)
				assert.Len(index.Manifests, 2)
				for _, desc := range index.Manifests {
					blobs, _ := mockNydusLayers(t, reg, "nydus", desc.Digest.String())
					assert.Len(blobs, 1)
					for _, blob := range blobs {
						_, ok := reg.Load("nydus", blob.Digest.String())
						assert.True(ok)
					}
				}
			},
		},
		{
			name: "convert one platform of oci image",
			args: func(t *testing.T, reg *registrytest.Registry, _ string) []string {
				return []string{"--builder", builderPath(t), "--source", reg.Ref("oci", "v1"), "--target", reg.Ref("nydus", "v1"), "--platform", "linux/arm64"}
			},
			expect: func(t *testing.T, reg *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				var manifest ocispec.Manifest
				reg.LoadJSON(t, "nydus", "v1", &manifest)
				var config ocispec.Image
				reg.LoadJSON(t, "nydus", manifest.Config.Digest.String(), &config)
				assert.Equal("arm64", config.Architecture)
			},
		},
		{
			name: "merge directory and oci image sources",
			args: func(t *testing.T, reg *registrytest.Registry, dir string) []string {
				return []string{"--builder", builderPath(t), "--source", dir, "--source", reg.Ref("oci", "v1"), "--target", reg.Ref("merged", "v1")}
			},
			expect: func(t *testing.T, reg *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				blobs, _ := mockNydusLayers(t, reg, "merged", "v1")
				assert.Len(blobs, 2)
			},
		},
		{
			name: "convert nydus image back to oci",
			args: func(t *testing.T, reg *registrytest.Registry, _ string) []string {
				mockNydusImage(t, reg, "base", "v1")
				return []string{"--builder", builderPath(t), "--source", reg.Ref("base", "v1"), "--target", reg.Ref("oci", "v2"), "--compressor", "oci-tar"}
			},
			expect: func(t *testing.T, reg *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				var manifest ocispec.Manifest
				reg.LoadJSON(t, "oci", "v2", &manifest)
				assert.Len(manifest.Layers, 2)
				for _, layer := range manifest.Layers {
					assert.Equal(ocispec.MediaTypeImageLayer, layer.MediaType)
				}
			},
		},
		{
			name: "mount parent blobs into another repository",
			args: func(t *testing.T, reg *registrytest.Registry, _ string) []string {
				mockNydusImage(t, reg, "base", "v1")
				return []string{"--builder", builderPath(t), "--bootstrap", mockBootstrap(t, reg, "base", "v1"), "--parent-image", reg.Ref("base", "v1"), "--target", reg.Ref("child", "v1")}
			},
			expect: func(t *testing.T, reg *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				blobs, _ := mockNydusLayers(t, reg, "child", "v1")
				assert.Len(blobs, 2)
				for _, blob := range blobs {
					_, ok := reg.Load("child", blob.Digest.String())
					assert.True(ok)
				}
			},
		},
		{
			name: "compact parent blobs into one blob",
			args: func(t *testing.T, reg *registrytest.Registry, dir string) []string {
				mockNydusImage(t, reg, "base", "v1")
				return []string{"--builder", builderPath(t), "--bootstrap", mockBootstrap(t, reg, "base", "v1"), "--parent-image", reg.Ref("base", "v1"), "--target", reg.Ref("child", "v1"),
					"--compact-max-layers", "1", "--output-bootstrap", filepath.Join(dir, "image.boot")}
			},
			expect: func(t *testing.T, reg *registrytest.Registry, dir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				blobs, _ := mockNydusLayers(t, reg, "child", "v1")
				assert.Len(blobs, 1)
				for _, blob := range blobs {
					_, ok := reg.Load("child", blob.Digest.String())
					assert.True(ok)
				}

				pushed, err := os.ReadFile(mockBootstrap(t, reg, "child", "v1"))
				assert.NoError(err)
				saved, err := os.ReadFile(filepath.Join(dir, "image.boot"))
				assert.NoError(err)
				assert.Equal(pushed, saved)
			},
		},
		{
			name: "upload local blobs",
			args: func(t *testing.T, reg *registrytest.Registry, dir string) []string {
				mockNydusImage(t, reg, "base", "v1")
				bootstrap := mockBootstrap(t, reg, "base", "v1")
				return []string{"--builder", builderPath(t), "--bootstrap", bootstrap, "--blob-dir", filepath.Dir(bootstrap), "--target", reg.Ref("local", "v1"),
					"--output-bootstrap", filepath.Join(dir, "image.boot")}
			},
			expect: func(t *testing.T, reg *registrytest.Registry, dir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				blobs, _ := mockNydusLayers(t, reg, "local", "v1")
				assert.Len(blobs, 2)
				for _, blob := range blobs {
					_, ok := reg.Load("local", blob.Digest.String())
					assert.True(ok)
				}

				pushed, err := os.ReadFile(mockBootstrap(t, reg, "local", "v1"))
				assert.NoError(err)
				saved, err := os.ReadFile(filepath.Join(dir, "image.boot"))
				assert.NoError(err)
				assert.Equal(pushed, saved)
			},
		},
		{
			name: "target registry rejects nydus image",
			args: func(t *testing.T, reg *registrytest.Registry, _ string) []string {
				return []string{"--builder", builderPath(t), "--source", reg.Ref("oci", "v1"), "--target", registrytest.Forbidding(t) + "/nydus:v1"}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "403 Forbidden")
			},
		},
		{
			name: "target registry rejects oci image",
			args: func(t *testing.T, reg *registrytest.Registry, _ string) []string {
				mockNydusImage(t, reg, "base", "v1")
				return []string{"--builder", builderPath(t), "--source", reg.Ref("base", "v1"), "--target", registrytest.Forbidding(t) + "/oci:v2", "--compressor", "oci-tar"}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "403 Forbidden")
			},
		},
		{
			name: "target registry rejects local blobs",
			args: func(t *testing.T, reg *registrytest.Registry, _ string) []string {
				mockNydusImage(t, reg, "base", "v1")
				bootstrap := mockBootstrap(t, reg, "base", "v1")
				return []string{"--builder", builderPath(t), "--bootstrap", bootstrap, "--blob-dir", filepath.Dir(bootstrap), "--target", registrytest.Forbidding(t) + "/local:v1"}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "push local artifact blob")
			},
		},
		{
			name: "one rejected local blob cancels the upload of the others",
			args: func(t *testing.T, reg *registrytest.Registry, _ string) []string {
				mockNydusImage(t, reg, "base", "v1")
				bootstrap := mockBootstrap(t, reg, "base", "v1")

				var host string
				host, abandoned = mockStallingRegistry(t)

				return []string{"--builder", builderPath(t), "--bootstrap", bootstrap, "--blob-dir", filepath.Dir(bootstrap), "--target", host + "/local:v1"}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "push local artifact blob")
				assert.ErrorContains(err, "403 Forbidden")

				// An upload that reached the registry was given up, not left
				// to run out; one cancelled before its request leaves no report.
				select {
				case gaveUp := <-abandoned:
					assert.True(gaveUp)
				case <-time.After(time.Second):
				}
			},
		},
		{
			name: "failed conversion ends the blob uploads",
			args: func(t *testing.T, reg *registrytest.Registry, dir string) []string {
				reached := filepath.Join(dir, "reached")

				var host string
				host, abandoned = mockSilentRegistry(t, reached)

				return []string{"--builder", mockBuilder(t, "while [ ! -e '"+reached+"' ]; do sleep 0.05; done; exit 1"), "--source", reg.Ref("oci", "v1"), "--target", host + "/nydus:v1"}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "convert: ")
				assert.ErrorContains(err, "nydus merge")

				// The upload that reached the registry was given up, not left
				// to run out.
				select {
				case gaveUp := <-abandoned:
					assert.True(gaveUp)
				case <-time.After(10 * time.Second):
					assert.Fail("no blob upload reached the registry")
				}
			},
		},
		{
			name: "parent image on another registry",
			args: func(t *testing.T, reg *registrytest.Registry, _ string) []string {
				mockNydusImage(t, reg, "base", "v1")
				return []string{"--builder", builderPath(t), "--bootstrap", mockBootstrap(t, reg, "base", "v1"), "--parent-image", reg.Ref("base", "v1"), "--target", registrytest.Forbidding(t) + "/child:v1"}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "must use the same registry")
			},
		},
		{
			name: "output bootstrap directory missing",
			args: func(t *testing.T, reg *registrytest.Registry, dir string) []string {
				mockNydusImage(t, reg, "base", "v1")
				bootstrap := mockBootstrap(t, reg, "base", "v1")
				return []string{"--builder", builderPath(t), "--bootstrap", bootstrap, "--blob-dir", filepath.Dir(bootstrap), "--target", reg.Ref("local", "v1"),
					"--output-bootstrap", filepath.Join(dir, "missing", "image.boot")}
			},
			expect: func(t *testing.T, reg *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "save published bootstrap")
				mockNydusLayers(t, reg, "local", "v1")
			},
		},
		{
			name: "convert nydus image back to oci without builder",
			args: func(t *testing.T, reg *registrytest.Registry, dir string) []string {
				mockNydusImage(t, reg, "base", "v1")
				return []string{"--builder", filepath.Join(dir, "missing"), "--source", reg.Ref("base", "v1"), "--target", reg.Ref("oci", "v2"), "--compressor", "oci-tar"}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "convert to oci")
			},
		},
		{
			name: "convert oci image without builder",
			args: func(t *testing.T, reg *registrytest.Registry, dir string) []string {
				return []string{"--builder", filepath.Join(dir, "missing"), "--source", reg.Ref("oci", "v1"), "--target", reg.Ref("nydus", "v1")}
			},
			expect: func(t *testing.T, reg *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "convert: ")

				_, ok := reg.Load("nydus", "v1")
				assert.False(ok)
			},
		},
		{
			name: "merge sources without builder",
			args: func(t *testing.T, reg *registrytest.Registry, dir string) []string {
				return []string{"--builder", filepath.Join(dir, "missing"), "--source", dir, "--source", reg.Ref("oci", "v1"), "--target", reg.Ref("merged", "v1")}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "convert multiple sources")
			},
		},
		{
			name: "merge missing image source",
			args: func(t *testing.T, reg *registrytest.Registry, dir string) []string {
				return []string{"--source", dir, "--source", reg.Ref("missing", "v1"), "--target", reg.Ref("merged", "v1")}
			},
			expect: func(t *testing.T, reg *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "pull \""+reg.Ref("missing", "v1"))
			},
		},
		{
			name: "parent image missing",
			args: func(t *testing.T, reg *registrytest.Registry, dir string) []string {
				return []string{"--bootstrap", filepath.Join(dir, "image.boot"), "--parent-image", reg.Ref("missing", "v1"), "--target", reg.Ref("child", "v1")}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "pull parent metadata")
			},
		},
		{
			name: "parent image is not nydus",
			args: func(t *testing.T, reg *registrytest.Registry, dir string) []string {
				return []string{"--bootstrap", filepath.Join(dir, "image.boot"), "--parent-image", reg.Ref("oci", "v1"), "--target", reg.Ref("child", "v1")}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "load parent metadata")
			},
		},
		{
			name: "work dir holds a file named content",
			args: func(t *testing.T, reg *registrytest.Registry, dir string) []string {
				if err := os.WriteFile(filepath.Join(dir, "content"), nil, 0o600); err != nil {
					t.Fatal(err)
				}

				return []string{"--source", reg.Ref("oci", "v1"), "--target", reg.Ref("nydus", "v1"), "--work-dir", dir}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create dir")
			},
		},
		{
			name: "invalid manifest annotation",
			args: func(t *testing.T, _ *registrytest.Registry, dir string) []string {
				return []string{"--target", mockTargetRef, "--source", dir, "--manifest-annotation", "bad"}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "expected key=value")
			},
		},
		{
			name: "missing source",
			args: func(t *testing.T, _ *registrytest.Registry, _ string) []string {
				return []string{"--target", mockTargetRef}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "source")
			},
		},
		{
			name: "prune without bootstrap",
			args: func(t *testing.T, _ *registrytest.Registry, dir string) []string {
				return []string{"--target", mockTargetRef, "--source", dir, "--prune"}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "--prune requires --bootstrap")
			},
		},
		{
			name: "compaction without bootstrap",
			args: func(t *testing.T, _ *registrytest.Registry, dir string) []string {
				return []string{"--target", mockTargetRef, "--source", dir, "--compact-max-layers", "1"}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "--compact-max-layers requires --bootstrap")
			},
		},
		{
			name: "output bootstrap without bootstrap",
			args: func(t *testing.T, _ *registrytest.Registry, dir string) []string {
				return []string{"--target", mockTargetRef, "--source", dir, "--output-bootstrap", filepath.Join(dir, "missing")}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "--output-bootstrap requires --bootstrap")
			},
		},
		{
			name: "unsupported compressor",
			args: func(t *testing.T, _ *registrytest.Registry, dir string) []string {
				return []string{"--target", mockTargetRef, "--source", dir, "--compressor", "invalid"}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unsupported --compressor")
			},
		},
		{
			name: "manifest annotation with oci compressor",
			args: func(t *testing.T, _ *registrytest.Registry, dir string) []string {
				return []string{"--target", mockTargetRef, "--source", dir, "--compressor", "oci-tar", "--manifest-annotation", "key=value"}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "only supported")
			},
		},
		{
			name: "chunk size overflows uint32",
			args: func(t *testing.T, _ *registrytest.Registry, dir string) []string {
				return []string{"--target", mockTargetRef, "--source", dir, "--chunk-size", "4294967296"}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "fit uint32")
			},
		},
		{
			name: "invalid platform",
			args: func(t *testing.T, _ *registrytest.Registry, dir string) []string {
				return []string{"--target", mockTargetRef, "--source", dir, "--platform", "a/b/c/d"}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid platform")
			},
		},
		{
			name: "work dir is a file",
			args: func(t *testing.T, _ *registrytest.Registry, dir string) []string {
				return []string{"--target", mockTargetRef, "--source", dir, "--work-dir", blocked}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create work dir")
			},
		},
		{
			name: "convert artifacts back to oci",
			args: func(t *testing.T, _ *registrytest.Registry, _ string) []string {
				return []string{"--target", mockTargetRef, "--bootstrap", blocked, "--blob", blocked, "--compressor", "oci-tar"}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "artifacts back to OCI")
			},
		},
		{
			name: "convert directory back to oci",
			args: func(t *testing.T, _ *registrytest.Registry, dir string) []string {
				return []string{"--target", mockTargetRef, "--source", dir, "--compressor", "oci-tar"}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "exactly one nydus image")
			},
		},
		{
			name: "invalid nydus source reference",
			args: func(t *testing.T, _ *registrytest.Registry, _ string) []string {
				return []string{"--target", mockTargetRef, "--source", "://bad", "--compressor", "oci-tar"}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "pull")
			},
		},
		{
			name: "invalid parent image reference",
			args: func(t *testing.T, _ *registrytest.Registry, _ string) []string {
				return []string{"--target", mockTargetRef, "--bootstrap", blocked, "--parent-image", "://bad"}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "reference")
			},
		},
		{
			name: "inspect bootstrap without builder",
			args: func(t *testing.T, _ *registrytest.Registry, dir string) []string {
				return []string{"--target", mockTargetRef, "--bootstrap", blocked, "--blob", blocked, "--builder", filepath.Join(dir, "missing")}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "inspect bootstrap")
			},
		},
		{
			name: "convert directory without builder",
			args: func(t *testing.T, _ *registrytest.Registry, dir string) []string {
				return []string{"--target", mockTargetRef, "--source", dir, "--builder", filepath.Join(dir, "missing")}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "convert")
			},
		},
		{
			name: "invalid source reference",
			args: func(t *testing.T, _ *registrytest.Registry, _ string) []string {
				return []string{"--target", mockTargetRef, "--source", "://bad"}
			},
			expect: func(t *testing.T, _ *registrytest.Registry, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "pull")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := registrytest.New(t)
			mockOCIImage(t, reg, "oci", "v1")
			dir := t.TempDir()
			err := mockApp().Run(append([]string{"nydusify", "convert", "--source-plain-http", "--target-plain-http"}, tc.args(t, reg, dir)...))

			tc.expect(t, reg, dir, err)
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
				return mockManifest(t, cs, 3, 4)
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
				amd64 := mockManifest(t, cs, 1)
				amd64.Platform = &ocispec.Platform{OS: "linux", Architecture: "amd64"}
				arm64 := mockManifest(t, cs, 10, 20)
				arm64.Platform = &ocispec.Platform{OS: "linux", Architecture: "arm64"}
				return mockJSON(t, cs, ocispec.MediaTypeImageIndex, ocispec.Index{Manifests: []ocispec.Descriptor{amd64, arm64}})
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
				amd64 := mockManifest(t, cs, 1)
				amd64.Platform = &ocispec.Platform{OS: "linux", Architecture: "amd64"}
				return mockJSON(t, cs, ocispec.MediaTypeImageIndex, ocispec.Index{Manifests: []ocispec.Descriptor{amd64}})
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
			if err != nil {
				t.Fatal(err)
			}

			size, err := totalLayerSize(context.Background(), cs, tc.root(t, cs), tc.platformMC)

			tc.expect(t, size, err)
		})
	}
}

func TestRunCheck(t *testing.T) {
	blocked := mockBlockedFile(t)

	var x86 *registrytest.Registry

	tests := []struct {
		name   string
		args   func(t *testing.T, reg *registrytest.Registry, dir string) []string
		expect func(t *testing.T, dir string, err error)
	}{
		{
			name: "no image",
			args: func(t *testing.T, _ *registrytest.Registry, dir string) []string {
				return []string{"--work-dir", dir}
			},
			expect: func(t *testing.T, _ string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "at least one of --source or --target must be provided")
			},
		},
		{
			name: "pull only the requested platform",
			args: func(t *testing.T, reg *registrytest.Registry, dir string) []string {
				x86 = reg
				mockOCIImage(t, reg, "x86", "v1", "386", "amd64")

				return []string{"--target", reg.Ref("x86", "v1"), "--platform", "linux/amd64", "--work-dir", dir}
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				data, err := os.ReadFile(filepath.Join(dir, "target", "config.json"))
				assert.NoError(err)
				assert.Contains(string(data), `"architecture":"amd64"`)

				var index ocispec.Index
				x86.LoadJSON(t, "x86", "v1", &index)
				assert.Equal("386", index.Manifests[0].Platform.Architecture)

				for _, req := range x86.Requests() {
					assert.NotContains(req.URL, index.Manifests[0].Digest.String())
				}
			},
		},
		{
			name: "check one platform of oci image",
			args: func(t *testing.T, reg *registrytest.Registry, dir string) []string {
				return []string{"--target", reg.Ref("oci", "v1"), "--platform", "linux/arm64", "--work-dir", dir}
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
			args: func(t *testing.T, reg *registrytest.Registry, dir string) []string {
				mockNydusImage(t, reg, "base", "v1")
				return []string{"--builder", builderPath(t), "--target", reg.Ref("base", "v1"), "--work-dir", dir}
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.FileExists(filepath.Join(dir, "target", "bootstrap", "image", "image.boot"))
			},
		},
		{
			name: "default work dir",
			args: func(t *testing.T, reg *registrytest.Registry, dir string) []string {
				t.Chdir(dir)
				return []string{"--target", reg.Ref("missing", "v1"), "--work-dir", ""}
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "load target")
				assert.DirExists(filepath.Join(dir, "output", "content"))
			},
		},
		{
			name: "invalid platform",
			args: func(t *testing.T, _ *registrytest.Registry, dir string) []string {
				return []string{"--target", mockTargetRef, "--work-dir", dir, "--platform", "a/b/c/d"}
			},
			expect: func(t *testing.T, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid platform")
			},
		},
		{
			name: "work dir is a file",
			args: func(t *testing.T, _ *registrytest.Registry, _ string) []string {
				return []string{"--target", mockTargetRef, "--work-dir", blocked}
			},
			expect: func(t *testing.T, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create work dir")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := registrytest.New(t)
			mockOCIImage(t, reg, "oci", "v1")
			dir := t.TempDir()
			err := mockApp().Run(append([]string{"nydusify", "check", "--source-plain-http", "--target-plain-http"}, tc.args(t, reg, dir)...))

			tc.expect(t, dir, err)
		})
	}
}

func TestRunMount(t *testing.T) {
	blocked := mockBlockedFile(t)

	tests := []struct {
		name   string
		args   func(reg *registrytest.Registry, dir string) []string
		expect func(t *testing.T, dir string, err error)
	}{
		{
			name: "extract one platform of oci image",
			args: func(reg *registrytest.Registry, dir string) []string {
				return []string{"--target", reg.Ref("oci", "v1"), "--platform", "linux/arm64", "--mountpoint", filepath.Join(dir, "rootfs")}
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
			args: func(_ *registrytest.Registry, dir string) []string {
				return []string{"--target", "", "--mountpoint", dir}
			},
			expect: func(t *testing.T, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "target must be provided")
			},
		},
		{
			name: "image missing",
			args: func(reg *registrytest.Registry, dir string) []string {
				return []string{"--target", reg.Ref("missing", "v1"), "--mountpoint", dir}
			},
			expect: func(t *testing.T, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "load target")
			},
		},
		{
			name: "invalid platform",
			args: func(_ *registrytest.Registry, dir string) []string {
				return []string{"--target", mockTargetRef, "--mountpoint", dir, "--platform", "a/b/c/d"}
			},
			expect: func(t *testing.T, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid platform")
			},
		},
		{
			name: "mountpoint is a file",
			args: func(_ *registrytest.Registry, _ string) []string {
				return []string{"--target", mockTargetRef, "--mountpoint", blocked}
			},
			expect: func(t *testing.T, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create mountpoint")
			},
		},
		{
			name: "work dir is a file",
			args: func(_ *registrytest.Registry, dir string) []string {
				return []string{"--target", mockTargetRef, "--mountpoint", dir, "--work-dir", blocked}
			},
			expect: func(t *testing.T, _ string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create work dir")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := registrytest.New(t)
			mockOCIImage(t, reg, "oci", "v1")
			dir := t.TempDir()
			err := mockApp().Run(append([]string{"nydusify", "mount", "--target-plain-http"}, tc.args(reg, dir)...))

			tc.expect(t, dir, err)
		})
	}
}

func TestRunOptimize(t *testing.T) {
	blocked := mockBlockedFile(t)

	tests := []struct {
		name   string
		args   func(reg *registrytest.Registry, dir string) []string
		expect func(t *testing.T, err error)
	}{
		{
			name: "empty trace file",
			args: func(reg *registrytest.Registry, _ string) []string {
				return []string{"--source", reg.Ref("oci", "v1"), "--target", reg.Ref("optimized", "v1"), "--trace-file", ""}
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "trace file must be provided")
			},
		},
		{
			name: "source is not nydus",
			args: func(reg *registrytest.Registry, dir string) []string {
				return []string{"--source", reg.Ref("oci", "v1"), "--target", reg.Ref("optimized", "v1"), "--trace-file", filepath.Join(dir, "trace.json"), "--platform", "linux/arm64"}
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "is not a nydus image")
			},
		},
		{
			name: "invalid platform",
			args: func(_ *registrytest.Registry, _ string) []string {
				return []string{"--source", mockSourceRef, "--target", mockTargetRef, "--trace-file", blocked, "--platform", "a/b/c/d"}
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid platform")
			},
		},
		{
			name: "work dir is a file",
			args: func(_ *registrytest.Registry, _ string) []string {
				return []string{"--source", mockSourceRef, "--target", mockTargetRef, "--trace-file", blocked, "--work-dir", blocked}
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create work dir")
			},
		},
		{
			name: "invalid source reference",
			args: func(_ *registrytest.Registry, _ string) []string {
				return []string{"--source", "://bad", "--target", mockTargetRef, "--trace-file", blocked}
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "reference")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := registrytest.New(t)
			mockOCIImage(t, reg, "oci", "v1")
			err := mockApp().Run(append([]string{"nydusify", "optimize", "--source-plain-http", "--target-plain-http"}, tc.args(reg, t.TempDir())...))

			tc.expect(t, err)
		})
	}
}
