/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package optimizer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/errdefs"
	"github.com/dragonflyoss/nydus/nydusify/internal/nydusfs"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/internal/registrytest"
	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

type mockFile struct {
	name string
	data string
}

var (
	mockOndemandHex = digest.FromString("ondemand blob").Encoded()

	mockDataBlob = []byte("data blob")

	mockImageConfig = ocispec.Image{
		Platform: ocispec.Platform{OS: "linux", Architecture: "amd64"},
		Config:   ocispec.ImageConfig{Env: []string{"PATH=/bin"}},
		History:  []ocispec.History{{CreatedBy: "source"}},
	}

	mockOptimizeArgs = "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > \"$(dirname \"$0\")/args\"\n" +
		"while [ $# -gt 0 ]; do\n" +
		"\tcase \"$1\" in\n" +
		"\t--bootstrap) boot=\"$2\" ;;\n" +
		"\t--blob-dir) dir=\"$2\" ;;\n" +
		"\tesac\n" +
		"\tshift\n" +
		"done\n" +
		"mkdir -p \"$dir\"\n"

	mockOptimizeBlob = "printf 'ondemand blob' > \"$dir/" + mockOndemandHex + "\"\n"

	mockOptimizeBlobMeta = "printf 'ondemand meta' > \"$dir/" + mockOndemandHex + ".blob.meta\"\n"

	mockOptimizeBootstrap = "printf 'optimized bootstrap' > \"$boot\"\n"

	mockOptimizeReport = "echo 'ONDEMAND BLOB DIGEST  " + mockOndemandHex + "'\n"
)

func TestNewOptimizerTraceFileValidation(t *testing.T) {
	base := OptimizeOption{Source: "localhost:5000/src:v3", Target: "localhost:5000/dst:v3"}

	// Trace file missing.
	if _, err := NewOptimizer(base); err == nil ||
		!strings.Contains(err.Error(), "trace file must be provided") {
		t.Fatalf("expected missing-trace-file error, got %v", err)
	}

	// Trace file provided.
	withTraceFile := base
	withTraceFile.TraceFile = "/tmp/trace.json"
	o, err := NewOptimizer(withTraceFile)
	if err != nil {
		t.Fatalf("trace file should be accepted: %v", err)
	}
	if o.opt.TraceFile != "/tmp/trace.json" {
		t.Fatalf("unexpected opt normalization: %+v", o.opt)
	}
}

func TestRunNydusOptimize(t *testing.T) {
	hex := digest.FromString("ondemand").Encoded()
	for _, tc := range []struct {
		name, script, wantError string
		cancel                  bool
	}{
		{"success", "printf 'ONDEMAND BLOB DIGEST  " + hex + "\\n'", "", false},
		{"exit_failure", "exit 7", "run nydus optimize: exit status 7", false},
		{"cancel", "exec sleep 60", "run nydus optimize", true},
		{"missing_digest", "echo completed", "did not report an ondemand blob digest", false},
		{"short_digest", "echo 'ONDEMAND BLOB DIGEST " + hex[:63] + "'", "did not report an ondemand blob digest", false},
		{"long_digest", "echo 'ONDEMAND BLOB DIGEST " + hex + "a'", "did not report an ondemand blob digest", false},
		{"prefixed_row", "echo 'NOT ONDEMAND BLOB DIGEST " + hex + "'", "did not report an ondemand blob digest", false},
		{"suffixed_row", "echo 'ONDEMAND BLOB DIGEST " + hex + " trailing text'", "did not report an ondemand blob digest", false},
		{"invalid_digest", "echo 'ONDEMAND BLOB DIGEST " + strings.Repeat("g", 64) + "'", "did not report an ondemand blob digest", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			builder := filepath.Join(dir, "builder")
			pidPath := filepath.Join(dir, "pid")
			argsPath := filepath.Join(dir, "args")
			script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" > %q\necho $$ > %q\n%s\n", argsPath, pidPath, tc.script)
			if err := os.WriteFile(builder, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type result struct {
				digest string
				err    error
			}
			done := make(chan result, 1)
			go func() {
				got, err := (&Optimizer{opt: OptimizeOption{BuilderPath: builder, TraceFile: "trace.json"}}).
					runNydusOptimize(ctx, "parent.boot", "out.boot", dir, "config.yaml")
				done <- result{got, err}
				close(done)
			}()
			var pid int
			t.Cleanup(func() {
				cancel()
				if pid != 0 {
					_ = unix.Kill(pid, unix.SIGKILL)
				}
				<-done
			})
			deadline := time.Now().Add(5 * time.Second)
			for pid == 0 && time.Now().Before(deadline) {
				data, _ := os.ReadFile(pidPath)
				pid, _ = strconv.Atoi(strings.TrimSpace(string(data)))
				if pid == 0 {
					time.Sleep(10 * time.Millisecond)
				}
			}
			if pid == 0 {
				t.Fatal("child did not start")
			}
			if tc.cancel {
				cancel()
			}
			select {
			case got := <-done:
				if tc.wantError == "" {
					if got.err != nil || got.digest != hex {
						t.Fatalf("result = %+v", got)
					}
				} else if got.err == nil || !strings.Contains(got.err.Error(), tc.wantError) || got.digest != "" {
					t.Fatalf("result = %+v, want error %q and no digest", got, tc.wantError)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("optimizer failed to return or cancel within 5s")
			}
			if err := unix.Kill(pid, 0); err != unix.ESRCH {
				t.Fatalf("child %d not reaped: %v", pid, err)
			}
			args, err := os.ReadFile(argsPath)
			if err != nil {
				t.Fatal(err)
			}
			wantArgs := []string{"optimize", "--parent-bootstrap", "parent.boot", "--bootstrap", "out.boot",
				"--blob-dir", dir, "--config", "config.yaml", "--log-level", nydus.DefaultLogLevel,
				"--trace-file", "trace.json", "--type", nydus.DefaultOptimizeType}
			if !reflect.DeepEqual(strings.Split(strings.TrimSpace(string(args)), "\n"), wantArgs) {
				t.Fatalf("arguments: %s", args)
			}
		})
	}
}

func TestIngestDigestNamedBlobFile(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(fmt.Sprintf("mismatch_%v", mismatch), func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			store, err := local.NewStore(filepath.Join(dir, "content"))
			if err != nil {
				t.Fatal(err)
			}
			data := []byte("ondemand payload")
			expected := digest.FromBytes(data)
			if mismatch {
				expected = digest.FromString("different payload")
			}
			path := filepath.Join(dir, expected.Encoded())
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			desc, err := ingestDigestNamedBlobFile(ctx, store, path)
			if mismatch {
				if err == nil || desc != nil || !strings.Contains(err.Error(), "unexpected commit digest") {
					t.Fatalf("mismatched blob = %v, %v", desc, err)
				}
				for _, dgst := range []digest.Digest{expected, digest.FromBytes(data)} {
					if _, err := store.Info(ctx, dgst); !errdefs.IsNotFound(err) {
						t.Fatalf("mismatched content published as %s: %v", dgst, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := content.ReadBlob(ctx, store, *desc)
			if err != nil || string(got) != string(data) || desc.Digest != expected ||
				desc.Annotations[nydus.LayerAnnotationNydusBlobOptimized] != "true" ||
				desc.Annotations[nydus.LayerAnnotationUncompressed] != expected.String() {
				t.Fatalf("blob = %+v, %q, %v", desc, got, err)
			}
		})
	}
}

func TestWriteOptimizedImage(t *testing.T) {
	for _, tc := range []struct {
		name, missing, wantError string
		fallback, previous       bool
	}{
		{name: "annotations"},
		{name: "config_diffid_fallback", fallback: true},
		{name: "previous_ondemand", fallback: true, previous: true},
		{name: "missing_source_diffid", fallback: true, missing: "source", wantError: "cannot determine diff id"},
		{name: "missing_ondemand_annotation", missing: "ondemand", wantError: "missing uncompressed annotation on appended layer"},
		{name: "missing_bootstrap_annotation", missing: "bootstrap", wantError: "missing uncompressed annotation on appended layer"},
		{name: "bootstrap_not_last", missing: "order", wantError: "split source layers"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			store := provider.ContentStore()
			blob := func(name string) ocispec.Descriptor {
				dgst := digest.FromString(name)
				return ocispec.Descriptor{MediaType: nydus.MediaTypeNydusBlob, Digest: dgst, Annotations: map[string]string{
					nydus.LayerAnnotationNydusBlob: "true", nydus.LayerAnnotationUncompressed: dgst.String(),
				}}
			}
			data, previous, ondemand := blob("data"), blob("previous"), blob("ondemand")
			previous.Annotations[nydus.LayerAnnotationNydusBlobOptimized] = "true"
			ondemand.Annotations[nydus.LayerAnnotationNydusBlobOptimized] = "true"
			bootstrap := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayerGzip, Digest: digest.FromString("bootstrap"), Annotations: map[string]string{
				nydus.LayerAnnotationNydusBootstrap: "true", nydus.LayerAnnotationUncompressed: digest.FromString("bootstrap tar").String(),
			}}
			img := &nydusfs.Image{
				Desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Platform: &ocispec.Platform{OS: "linux", Architecture: "amd64"}},
				Config: ocispec.Image{RootFS: ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{digest.FromString("original diffid")}},
					Config: ocispec.ImageConfig{Env: []string{"KEY=value"}}, History: []ocispec.History{{CreatedBy: "source"}}},
				Manifest: ocispec.Manifest{Config: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig},
					Layers: []ocispec.Descriptor{data}, Annotations: map[string]string{"example.test/source": "retained"}},
			}
			wantLayers := []ocispec.Descriptor{data}
			wantDiffIDs := []digest.Digest{data.Digest}
			if tc.fallback {
				delete(data.Annotations, nydus.LayerAnnotationUncompressed)
				wantDiffIDs[0] = img.Config.RootFS.DiffIDs[0]
			}
			if tc.previous {
				delete(previous.Annotations, nydus.LayerAnnotationUncompressed)
				img.Manifest.Layers = append(img.Manifest.Layers, previous)
				img.Config.RootFS.DiffIDs = append(img.Config.RootFS.DiffIDs, previous.Digest)
				wantLayers = append(wantLayers, previous)
				wantDiffIDs = append(wantDiffIDs, previous.Digest)
			}
			oldBootstrap := bootstrap
			oldBootstrap.Digest = digest.FromString("old bootstrap")
			img.Manifest.Layers = append(img.Manifest.Layers, oldBootstrap)
			if tc.missing == "source" {
				img.Config.RootFS.DiffIDs = nil
			}
			if tc.missing == "ondemand" {
				delete(ondemand.Annotations, nydus.LayerAnnotationUncompressed)
			}
			if tc.missing == "bootstrap" {
				delete(bootstrap.Annotations, nydus.LayerAnnotationUncompressed)
			}
			if tc.missing == "order" {
				img.Manifest.Layers[0], img.Manifest.Layers[1] = img.Manifest.Layers[1], img.Manifest.Layers[0]
			}
			desc, err := (&Optimizer{}).writeOptimizedImage(ctx, store, img, ondemand, bootstrap)
			if tc.wantError != "" {
				if err == nil || desc != nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("result = %v, %v, want %q", desc, err, tc.wantError)
				}
				count := 0
				if err := store.Walk(ctx, func(content.Info) error { count++; return nil }); (err != nil && !os.IsNotExist(err)) || count != 0 {
					t.Fatalf("invalid image published %d blobs: %v", count, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var manifest ocispec.Manifest
			if err := oci.ReadJSON(ctx, store, *desc, &manifest); err != nil {
				t.Fatal(err)
			}
			wantLayers = append(wantLayers, ondemand, bootstrap)
			wantDiffIDs = append(wantDiffIDs, ondemand.Digest, digest.Digest(bootstrap.Annotations[nydus.LayerAnnotationUncompressed]))
			if !reflect.DeepEqual(manifest.Layers, wantLayers) || !reflect.DeepEqual(manifest.Annotations, img.Manifest.Annotations) ||
				!reflect.DeepEqual(desc.Platform, img.Desc.Platform) {
				t.Fatalf("manifest changed retained fields: %+v", manifest)
			}
			var config ocispec.Image
			if err := oci.ReadJSON(ctx, store, manifest.Config, &config); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(config.RootFS.DiffIDs, wantDiffIDs) || !reflect.DeepEqual(config.Config, img.Config.Config) ||
				len(config.History) != 2 || config.History[0] != img.Config.History[0] || config.History[1].CreatedBy != "Nydus Optimizer" {
				t.Fatalf("config = %+v", config)
			}
			labels, err := oci.Labels(ctx, store, desc.Digest)
			if err != nil {
				t.Fatal(err)
			}
			for i, layer := range wantLayers {
				if labels["containerd.io/gc.ref.content.l."+strconv.Itoa(i)] != layer.Digest.String() {
					t.Errorf("layer %d missing GC reference", i)
				}
			}
			if labels["containerd.io/gc.ref.content.config"] != manifest.Config.Digest.String() {
				t.Error("config missing GC reference")
			}
		})
	}
}

func mockTar(t *testing.T, files ...mockFile) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, file := range files {
		if !assert.NoError(t, tw.WriteHeader(&tar.Header{Name: file.name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(file.data))})) {
			t.FailNow()
		}

		if _, err := tw.Write([]byte(file.data)); !assert.NoError(t, err) {
			t.FailNow()
		}
	}

	if !assert.NoError(t, tw.Close()) {
		t.FailNow()
	}

	return buf.Bytes()
}

func mockUntar(t *testing.T, layer []byte) map[string]string {
	gr, err := gzip.NewReader(bytes.NewReader(layer))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	files := map[string]string{}
	tr := tar.NewReader(gr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return files
		}

		if !assert.NoError(t, err) {
			t.FailNow()
		}

		data, err := io.ReadAll(tr)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		if header.Typeflag == tar.TypeReg {
			files[header.Name] = string(data)
		}
	}
}

type registry struct {
	*registrytest.Registry
}

func newRegistry(t *testing.T) *registry {
	return &registry{registrytest.New(t)}
}

func (r *registry) blob(repo string, dgst digest.Digest) string {
	data, _ := r.Load(repo, dgst.String())
	return string(data)
}

func (r *registry) storeImage(t *testing.T, repo string, config ocispec.Image, layers ...ocispec.Descriptor) {
	r.StoreJSON(t, repo, "latest", ocispec.MediaTypeImageManifest, ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    r.StoreJSON(t, repo, "", ocispec.MediaTypeImageConfig, config),
		Layers:    layers,
	})
}

func (r *registry) storeNydusImage(t *testing.T, repo string, diffIDs bool, files ...mockFile) {
	data := r.Store(repo, "", nydus.MediaTypeNydusBlob, mockDataBlob)
	data.Annotations = map[string]string{nydus.LayerAnnotationNydusBlob: "true"}
	bootstrap := r.Store(repo, "", ocispec.MediaTypeImageLayer, mockTar(t, files...))
	bootstrap.Annotations = map[string]string{
		nydus.LayerAnnotationNydusBootstrap: "true",
		nydus.LayerAnnotationUncompressed:   bootstrap.Digest.String(),
	}
	config := mockImageConfig
	if diffIDs {
		data.Annotations[nydus.LayerAnnotationUncompressed] = data.Digest.String()
		config.RootFS.DiffIDs = []digest.Digest{data.Digest, bootstrap.Digest}
	}

	r.storeImage(t, repo, config, data, bootstrap)
}

func TestOptimizer_Optimize(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	reg := newRegistry(t)
	dataMeta := mockFile{name: "image/" + digest.FromBytes(mockDataBlob).Encoded() + ".blob.meta", data: "data meta"}
	reg.storeNydusImage(t, "nydus", true, mockFile{name: nydus.BootstrapFileNameInLayer, data: "bootstrap"}, dataMeta)
	reg.storeNydusImage(t, "headless", true, dataMeta)
	reg.storeNydusImage(t, "nodiff", false, mockFile{name: nydus.BootstrapFileNameInLayer, data: "bootstrap"})
	layer := reg.Store("oci", "", ocispec.MediaTypeImageLayer, mockTar(t, mockFile{name: "etc/hostname", data: "nydus\n"}))
	ociConfig := mockImageConfig
	ociConfig.RootFS.DiffIDs = []digest.Digest{layer.Digest}
	reg.storeImage(t, "oci", ociConfig, layer)

	tests := []struct {
		name   string
		source string
		script string
		forbid bool
		expect func(t *testing.T, dir string, err error)
	}{
		{
			name:   "push optimized image with ondemand blob",
			source: "nydus",
			script: mockOptimizeArgs + mockOptimizeBlob + mockOptimizeBlobMeta + mockOptimizeBootstrap + mockOptimizeReport,
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					t.FailNow()
				}

				var manifest ocispec.Manifest
				reg.LoadJSON(t, "optimized", "latest", &manifest)
				if !assert.Len(manifest.Layers, 3) {
					t.FailNow()
				}

				data, ondemand, bootstrap := manifest.Layers[0], manifest.Layers[1], manifest.Layers[2]
				assert.Equal(string(mockDataBlob), reg.blob("optimized", data.Digest))
				assert.Equal(digest.FromString("ondemand blob"), ondemand.Digest)
				assert.Equal("true", ondemand.Annotations[nydus.LayerAnnotationNydusBlobOptimized])
				assert.Equal("ondemand blob", reg.blob("optimized", ondemand.Digest))
				assert.Equal("true", bootstrap.Annotations[nydus.LayerAnnotationNydusBootstrap])
				assert.Equal(map[string]string{
					nydus.BootstrapFileNameInLayer:            "optimized bootstrap",
					dataMeta.name:                             dataMeta.data,
					"image/" + mockOndemandHex + ".blob.meta": "ondemand meta",
				}, mockUntar(t, []byte(reg.blob("optimized", bootstrap.Digest))))

				var config ocispec.Image
				reg.LoadJSON(t, "optimized", manifest.Config.Digest.String(), &config)
				assert.Equal([]digest.Digest{
					data.Digest,
					ondemand.Digest,
					digest.Digest(bootstrap.Annotations[nydus.LayerAnnotationUncompressed]),
				}, config.RootFS.DiffIDs)
				assert.Equal([]ocispec.History{{CreatedBy: "source"}, {CreatedBy: "Nydus Optimizer", Comment: "Nydus Ondemand Blob Layer"}}, config.History)
				assert.Equal(mockImageConfig.Config, config.Config)

				args, err := os.ReadFile(filepath.Join(dir, "args"))
				assert.NoError(err)
				assert.Contains(string(args), "--trace-file\n"+filepath.Join(dir, "trace.json")+"\n--type\nondemand\n")
				entries, err := os.ReadDir(filepath.Join(dir, "work", "scratch"))
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name:   "reject missing source image",
			source: "absent",
			script: mockOptimizeArgs,
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `load source "`+reg.Ref("absent", "latest")+`"`)
			},
		},
		{
			name:   "reject oci source image",
			source: "oci",
			script: mockOptimizeArgs,
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `source "`+reg.Ref("oci", "latest")+`" is not a nydus image`)
			},
		},
		{
			name:   "reject bootstrap layer without bootstrap file",
			source: "headless",
			script: mockOptimizeArgs,
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `extract bootstrap: bootstrap entry "image/image.boot" not found in layer`)
				assert.NoFileExists(filepath.Join(dir, "args"))
				entries, err := os.ReadDir(filepath.Join(dir, "work", "scratch"))
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name:   "report builder failure",
			source: "nydus",
			script: mockOptimizeArgs + "exit 1\n",
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "run nydus optimize: exit status 1")
				entries, err := os.ReadDir(filepath.Join(dir, "work", "scratch"))
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name:   "reject ondemand blob not matching reported digest",
			source: "nydus",
			script: mockOptimizeArgs + "printf 'tampered' > \"$dir/" + mockOndemandHex + "\"\n" + mockOptimizeBlobMeta + mockOptimizeBootstrap + mockOptimizeReport,
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "commit ondemand blob")
			},
		},
		{
			name:   "reject missing optimized bootstrap",
			source: "nydus",
			script: mockOptimizeArgs + mockOptimizeBlob + mockOptimizeBlobMeta + mockOptimizeReport,
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read optimized bootstrap")
				assert.ErrorIs(err, os.ErrNotExist)
			},
		},
		{
			name:   "reject missing ondemand blob meta",
			source: "nydus",
			script: mockOptimizeArgs + mockOptimizeBlob + mockOptimizeBootstrap + mockOptimizeReport,
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read ondemand blob meta")
				assert.ErrorIs(err, os.ErrNotExist)
			},
		},
		{
			name:   "reject data layer without diff id",
			source: "nodiff",
			script: mockOptimizeArgs + mockOptimizeBlob + mockOptimizeBlobMeta + mockOptimizeBootstrap + mockOptimizeReport,
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "write optimized image: cannot determine diff id for layer "+digest.FromBytes(mockDataBlob).String())
			},
		},
		{
			name:   "report rejected push",
			source: "nydus",
			script: mockOptimizeArgs + mockOptimizeBlob + mockOptimizeBlobMeta + mockOptimizeBootstrap + mockOptimizeReport,
			forbid: true,
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "push \"")
				assert.ErrorContains(err, "403 Forbidden")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			workDir := filepath.Join(dir, "work")
			builder := filepath.Join(dir, "nydus")
			if !assert.NoError(t, os.Mkdir(workDir, 0o755)) || !assert.NoError(t, os.WriteFile(builder, []byte(tc.script), 0o700)) {
				t.FailNow()
			}

			target := reg.Ref("optimized", "latest")
			if tc.forbid {
				target = registrytest.Forbidding(t) + "/optimized:latest"
			}

			optimizer, err := NewOptimizer(OptimizeOption{
				Source:          reg.Ref(tc.source, "latest"),
				Target:          target,
				TraceFile:       filepath.Join(dir, "trace.json"),
				BuilderPath:     builder,
				WorkDir:         workDir,
				SourcePlainHTTP: true,
				TargetPlainHTTP: true,
			})
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			tc.expect(t, dir, optimizer.Optimize(context.Background()))
		})
	}
}
