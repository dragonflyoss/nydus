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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	"github.com/dragonflyoss/nydus/nydusify/internal/nydusfs"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/internal/registrytest"
	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

type mockFile struct {
	name string
	data string
}

var (
	mockPlatform = ocispec.Platform{OS: "linux", Architecture: "amd64"}

	mockImageConfig = ocispec.Image{
		Platform: mockPlatform,
		Config:   ocispec.ImageConfig{Env: []string{"PATH=/bin"}},
		History:  []ocispec.History{{CreatedBy: "source"}},
	}

	mockOptimizedHistory = []ocispec.History{
		{CreatedBy: "source"},
		{CreatedBy: "Nydus Optimizer", Comment: "Nydus Ondemand Blob Layer"},
	}

	mockManifestAnnotations = map[string]string{"example.test/source": "retained"}

	mockDiffID = digest.FromString("original diffid")

	mockDataBlob = []byte("data blob")

	mockDataLayer = ocispec.Descriptor{
		MediaType: nydus.MediaTypeNydusBlob,
		Digest:    digest.FromBytes(mockDataBlob),
		Size:      int64(len(mockDataBlob)),
		Annotations: map[string]string{
			nydus.LayerAnnotationNydusBlob:    "true",
			nydus.LayerAnnotationUncompressed: digest.FromBytes(mockDataBlob).String(),
		},
	}

	mockDataLayerWithoutDiffID = ocispec.Descriptor{
		MediaType:   nydus.MediaTypeNydusBlob,
		Digest:      digest.FromBytes(mockDataBlob),
		Size:        int64(len(mockDataBlob)),
		Annotations: map[string]string{nydus.LayerAnnotationNydusBlob: "true"},
	}

	mockPreviousOndemandLayer = ocispec.Descriptor{
		MediaType: nydus.MediaTypeNydusBlob,
		Digest:    digest.FromString("previous ondemand blob"),
		Annotations: map[string]string{
			nydus.LayerAnnotationNydusBlob:          "true",
			nydus.LayerAnnotationNydusBlobOptimized: "true",
		},
	}

	mockOndemandBlob = []byte("ondemand blob")

	mockOndemandLayer = ocispec.Descriptor{
		MediaType: nydus.MediaTypeNydusBlob,
		Digest:    digest.FromBytes(mockOndemandBlob),
		Size:      int64(len(mockOndemandBlob)),
		Annotations: map[string]string{
			nydus.LayerAnnotationNydusBlob:          "true",
			nydus.LayerAnnotationNydusBlobOptimized: "true",
			nydus.LayerAnnotationUncompressed:       digest.FromBytes(mockOndemandBlob).String(),
		},
	}

	mockOndemandHex = mockOndemandLayer.Digest.Encoded()

	mockBootstrapLayer = ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Digest:    digest.FromString("bootstrap"),
		Annotations: map[string]string{
			nydus.LayerAnnotationNydusBootstrap: "true",
			nydus.LayerAnnotationUncompressed:   digest.FromString("bootstrap tar").String(),
		},
	}

	mockOldBootstrapLayer = ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Digest:    digest.FromString("old bootstrap"),
		Annotations: map[string]string{
			nydus.LayerAnnotationNydusBootstrap: "true",
			nydus.LayerAnnotationUncompressed:   digest.FromString("old bootstrap tar").String(),
		},
	}

	mockBootstrapFile = mockFile{name: nydus.BootstrapFileNameInLayer, data: "bootstrap"}

	mockDataBlobMeta = mockFile{name: "image/" + mockDataLayer.Digest.Encoded() + ".blob.meta", data: "data meta"}

	mockOptimizeCommand = []string{
		"optimize",
		"--parent-bootstrap", "parent.boot",
		"--bootstrap", "out.boot",
		"--blob-dir", "blobs",
		"--config", "config.yaml",
		"--log-level", nydus.DefaultLogLevel,
		"--trace-file", "trace.json",
		"--type", nydus.DefaultOptimizeType,
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

func mockTar(t *testing.T, files ...mockFile) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, file := range files {
		if err := tw.WriteHeader(&tar.Header{Name: file.name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(file.data))}); err != nil {
			t.Fatal(err)
		}

		if _, err := tw.Write([]byte(file.data)); err != nil {
			t.Fatal(err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

func mockUntar(t *testing.T, layer []byte) map[string]string {
	gr, err := gzip.NewReader(bytes.NewReader(layer))
	if err != nil {
		t.Fatal(err)
	}

	files := map[string]string{}
	tr := tar.NewReader(gr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return files
		}

		if err != nil {
			t.Fatal(err)
		}

		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}

		if header.Typeflag == tar.TypeReg {
			files[header.Name] = string(data)
		}
	}
}

func mockNydusImage(t *testing.T, reg *registrytest.Registry, repo string, diffIDs bool, files ...mockFile) {
	reg.Store(repo, "", nydus.MediaTypeNydusBlob, mockDataBlob)
	bootstrap := reg.Store(repo, "", ocispec.MediaTypeImageLayer, mockTar(t, files...))
	bootstrap.Annotations = map[string]string{
		nydus.LayerAnnotationNydusBootstrap: "true",
		nydus.LayerAnnotationUncompressed:   bootstrap.Digest.String(),
	}

	data, config := mockDataLayerWithoutDiffID, mockImageConfig
	if diffIDs {
		data = mockDataLayer
		config.RootFS.DiffIDs = []digest.Digest{data.Digest, bootstrap.Digest}
	}

	reg.StoreImage(t, repo, "latest", config, data, bootstrap)
}

func TestNewOptimizer(t *testing.T) {
	tests := []struct {
		name   string
		opt    OptimizeOption
		expect func(t *testing.T, o *Optimizer, err error)
	}{
		{
			name: "reject empty source",
			opt:  OptimizeOption{},
			expect: func(t *testing.T, o *Optimizer, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "source must be provided")
				assert.Nil(o)
			},
		},
		{
			name: "reject empty target",
			opt:  OptimizeOption{Source: "localhost:5000/src:v3"},
			expect: func(t *testing.T, o *Optimizer, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "target must be provided")
				assert.Nil(o)
			},
		},
		{
			name: "reject missing trace file",
			opt:  OptimizeOption{Source: "localhost:5000/src:v3", Target: "localhost:5000/dst:v3"},
			expect: func(t *testing.T, o *Optimizer, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "trace file must be provided")
			},
		},
		{
			name: "accept trace file",
			opt:  OptimizeOption{Source: "localhost:5000/src:v3", Target: "localhost:5000/dst:v3", TraceFile: "/tmp/trace.json"},
			expect: func(t *testing.T, o *Optimizer, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&Optimizer{opt: OptimizeOption{
					Source:     "localhost:5000/src:v3",
					Target:     "localhost:5000/dst:v3",
					TraceFile:  "/tmp/trace.json",
					LogLevel:   "info",
					PlatformMC: platforms.Default(),
				}}, o)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o, err := NewOptimizer(tc.opt)

			tc.expect(t, o, err)
		})
	}
}

func TestOptimizer_Optimize(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	reg := registrytest.New(t)
	mockNydusImage(t, reg, "nydus", true, mockBootstrapFile, mockDataBlobMeta)
	mockNydusImage(t, reg, "headless", true, mockDataBlobMeta)
	mockNydusImage(t, reg, "nodiff", false, mockBootstrapFile)
	layer := reg.Store("oci", "", ocispec.MediaTypeImageLayer, mockTar(t, mockFile{name: "etc/hostname", data: "nydus\n"}))
	ociConfig := mockImageConfig
	ociConfig.RootFS.DiffIDs = []digest.Digest{layer.Digest}
	reg.StoreImage(t, "oci", "latest", ociConfig, layer)

	tests := []struct {
		name   string
		source string
		script string
		forbid bool
		mock   func(t *testing.T, workDir string)
		expect func(t *testing.T, dir string, err error)
	}{
		{
			name:   "push optimized image with ondemand blob",
			source: "nydus",
			script: mockOptimizeArgs + mockOptimizeBlob + mockOptimizeBlobMeta + mockOptimizeBootstrap + mockOptimizeReport,
			mock:   func(t *testing.T, workDir string) {},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
				if err != nil {
					t.Fatal(err)
				}

				bootstrap, err := oci.WriteBootstrapLayer(context.Background(), provider.ContentStore(), []byte("optimized bootstrap"), []nydus.BlobMetaFile{
					{Name: filepath.Base(mockDataBlobMeta.name), Data: []byte(mockDataBlobMeta.data)},
					{Name: mockOndemandHex + ".blob.meta", Data: []byte("ondemand meta")},
				}, nil)
				if err != nil {
					t.Fatal(err)
				}

				var manifest ocispec.Manifest
				reg.LoadJSON(t, "optimized", "latest", &manifest)
				assert.Equal([]ocispec.Descriptor{mockDataLayer, mockOndemandLayer, *bootstrap}, manifest.Layers)
				data, _ := reg.Load("optimized", mockDataLayer.Digest.String())
				assert.Equal(mockDataBlob, data)
				ondemand, _ := reg.Load("optimized", mockOndemandLayer.Digest.String())
				assert.Equal(mockOndemandBlob, ondemand)
				bootstrapBlob, _ := reg.Load("optimized", bootstrap.Digest.String())
				assert.Equal(map[string]string{
					nydus.BootstrapFileNameInLayer:            "optimized bootstrap",
					mockDataBlobMeta.name:                     mockDataBlobMeta.data,
					"image/" + mockOndemandHex + ".blob.meta": "ondemand meta",
				}, mockUntar(t, bootstrapBlob))

				var config ocispec.Image
				reg.LoadJSON(t, "optimized", manifest.Config.Digest.String(), &config)
				assert.Equal([]digest.Digest{
					mockDataLayer.Digest,
					mockOndemandLayer.Digest,
					digest.Digest(bootstrap.Annotations[nydus.LayerAnnotationUncompressed]),
				}, config.RootFS.DiffIDs)
				assert.Equal(mockOptimizedHistory, config.History)
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
			mock:   func(t *testing.T, workDir string) {},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `load source "`+reg.Ref("absent", "latest")+`"`)
			},
		},
		{
			name:   "reject oci source image",
			source: "oci",
			script: mockOptimizeArgs,
			mock:   func(t *testing.T, workDir string) {},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `source "`+reg.Ref("oci", "latest")+`" is not a nydus image`)
			},
		},
		{
			name:   "reject bootstrap layer without bootstrap file",
			source: "headless",
			script: mockOptimizeArgs,
			mock:   func(t *testing.T, workDir string) {},
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
			mock:   func(t *testing.T, workDir string) {},
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
			mock:   func(t *testing.T, workDir string) {},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "commit ondemand blob")
			},
		},
		{
			name:   "reject missing optimized bootstrap",
			source: "nydus",
			script: mockOptimizeArgs + mockOptimizeBlob + mockOptimizeBlobMeta + mockOptimizeReport,
			mock:   func(t *testing.T, workDir string) {},
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
			mock:   func(t *testing.T, workDir string) {},
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
			mock:   func(t *testing.T, workDir string) {},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "write optimized image: cannot determine diff id for layer "+mockDataLayer.Digest.String())
			},
		},
		{
			name:   "report rejected push",
			source: "nydus",
			script: mockOptimizeArgs + mockOptimizeBlob + mockOptimizeBlobMeta + mockOptimizeBootstrap + mockOptimizeReport,
			forbid: true,
			mock:   func(t *testing.T, workDir string) {},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "push \"")
				assert.ErrorContains(err, "403 Forbidden")
			},
		},
		{
			name:   "content dir is a file",
			source: "nydus",
			script: mockOptimizeArgs,
			mock: func(t *testing.T, workDir string) {
				if err := os.WriteFile(filepath.Join(workDir, "content"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create dir "+strconv.Quote(filepath.Join(dir, "work", "content")))
			},
		},
		{
			name:   "scratch dir is a file",
			source: "nydus",
			script: mockOptimizeArgs,
			mock: func(t *testing.T, workDir string) {
				if err := os.WriteFile(filepath.Join(workDir, "scratch"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, dir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create dir "+strconv.Quote(filepath.Join(dir, "work", "scratch")))
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

			tc.mock(t, workDir)

			builder := filepath.Join(dir, "nydus")
			if err := os.WriteFile(builder, []byte(tc.script), 0o700); err != nil {
				t.Fatal(err)
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
			if err != nil {
				t.Fatal(err)
			}

			tc.expect(t, dir, optimizer.Optimize(context.Background()))
		})
	}
}

func TestOptimizer_runNydusOptimize(t *testing.T) {
	tests := []struct {
		name   string
		script string
		cancel bool
		expect func(t *testing.T, pid int, args []string, dgst string, err error)
	}{
		{
			name:   "parse ondemand blob digest",
			script: "printf 'ONDEMAND BLOB DIGEST  " + mockOndemandHex + "\\n'",
			expect: func(t *testing.T, pid int, args []string, dgst string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockOndemandHex, dgst)
				assert.ErrorIs(unix.Kill(pid, 0), unix.ESRCH)
				assert.Equal(mockOptimizeCommand, args)
			},
		},
		{
			name:   "report builder failure",
			script: "exit 7",
			expect: func(t *testing.T, pid int, args []string, dgst string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "run nydus optimize: exit status 7")
				assert.Empty(dgst)
				assert.ErrorIs(unix.Kill(pid, 0), unix.ESRCH)
				assert.Equal(mockOptimizeCommand, args)
			},
		},
		{
			name:   "kill builder on cancel",
			script: "exec sleep 60",
			cancel: true,
			expect: func(t *testing.T, pid int, args []string, dgst string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "run nydus optimize")
				assert.Empty(dgst)
				assert.ErrorIs(unix.Kill(pid, 0), unix.ESRCH)
				assert.Equal(mockOptimizeCommand, args)
			},
		},
		{
			name:   "reject output without digest",
			script: "echo completed",
			expect: func(t *testing.T, pid int, args []string, dgst string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "did not report an ondemand blob digest")
				assert.Empty(dgst)
				assert.ErrorIs(unix.Kill(pid, 0), unix.ESRCH)
				assert.Equal(mockOptimizeCommand, args)
			},
		},
		{
			name:   "reject short digest",
			script: "echo 'ONDEMAND BLOB DIGEST " + mockOndemandHex[:63] + "'",
			expect: func(t *testing.T, pid int, args []string, dgst string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "did not report an ondemand blob digest")
				assert.Empty(dgst)
				assert.ErrorIs(unix.Kill(pid, 0), unix.ESRCH)
				assert.Equal(mockOptimizeCommand, args)
			},
		},
		{
			name:   "reject long digest",
			script: "echo 'ONDEMAND BLOB DIGEST " + mockOndemandHex + "a'",
			expect: func(t *testing.T, pid int, args []string, dgst string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "did not report an ondemand blob digest")
				assert.Empty(dgst)
				assert.ErrorIs(unix.Kill(pid, 0), unix.ESRCH)
				assert.Equal(mockOptimizeCommand, args)
			},
		},
		{
			name:   "reject prefixed digest row",
			script: "echo 'NOT ONDEMAND BLOB DIGEST " + mockOndemandHex + "'",
			expect: func(t *testing.T, pid int, args []string, dgst string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "did not report an ondemand blob digest")
				assert.Empty(dgst)
				assert.ErrorIs(unix.Kill(pid, 0), unix.ESRCH)
				assert.Equal(mockOptimizeCommand, args)
			},
		},
		{
			name:   "reject suffixed digest row",
			script: "echo 'ONDEMAND BLOB DIGEST " + mockOndemandHex + " trailing text'",
			expect: func(t *testing.T, pid int, args []string, dgst string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "did not report an ondemand blob digest")
				assert.Empty(dgst)
				assert.ErrorIs(unix.Kill(pid, 0), unix.ESRCH)
				assert.Equal(mockOptimizeCommand, args)
			},
		},
		{
			name:   "reject non-hex digest",
			script: "echo 'ONDEMAND BLOB DIGEST " + strings.Repeat("g", 64) + "'",
			expect: func(t *testing.T, pid int, args []string, dgst string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "did not report an ondemand blob digest")
				assert.Empty(dgst)
				assert.ErrorIs(unix.Kill(pid, 0), unix.ESRCH)
				assert.Equal(mockOptimizeCommand, args)
			},
		},
	}

	for _, tc := range tests {
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
				dgst string
				err  error
			}

			done := make(chan result, 1)
			go func() {
				dgst, err := (&Optimizer{opt: OptimizeOption{BuilderPath: builder, TraceFile: "trace.json"}}).
					runNydusOptimize(ctx, "parent.boot", "out.boot", "blobs", "config.yaml")
				done <- result{dgst: dgst, err: err}
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

			var res result
			select {
			case res = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("optimizer failed to return or cancel within 5s")
			}

			args, err := os.ReadFile(argsPath)
			if err != nil {
				t.Fatal(err)
			}

			tc.expect(t, pid, strings.Split(strings.TrimSpace(string(args)), "\n"), res.dgst, res.err)
		})
	}
}

func TestIngestDigestNamedBlobFile(t *testing.T) {
	tests := []struct {
		name   string
		dgst   digest.Digest
		expect func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error)
	}{
		{
			name: "commit blob named by its digest",
			dgst: mockOndemandLayer.Digest,
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&mockOndemandLayer, desc)
				data, err := content.ReadBlob(context.Background(), cs, mockOndemandLayer)
				assert.NoError(err)
				assert.Equal(mockOndemandBlob, data)
			},
		},
		{
			name: "reject blob not matching its name",
			dgst: digest.FromString("different payload"),
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unexpected commit digest")
				assert.Nil(desc)
				_, err = cs.Info(context.Background(), digest.FromString("different payload"))
				assert.ErrorIs(err, errdefs.ErrNotFound)
				_, err = cs.Info(context.Background(), mockOndemandLayer.Digest)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cs, err := local.NewStore(filepath.Join(dir, "content"))
			if err != nil {
				t.Fatal(err)
			}

			path := filepath.Join(dir, tc.dgst.Encoded())
			if err := os.WriteFile(path, mockOndemandBlob, 0o600); err != nil {
				t.Fatal(err)
			}

			desc, err := ingestDigestNamedBlobFile(context.Background(), cs, path)

			tc.expect(t, cs, desc, err)
		})
	}
}

func TestOptimizer_writeOptimizedImage(t *testing.T) {
	tests := []struct {
		name      string
		config    string
		rejected  bool
		layers    []ocispec.Descriptor
		diffIDs   []digest.Digest
		ondemand  ocispec.Descriptor
		bootstrap ocispec.Descriptor
		expect    func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error)
	}{
		{
			name:      "keep config fields the image spec does not name and empty ones",
			config:    `{"architecture":"amd64","os":"linux","config":{"Cmd":[],"Labels":{},"Healthcheck":{"Test":["CMD","true"]}},"moby.buildkit.cache.v0":"e30=","history":[{"created_by":"source"}]}`,
			layers:    []ocispec.Descriptor{mockDataLayer, mockOldBootstrapLayer},
			diffIDs:   []digest.Digest{mockDiffID},
			ondemand:  mockOndemandLayer,
			bootstrap: mockBootstrapLayer,
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				var manifest ocispec.Manifest
				assert.NoError(oci.ReadJSON(context.Background(), cs, *desc, &manifest))
				assert.Equal(ocispec.MediaTypeImageConfig, manifest.Config.MediaType)

				var config map[string]json.RawMessage
				assert.NoError(oci.ReadJSON(context.Background(), cs, manifest.Config, &config))
				assert.JSONEq(`{"Cmd":[],"Labels":{},"Healthcheck":{"Test":["CMD","true"]}}`, string(config["config"]))
				assert.JSONEq(`"e30="`, string(config["moby.buildkit.cache.v0"]))

				var history []ocispec.History
				assert.NoError(json.Unmarshal(config["history"], &history))
				assert.Equal(mockOptimizedHistory, history)

				var rootFS ocispec.RootFS
				assert.NoError(json.Unmarshal(config["rootfs"], &rootFS))
				assert.Equal([]digest.Digest{mockDataLayer.Digest, mockOndemandLayer.Digest, digest.FromString("bootstrap tar")}, rootFS.DiffIDs)
			},
		},
		{
			name:      "take diff id from layer annotation",
			layers:    []ocispec.Descriptor{mockDataLayer, mockOldBootstrapLayer},
			diffIDs:   []digest.Digest{mockDiffID},
			ondemand:  mockOndemandLayer,
			bootstrap: mockBootstrapLayer,
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&mockPlatform, desc.Platform)
				var manifest ocispec.Manifest
				assert.NoError(oci.ReadJSON(context.Background(), cs, *desc, &manifest))
				assert.Equal([]ocispec.Descriptor{mockDataLayer, mockOndemandLayer, mockBootstrapLayer}, manifest.Layers)
				assert.Equal(mockManifestAnnotations, manifest.Annotations)

				var config ocispec.Image
				assert.NoError(oci.ReadJSON(context.Background(), cs, manifest.Config, &config))
				assert.Equal([]digest.Digest{mockDataLayer.Digest, mockOndemandLayer.Digest, digest.FromString("bootstrap tar")}, config.RootFS.DiffIDs)
				assert.Equal(mockImageConfig.Config, config.Config)
				assert.Equal(mockOptimizedHistory, config.History)

				labels, err := oci.Labels(context.Background(), cs, desc.Digest)
				assert.NoError(err)
				assert.Equal(map[string]string{
					"containerd.io/gc.ref.content.config": manifest.Config.Digest.String(),
					"containerd.io/gc.ref.content.l.0":    mockDataLayer.Digest.String(),
					"containerd.io/gc.ref.content.l.1":    mockOndemandLayer.Digest.String(),
					"containerd.io/gc.ref.content.l.2":    mockBootstrapLayer.Digest.String(),
				}, labels)
			},
		},
		{
			name:      "fall back to config diff id",
			layers:    []ocispec.Descriptor{mockDataLayerWithoutDiffID, mockOldBootstrapLayer},
			diffIDs:   []digest.Digest{mockDiffID},
			ondemand:  mockOndemandLayer,
			bootstrap: mockBootstrapLayer,
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&mockPlatform, desc.Platform)
				var manifest ocispec.Manifest
				assert.NoError(oci.ReadJSON(context.Background(), cs, *desc, &manifest))
				assert.Equal([]ocispec.Descriptor{mockDataLayerWithoutDiffID, mockOndemandLayer, mockBootstrapLayer}, manifest.Layers)
				assert.Equal(mockManifestAnnotations, manifest.Annotations)

				var config ocispec.Image
				assert.NoError(oci.ReadJSON(context.Background(), cs, manifest.Config, &config))
				assert.Equal([]digest.Digest{mockDiffID, mockOndemandLayer.Digest, digest.FromString("bootstrap tar")}, config.RootFS.DiffIDs)
				assert.Equal(mockImageConfig.Config, config.Config)
				assert.Equal(mockOptimizedHistory, config.History)

				labels, err := oci.Labels(context.Background(), cs, desc.Digest)
				assert.NoError(err)
				assert.Equal(map[string]string{
					"containerd.io/gc.ref.content.config": manifest.Config.Digest.String(),
					"containerd.io/gc.ref.content.l.0":    mockDataLayerWithoutDiffID.Digest.String(),
					"containerd.io/gc.ref.content.l.1":    mockOndemandLayer.Digest.String(),
					"containerd.io/gc.ref.content.l.2":    mockBootstrapLayer.Digest.String(),
				}, labels)
			},
		},
		{
			name:      "keep previous ondemand blob",
			layers:    []ocispec.Descriptor{mockDataLayerWithoutDiffID, mockPreviousOndemandLayer, mockOldBootstrapLayer},
			diffIDs:   []digest.Digest{mockDiffID, mockPreviousOndemandLayer.Digest},
			ondemand:  mockOndemandLayer,
			bootstrap: mockBootstrapLayer,
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&mockPlatform, desc.Platform)
				var manifest ocispec.Manifest
				assert.NoError(oci.ReadJSON(context.Background(), cs, *desc, &manifest))
				assert.Equal([]ocispec.Descriptor{mockDataLayerWithoutDiffID, mockPreviousOndemandLayer, mockOndemandLayer, mockBootstrapLayer}, manifest.Layers)
				assert.Equal(mockManifestAnnotations, manifest.Annotations)

				var config ocispec.Image
				assert.NoError(oci.ReadJSON(context.Background(), cs, manifest.Config, &config))
				assert.Equal([]digest.Digest{mockDiffID, mockPreviousOndemandLayer.Digest, mockOndemandLayer.Digest, digest.FromString("bootstrap tar")}, config.RootFS.DiffIDs)
				assert.Equal(mockImageConfig.Config, config.Config)
				assert.Equal(mockOptimizedHistory, config.History)

				labels, err := oci.Labels(context.Background(), cs, desc.Digest)
				assert.NoError(err)
				assert.Equal(map[string]string{
					"containerd.io/gc.ref.content.config": manifest.Config.Digest.String(),
					"containerd.io/gc.ref.content.l.0":    mockDataLayerWithoutDiffID.Digest.String(),
					"containerd.io/gc.ref.content.l.1":    mockPreviousOndemandLayer.Digest.String(),
					"containerd.io/gc.ref.content.l.2":    mockOndemandLayer.Digest.String(),
					"containerd.io/gc.ref.content.l.3":    mockBootstrapLayer.Digest.String(),
				}, labels)
			},
		},
		{
			name:      "reject data layer without diff id",
			rejected:  true,
			layers:    []ocispec.Descriptor{mockDataLayerWithoutDiffID, mockOldBootstrapLayer},
			ondemand:  mockOndemandLayer,
			bootstrap: mockBootstrapLayer,
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "cannot determine diff id")
				assert.Nil(desc)
				var infos []content.Info
				err = cs.Walk(context.Background(), func(info content.Info) error {
					infos = append(infos, info)
					return nil
				})
				assert.ErrorIs(err, os.ErrNotExist)
				assert.Empty(infos)
			},
		},
		{
			name:     "reject ondemand blob without diff id",
			rejected: true,
			layers:   []ocispec.Descriptor{mockDataLayer, mockOldBootstrapLayer},
			diffIDs:  []digest.Digest{mockDiffID},
			ondemand: ocispec.Descriptor{
				MediaType: nydus.MediaTypeNydusBlob,
				Digest:    mockOndemandLayer.Digest,
				Annotations: map[string]string{
					nydus.LayerAnnotationNydusBlob:          "true",
					nydus.LayerAnnotationNydusBlobOptimized: "true",
				},
			},
			bootstrap: mockBootstrapLayer,
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "missing uncompressed annotation on appended layer")
				assert.Nil(desc)
				var infos []content.Info
				err = cs.Walk(context.Background(), func(info content.Info) error {
					infos = append(infos, info)
					return nil
				})
				assert.ErrorIs(err, os.ErrNotExist)
				assert.Empty(infos)
			},
		},
		{
			name:     "reject bootstrap without diff id",
			rejected: true,
			layers:   []ocispec.Descriptor{mockDataLayer, mockOldBootstrapLayer},
			diffIDs:  []digest.Digest{mockDiffID},
			ondemand: mockOndemandLayer,
			bootstrap: ocispec.Descriptor{
				MediaType:   ocispec.MediaTypeImageLayerGzip,
				Digest:      mockBootstrapLayer.Digest,
				Annotations: map[string]string{nydus.LayerAnnotationNydusBootstrap: "true"},
			},
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "missing uncompressed annotation on appended layer")
				assert.Nil(desc)
				var infos []content.Info
				err = cs.Walk(context.Background(), func(info content.Info) error {
					infos = append(infos, info)
					return nil
				})
				assert.ErrorIs(err, os.ErrNotExist)
				assert.Empty(infos)
			},
		},
		{
			name:      "reject bootstrap that is not the last layer",
			rejected:  true,
			layers:    []ocispec.Descriptor{mockOldBootstrapLayer, mockDataLayer},
			diffIDs:   []digest.Digest{mockDiffID},
			ondemand:  mockOndemandLayer,
			bootstrap: mockBootstrapLayer,
			expect: func(t *testing.T, cs content.Store, desc *ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "split source layers")
				assert.Nil(desc)
				var infos []content.Info
				err = cs.Walk(context.Background(), func(info content.Info) error {
					infos = append(infos, info)
					return nil
				})
				assert.ErrorIs(err, os.ErrNotExist)
				assert.Empty(infos)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}

			config := mockImageConfig
			if tc.config != "" {
				config = ocispec.Image{}
				if err := json.Unmarshal([]byte(tc.config), &config); err != nil {
					t.Fatal(err)
				}
			}
			config.RootFS = ocispec.RootFS{Type: "layers", DiffIDs: tc.diffIDs}

			// The image's config as the store holds it: the raw source one,
			// or the typed mock. A rejected image is refused before its
			// config is read, and its cases assert an untouched store.
			configDesc := &ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig}
			if !tc.rejected {
				var stored any = config
				if tc.config != "" {
					stored = json.RawMessage(tc.config)
				}
				configDesc, err = oci.WriteJSON(context.Background(), provider.ContentStore(), stored, *configDesc, nil)
				if err != nil {
					t.Fatal(err)
				}
			}

			img := &nydusfs.Image{
				Desc:   ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Platform: &mockPlatform},
				Config: config,
				Manifest: ocispec.Manifest{
					Config:      *configDesc,
					Layers:      tc.layers,
					Annotations: mockManifestAnnotations,
				},
			}
			desc, err := (&Optimizer{}).writeOptimizedImage(context.Background(), provider.ContentStore(), img, tc.ondemand, tc.bootstrap)

			tc.expect(t, provider.ContentStore(), desc, err)
		})
	}
}
