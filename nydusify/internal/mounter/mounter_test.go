/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package mounter

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	"github.com/dragonflyoss/nydus/nydusify/internal/nydusfs"
	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/internal/registrytest"
	"github.com/dragonflyoss/nydus/nydusify/internal/remote"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

// TestMountChild exercises only the process boundary; FUSE readiness and
// unmounting are covered by TestMount/lifecycle in the end-to-end suite.
func TestMountChild(t *testing.T) {
	mode := os.Getenv("NYDUS_MOUNT_CHILD")
	if mode == "" {
		return
	}
	dir := os.Getenv("NYDUS_MOUNT_CONTROL")
	signals := make(chan os.Signal, 1)
	if mode == "unresponsive" {
		signal.Ignore(unix.SIGTERM)
	} else {
		signal.Notify(signals, unix.SIGTERM)
	}
	if err := os.WriteFile(filepath.Join(dir, "pid"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	if mode == "before_ready" {
		os.Exit(23)
	}
	if err := os.WriteFile(filepath.Join(dir, "ready"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "release")); err == nil {
			os.Exit(23)
		}
		select {
		case <-signals:
			if mode == "cancel_exit_race" {
				os.Exit(23)
			}
			os.Exit(0)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestMountNydusLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name, wantError string
		cancel, signal  bool
	}{
		{name: "startup_failure", wantError: "start nydus fuse"},
		{name: "before_ready", wantError: "nydus fuse exited: exit status 23"},
		{name: "running_failure", wantError: "nydus fuse exited: exit status 23"},
		{name: "cancel", cancel: true},
		{name: "cancel_exit_race", cancel: true},
		{name: "unresponsive", cancel: true, wantError: "nydus fuse exited: signal: killed"},
		{name: "terminate_signal", signal: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			mountpoint := filepath.Join(work, "mnt")
			if err := os.Mkdir(mountpoint, 0o700); err != nil {
				t.Fatal(err)
			}
			provider, err := remote.NewProvider(remote.Option{WorkDir: filepath.Join(work, "content"), TargetPlainHTTP: true})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			bootstrap, err := oci.WriteBootstrapLayer(ctx, provider.ContentStore(), []byte("process-boundary bootstrap"), nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			img := &nydusfs.Image{Ref: "localhost:5000/mount:test", Bootstrap: bootstrap}
			builder := filepath.Join(work, "builder")
			if tc.name != "startup_failure" {
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				script := fmt.Sprintf("#!/bin/sh\nexec %q -test.run=^TestMountChild$ -- \"$@\"\n", executable)
				if err := os.WriteFile(builder, []byte(script), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("NYDUS_MOUNT_CHILD", tc.name)
			t.Setenv("NYDUS_MOUNT_CONTROL", work)
			m := &Mounter{opt: MountOption{BuilderPath: builder, WorkDir: work, Mountpoint: mountpoint}}
			done := make(chan error, 1)
			go func() {
				done <- m.mountNydus(ctx, provider, provider.ContentStore(), img, filepath.Join(work, "scratch"))
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
			if tc.name != "startup_failure" {
				deadline := time.Now().Add(5 * time.Second)
				for pid == 0 && time.Now().Before(deadline) {
					data, _ := os.ReadFile(filepath.Join(work, "pid"))
					pid, _ = strconv.Atoi(string(data))
					time.Sleep(10 * time.Millisecond)
				}
				if pid == 0 {
					t.Fatal("mount child never started")
				}
				if tc.name != "before_ready" {
					for {
						if _, err := os.Stat(filepath.Join(work, "ready")); err == nil {
							break
						}
						if time.Now().After(deadline) {
							t.Fatal("child never became ready for termination")
						}
						time.Sleep(10 * time.Millisecond)
					}
				}
			}
			if tc.cancel {
				cancel()
			}
			if tc.signal {
				signals := make(chan os.Signal, 1)
				signal.Notify(signals, unix.SIGTERM)
				defer signal.Stop(signals)
				if err := unix.Kill(os.Getpid(), unix.SIGTERM); err != nil {
					t.Fatal(err)
				}
			}
			if tc.name == "running_failure" || tc.name == "cancel_exit_race" {
				if err := os.WriteFile(filepath.Join(work, "release"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-done:
				if tc.wantError == "" && err != nil {
					t.Fatalf("cancelled mount: %v", err)
				}
				if tc.wantError != "" && (err == nil || !strings.Contains(err.Error(), tc.wantError)) {
					t.Fatalf("error = %v, want %q", err, tc.wantError)
				}
			case <-time.After(8 * time.Second):
				t.Fatal("mount did not exit within 8s")
			}
			if pid != 0 {
				if err := unix.Kill(pid, 0); err != unix.ESRCH {
					t.Errorf("child %d not reaped: %v", pid, err)
				}
			}
			entries, err := os.ReadDir(mountpoint)
			if err != nil || len(entries) != 0 {
				t.Fatalf("mountpoint changed on process failure: %v, %v", entries, err)
			}
		})
	}
}

func TestMounter_mountNydus(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, work string, m *Mounter, img *nydusfs.Image)
		expect  func(t *testing.T, err error)
	}{
		{
			name: "missing mountpoint",
			prepare: func(t *testing.T, work string, m *Mounter, img *nydusfs.Image) {
				m.opt.Mountpoint = filepath.Join(work, "missing")
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "resolve mountpoint")
			},
		},
		{
			name: "mountpoint already mounted",
			prepare: func(t *testing.T, work string, m *Mounter, img *nydusfs.Image) {
				m.opt.Mountpoint = "/"
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "is already mounted")
			},
		},
		{
			name: "scratch dir is a file",
			prepare: func(t *testing.T, work string, m *Mounter, img *nydusfs.Image) {
				assert.NoError(t, os.WriteFile(filepath.Join(work, "scratch"), nil, 0o600))
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create dir")
			},
		},
		{
			name: "bootstrap missing from content store",
			prepare: func(t *testing.T, work string, m *Mounter, img *nydusfs.Image) {
				img.Bootstrap = &ocispec.Descriptor{Digest: digest.FromString("missing"), Size: 7}
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "extract bootstrap")
			},
		},
		{
			name: "blob meta cache entry is a directory",
			prepare: func(t *testing.T, work string, m *Mounter, img *nydusfs.Image) {
				assert.NoError(t, os.MkdirAll(filepath.Join(work, "scratch", "cache", "blob.blob.meta"), 0o700))
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "link blob meta to cache")
			},
		},
		{
			name: "invalid image reference",
			prepare: func(t *testing.T, work string, m *Mounter, img *nydusfs.Image) {
				img.Ref = "Invalid/Image:v1"
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "generate storage config")
			},
		},
		{
			name: "missing work dir",
			prepare: func(t *testing.T, work string, m *Mounter, img *nydusfs.Image) {
				m.opt.WorkDir = filepath.Join(work, "missing")
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "resolve nydus API socket directory")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			work := t.TempDir()
			mountpoint := filepath.Join(work, "mnt")
			if !assert.NoError(t, os.Mkdir(mountpoint, 0o700)) {
				t.FailNow()
			}
			provider, err := remote.NewProvider(remote.Option{WorkDir: filepath.Join(work, "content")})
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			bootstrap, err := oci.WriteBootstrapLayer(ctx, provider.ContentStore(), []byte("bootstrap"), []nydus.BlobMetaFile{{Name: "blob.blob.meta", Data: []byte("meta")}}, nil)
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			started := filepath.Join(work, "started")
			builder := filepath.Join(work, "builder")
			if !assert.NoError(t, os.WriteFile(builder, []byte("#!/bin/sh\ntouch "+started+"\n"), 0o700)) {
				t.FailNow()
			}
			m := &Mounter{opt: MountOption{BuilderPath: builder, WorkDir: work, Mountpoint: mountpoint}}
			img := &nydusfs.Image{Ref: "localhost:5000/mount:test", Bootstrap: bootstrap}
			tc.prepare(t, work, m, img)
			tc.expect(t, m.mountNydus(ctx, provider, provider.ContentStore(), img, filepath.Join(work, "scratch")))
			assert.NoFileExists(t, started)
			entries, err := os.ReadDir(mountpoint)
			assert.NoError(t, err)
			assert.Empty(t, entries)
		})
	}
}

func TestMounter_extractOCI(t *testing.T) {
	tests := []struct {
		name   string
		layer  func(t *testing.T, cs content.Store) ocispec.Descriptor
		expect func(t *testing.T, mountpoint string, err error)
	}{
		{
			name: "rootfs is extracted to mountpoint",
			layer: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				var archive bytes.Buffer
				tw := tar.NewWriter(&archive)
				assert.NoError(t, tw.WriteHeader(&tar.Header{Name: "etc/hostname", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg, Uid: os.Getuid(), Gid: os.Getgid()}))
				_, err := tw.Write([]byte("nydus"))
				assert.NoError(t, err)
				assert.NoError(t, tw.Close())
				desc := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayer, Digest: digest.FromBytes(archive.Bytes()), Size: int64(archive.Len())}
				assert.NoError(t, content.WriteBlob(context.Background(), cs, "layer", bytes.NewReader(archive.Bytes()), desc))
				return desc
			},
			expect: func(t *testing.T, mountpoint string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, err := os.ReadFile(filepath.Join(mountpoint, "etc", "hostname"))
				assert.NoError(err)
				assert.Equal("nydus", string(data))
			},
		},
		{
			name: "missing layer",
			layer: func(t *testing.T, cs content.Store) ocispec.Descriptor {
				return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayer, Digest: digest.FromString("missing"), Size: 7}
			},
			expect: func(t *testing.T, mountpoint string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "apply oci image")
				entries, err := os.ReadDir(mountpoint)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			mountpoint := t.TempDir()
			m := &Mounter{opt: MountOption{Mountpoint: mountpoint}}
			img := &nydusfs.Image{Ref: "localhost:5000/oci:test", Manifest: ocispec.Manifest{Layers: []ocispec.Descriptor{tc.layer(t, provider.ContentStore())}}}
			tc.expect(t, mountpoint, m.extractOCI(context.Background(), provider.ContentStore(), img))
		})
	}
}

func newMockLayer(t *testing.T, name, data string) []byte {
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	assert.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg, Uid: os.Getuid(), Gid: os.Getgid()}))
	_, err := tw.Write([]byte(data))
	assert.NoError(t, err)
	assert.NoError(t, tw.Close())
	return archive.Bytes()
}

type registry struct {
	*registrytest.Registry
}

func newRegistry(t *testing.T) *registry {
	return &registry{registrytest.New(t)}
}

func (r *registry) storeImage(t *testing.T, repo, tag string, layers ...ocispec.Descriptor) {
	r.StoreJSON(t, repo, tag, ocispec.MediaTypeImageManifest, ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    r.Store(repo, "", ocispec.MediaTypeImageConfig, []byte(`{"architecture":"amd64","os":"linux"}`)),
		Layers:    layers,
	})
}

func TestMounter_Mount(t *testing.T) {
	tests := []struct {
		name   string
		layer  func(t *testing.T) (ocispec.Descriptor, []byte)
		expect func(t *testing.T, work, mountpoint string, err error)
	}{
		{
			name: "oci image is extracted",
			layer: func(t *testing.T) (ocispec.Descriptor, []byte) {
				data := newMockLayer(t, "etc/hostname", "nydus")
				return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayer, Digest: digest.FromBytes(data), Size: int64(len(data))}, data
			},
			expect: func(t *testing.T, work, mountpoint string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, err := os.ReadFile(filepath.Join(mountpoint, "etc", "hostname"))
				assert.NoError(err)
				assert.Equal("nydus", string(data))
				assert.NoFileExists(filepath.Join(work, "bootstrap"))
			},
		},
		{
			name: "nydus image bootstrap is handed to fuse daemon",
			layer: func(t *testing.T) (ocispec.Descriptor, []byte) {
				provider, err := remote.NewProvider(remote.Option{WorkDir: t.TempDir()})
				if !assert.NoError(t, err) {
					t.FailNow()
				}
				desc, err := oci.WriteBootstrapLayer(context.Background(), provider.ContentStore(), []byte("bootstrap data"), nil, nil)
				if !assert.NoError(t, err) {
					t.FailNow()
				}
				data, err := content.ReadBlob(context.Background(), provider.ContentStore(), *desc)
				if !assert.NoError(t, err) {
					t.FailNow()
				}
				return *desc, data
			},
			expect: func(t *testing.T, work, mountpoint string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydus fuse exited: exit status 23")
				data, err := os.ReadFile(filepath.Join(work, "bootstrap"))
				assert.NoError(err)
				assert.Equal("bootstrap data", string(data))
				entries, err := os.ReadDir(mountpoint)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			layer, data := tc.layer(t)
			reg := newRegistry(t)
			reg.Store("image", "", "", data)
			reg.storeImage(t, "image", "v1", layer)
			work := t.TempDir()
			builder := filepath.Join(work, "builder")
			script := "#!/bin/sh\nwhile [ $# -gt 0 ]; do\nif [ \"$1\" = --bootstrap ]; then cp \"$2\" " + filepath.Join(work, "bootstrap") + "; fi\nshift\ndone\nexit 23\n"
			if !assert.NoError(t, os.WriteFile(builder, []byte(script), 0o700)) {
				t.FailNow()
			}
			mountpoint := t.TempDir()
			m, err := NewMounter(MountOption{Target: reg.Ref("image", "v1"), BuilderPath: builder, WorkDir: work, Mountpoint: mountpoint, TargetPlainHTTP: true})
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			tc.expect(t, work, mountpoint, m.Mount(context.Background()))
		})
	}
}
