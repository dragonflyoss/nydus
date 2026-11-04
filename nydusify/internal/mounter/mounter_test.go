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
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/content"
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

var (
	mockImageConfig = ocispec.Image{
		Platform: ocispec.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
	}

	mockBlobMetaFiles = []nydus.BlobMetaFile{
		{
			Name: "blob.blob.meta",
			Data: []byte("meta"),
		},
	}
)

func mockLayer(t *testing.T, name, data string) (ocispec.Descriptor, []byte) {
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg, Uid: os.Getuid(), Gid: os.Getgid()}); err != nil {
		t.Fatal(err)
	}

	if _, err := tw.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayer, Digest: digest.FromBytes(archive.Bytes()), Size: int64(archive.Len())}, archive.Bytes()
}

func childPID(work string) int {
	data, _ := os.ReadFile(filepath.Join(work, "pid"))
	pid, _ := strconv.Atoi(string(data))
	return pid
}

func waitChildReady(t *testing.T, work string) {
	assert.Eventually(t, func() bool {
		_, err := os.Stat(filepath.Join(work, "ready"))
		return err == nil
	}, 5*time.Second, 10*time.Millisecond)
}

func TestMountChild(t *testing.T) {
	mode := os.Getenv("NYDUS_MOUNT_CHILD")
	if mode == "" {
		return
	}

	dir := os.Getenv("NYDUS_MOUNT_CONTROL")
	signals := make(chan os.Signal, 1)
	if mode == "daemon ignores cancel" {
		signal.Ignore(unix.SIGTERM)
	} else {
		signal.Notify(signals, unix.SIGTERM)
	}

	if err := os.WriteFile(filepath.Join(dir, "pid"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}

	if mode == "daemon exits before ready" {
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
			if mode == "daemon fails on cancel" {
				os.Exit(23)
			}

			os.Exit(0)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestNewMounter(t *testing.T) {
	tests := []struct {
		name   string
		opt    MountOption
		expect func(t *testing.T, m *Mounter, err error)
	}{
		{
			name: "fill default platform and log level",
			opt:  MountOption{Target: "example.test/image:tag", Mountpoint: "/mnt"},
			expect: func(t *testing.T, m *Mounter, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(&Mounter{opt: MountOption{Target: "example.test/image:tag", Mountpoint: "/mnt", PlatformMC: platforms.Default(), LogLevel: "info"}}, m)
			},
		},
		{
			name: "reject empty target",
			opt:  MountOption{},
			expect: func(t *testing.T, m *Mounter, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "target must be provided")
				assert.Nil(m)
			},
		},
		{
			name: "reject empty mountpoint",
			opt:  MountOption{Target: "example.test/image:tag"},
			expect: func(t *testing.T, m *Mounter, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "mountpoint must be provided")
				assert.Nil(m)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := NewMounter(tc.opt)
			tc.expect(t, m, err)
		})
	}
}

func TestMounter_Mount(t *testing.T) {
	tests := []struct {
		name   string
		layer  func(t *testing.T) (ocispec.Descriptor, []byte)
		mock   func(t *testing.T, work string, m *Mounter)
		expect func(t *testing.T, work, mountpoint string, err error)
	}{
		{
			name: "oci image is extracted",
			layer: func(t *testing.T) (ocispec.Descriptor, []byte) {
				return mockLayer(t, "etc/hostname", "nydus")
			},
			mock: func(t *testing.T, work string, m *Mounter) {},
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
				if err != nil {
					t.Fatal(err)
				}

				desc, err := oci.WriteBootstrapLayer(context.Background(), provider.ContentStore(), []byte("bootstrap data"), nil, nil)
				if err != nil {
					t.Fatal(err)
				}

				data, err := content.ReadBlob(context.Background(), provider.ContentStore(), *desc)
				if err != nil {
					t.Fatal(err)
				}

				return *desc, data
			},
			mock: func(t *testing.T, work string, m *Mounter) {},
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
		{
			name: "content dir is a file",
			layer: func(t *testing.T) (ocispec.Descriptor, []byte) {
				return mockLayer(t, "etc/hostname", "nydus")
			},
			mock: func(t *testing.T, work string, m *Mounter) {
				if err := os.WriteFile(filepath.Join(work, "content"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, work, mountpoint string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create dir "+strconv.Quote(filepath.Join(work, "content")))
			},
		},
		{
			name: "scratch dir is a file",
			layer: func(t *testing.T) (ocispec.Descriptor, []byte) {
				return mockLayer(t, "etc/hostname", "nydus")
			},
			mock: func(t *testing.T, work string, m *Mounter) {
				if err := os.WriteFile(filepath.Join(work, "scratch"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, work, mountpoint string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create dir "+strconv.Quote(filepath.Join(work, "scratch")))
			},
		},
		{
			name: "invalid target reference",
			layer: func(t *testing.T) (ocispec.Descriptor, []byte) {
				return mockLayer(t, "etc/hostname", "nydus")
			},
			mock: func(t *testing.T, work string, m *Mounter) {
				m.opt.Target = "://invalid"
			},
			expect: func(t *testing.T, work, mountpoint string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `load target "://invalid"`)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			layer, data := tc.layer(t)
			reg := registrytest.New(t)
			reg.Store("image", "", "", data)
			reg.StoreImage(t, "image", "v1", mockImageConfig, layer)

			work := t.TempDir()
			builder := filepath.Join(work, "builder")
			script := "#!/bin/sh\nwhile [ $# -gt 0 ]; do\nif [ \"$1\" = --bootstrap ]; then cp \"$2\" " + filepath.Join(work, "bootstrap") + "; fi\nshift\ndone\nexit 23\n"
			if err := os.WriteFile(builder, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}

			mountpoint := t.TempDir()
			m, err := NewMounter(MountOption{Target: reg.Ref("image", "v1"), BuilderPath: builder, WorkDir: work, Mountpoint: mountpoint, TargetPlainHTTP: true})
			if err != nil {
				t.Fatal(err)
			}

			tc.mock(t, work, m)
			tc.expect(t, work, mountpoint, m.Mount(context.Background()))
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
				desc, data := mockLayer(t, "etc/hostname", "nydus")
				if err := content.WriteBlob(context.Background(), cs, "layer", bytes.NewReader(data), desc); err != nil {
					t.Fatal(err)
				}

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
			if err != nil {
				t.Fatal(err)
			}

			mountpoint := t.TempDir()
			m := &Mounter{opt: MountOption{Mountpoint: mountpoint}}
			img := &nydusfs.Image{Ref: "localhost:5000/oci:test", Manifest: ocispec.Manifest{Layers: []ocispec.Descriptor{tc.layer(t, provider.ContentStore())}}}

			tc.expect(t, mountpoint, m.extractOCI(context.Background(), provider.ContentStore(), img))
		})
	}
}

func TestMounter_mountNydus(t *testing.T) {
	tests := []struct {
		name   string
		mock   func(t *testing.T, work string, m *Mounter, img *nydusfs.Image)
		run    func(t *testing.T, work string, cancel context.CancelFunc)
		expect func(t *testing.T, pid int, entries []os.DirEntry, err error)
	}{
		{
			name: "image without bootstrap",
			mock: func(t *testing.T, work string, m *Mounter, img *nydusfs.Image) {
				img.Bootstrap = nil
			},
			run: func(t *testing.T, work string, cancel context.CancelFunc) {},
			expect: func(t *testing.T, pid int, entries []os.DirEntry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "missing its bootstrap")
				assert.Zero(pid)
				assert.Empty(entries)
			},
		},
		{
			name: "missing mountpoint",
			mock: func(t *testing.T, work string, m *Mounter, img *nydusfs.Image) {
				m.opt.Mountpoint = filepath.Join(work, "missing")
			},
			run: func(t *testing.T, work string, cancel context.CancelFunc) {},
			expect: func(t *testing.T, pid int, entries []os.DirEntry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "resolve mountpoint")
				assert.Zero(pid)
				assert.Empty(entries)
			},
		},
		{
			name: "mountpoint already mounted",
			mock: func(t *testing.T, work string, m *Mounter, img *nydusfs.Image) {
				m.opt.Mountpoint = "/"
			},
			run: func(t *testing.T, work string, cancel context.CancelFunc) {},
			expect: func(t *testing.T, pid int, entries []os.DirEntry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "is already mounted")
				assert.Zero(pid)
				assert.Empty(entries)
			},
		},
		{
			name: "scratch dir is a file",
			mock: func(t *testing.T, work string, m *Mounter, img *nydusfs.Image) {
				if err := os.WriteFile(filepath.Join(work, "scratch"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			run: func(t *testing.T, work string, cancel context.CancelFunc) {},
			expect: func(t *testing.T, pid int, entries []os.DirEntry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create dir")
				assert.Zero(pid)
				assert.Empty(entries)
			},
		},
		{
			name: "bootstrap missing from content store",
			mock: func(t *testing.T, work string, m *Mounter, img *nydusfs.Image) {
				img.Bootstrap = &ocispec.Descriptor{Digest: digest.FromString("missing"), Size: 7}
			},
			run: func(t *testing.T, work string, cancel context.CancelFunc) {},
			expect: func(t *testing.T, pid int, entries []os.DirEntry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "extract bootstrap")
				assert.Zero(pid)
				assert.Empty(entries)
			},
		},
		{
			name: "blob meta cache entry is a directory",
			mock: func(t *testing.T, work string, m *Mounter, img *nydusfs.Image) {
				if err := os.MkdirAll(filepath.Join(work, "scratch", "cache", "blob.blob.meta"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			run: func(t *testing.T, work string, cancel context.CancelFunc) {},
			expect: func(t *testing.T, pid int, entries []os.DirEntry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "link blob meta to cache")
				assert.Zero(pid)
				assert.Empty(entries)
			},
		},
		{
			name: "invalid image reference",
			mock: func(t *testing.T, work string, m *Mounter, img *nydusfs.Image) {
				img.Ref = "Invalid/Image:v1"
			},
			run: func(t *testing.T, work string, cancel context.CancelFunc) {},
			expect: func(t *testing.T, pid int, entries []os.DirEntry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "generate storage config")
				assert.Zero(pid)
				assert.Empty(entries)
			},
		},
		{
			name: "missing work dir",
			mock: func(t *testing.T, work string, m *Mounter, img *nydusfs.Image) {
				m.opt.WorkDir = filepath.Join(work, "missing")
			},
			run: func(t *testing.T, work string, cancel context.CancelFunc) {},
			expect: func(t *testing.T, pid int, entries []os.DirEntry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "resolve nydus API socket directory")
				assert.Zero(pid)
				assert.Empty(entries)
			},
		},
		{
			name: "missing builder",
			mock: func(t *testing.T, work string, m *Mounter, img *nydusfs.Image) {
				m.opt.BuilderPath = filepath.Join(work, "missing")
			},
			run: func(t *testing.T, work string, cancel context.CancelFunc) {},
			expect: func(t *testing.T, pid int, entries []os.DirEntry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "start nydus fuse")
				assert.Zero(pid)
				assert.Empty(entries)
			},
		},
		{
			name: "daemon exits before ready",
			mock: func(t *testing.T, work string, m *Mounter, img *nydusfs.Image) {},
			run:  func(t *testing.T, work string, cancel context.CancelFunc) {},
			expect: func(t *testing.T, pid int, entries []os.DirEntry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydus fuse exited: exit status 23")
				assert.ErrorIs(unix.Kill(pid, 0), unix.ESRCH)
				assert.Empty(entries)
			},
		},
		{
			name: "daemon fails while running",
			mock: func(t *testing.T, work string, m *Mounter, img *nydusfs.Image) {},
			run: func(t *testing.T, work string, cancel context.CancelFunc) {
				waitChildReady(t, work)
				if err := os.WriteFile(filepath.Join(work, "release"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, pid int, entries []os.DirEntry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydus fuse exited: exit status 23")
				assert.ErrorIs(unix.Kill(pid, 0), unix.ESRCH)
				assert.Empty(entries)
			},
		},
		{
			name: "cancel",
			mock: func(t *testing.T, work string, m *Mounter, img *nydusfs.Image) {},
			run: func(t *testing.T, work string, cancel context.CancelFunc) {
				waitChildReady(t, work)
				cancel()
			},
			expect: func(t *testing.T, pid int, entries []os.DirEntry, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.ErrorIs(unix.Kill(pid, 0), unix.ESRCH)
				assert.Empty(entries)
			},
		},
		{
			name: "daemon fails on cancel",
			mock: func(t *testing.T, work string, m *Mounter, img *nydusfs.Image) {},
			run: func(t *testing.T, work string, cancel context.CancelFunc) {
				waitChildReady(t, work)
				cancel()
				if err := os.WriteFile(filepath.Join(work, "release"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, pid int, entries []os.DirEntry, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.ErrorIs(unix.Kill(pid, 0), unix.ESRCH)
				assert.Empty(entries)
			},
		},
		{
			name: "daemon ignores cancel",
			mock: func(t *testing.T, work string, m *Mounter, img *nydusfs.Image) {},
			run: func(t *testing.T, work string, cancel context.CancelFunc) {
				waitChildReady(t, work)
				cancel()
			},
			expect: func(t *testing.T, pid int, entries []os.DirEntry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydus fuse exited: signal: killed")
				assert.ErrorIs(unix.Kill(pid, 0), unix.ESRCH)
				assert.Empty(entries)
			},
		},
		{
			name: "terminate signal",
			mock: func(t *testing.T, work string, m *Mounter, img *nydusfs.Image) {},
			run: func(t *testing.T, work string, cancel context.CancelFunc) {
				waitChildReady(t, work)
				signals := make(chan os.Signal, 1)
				signal.Notify(signals, unix.SIGTERM)
				t.Cleanup(func() { signal.Stop(signals) })
				if err := unix.Kill(os.Getpid(), unix.SIGTERM); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, pid int, entries []os.DirEntry, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.ErrorIs(unix.Kill(pid, 0), unix.ESRCH)
				assert.Empty(entries)
			},
		},
	}

	for _, tc := range tests {
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

			bootstrap, err := oci.WriteBootstrapLayer(ctx, provider.ContentStore(), []byte("bootstrap"), mockBlobMetaFiles, nil)
			if err != nil {
				t.Fatal(err)
			}

			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}

			builder := filepath.Join(work, "builder")
			if err := os.WriteFile(builder, fmt.Appendf(nil, "#!/bin/sh\nexec %q -test.run=^TestMountChild$ -- \"$@\"\n", executable), 0o700); err != nil {
				t.Fatal(err)
			}

			t.Setenv("NYDUS_MOUNT_CHILD", tc.name)
			t.Setenv("NYDUS_MOUNT_CONTROL", work)
			m := &Mounter{opt: MountOption{BuilderPath: builder, WorkDir: work, Mountpoint: mountpoint}}
			img := &nydusfs.Image{Ref: "localhost:5000/mount:test", Bootstrap: bootstrap}
			tc.mock(t, work, m, img)

			done := make(chan error, 1)
			go func() {
				done <- m.mountNydus(ctx, provider, provider.ContentStore(), img, filepath.Join(work, "scratch"))
				close(done)
			}()
			t.Cleanup(func() {
				cancel()
				if pid := childPID(work); pid != 0 {
					_ = unix.Kill(pid, unix.SIGKILL)
				}

				<-done
			})
			tc.run(t, work, cancel)

			select {
			case err := <-done:
				entries, readErr := os.ReadDir(mountpoint)
				if readErr != nil {
					t.Fatal(readErr)
				}

				tc.expect(t, childPID(work), entries, err)
			case <-time.After(8 * time.Second):
				t.Fatal("mount did not exit within 8s")
			}
		})
	}
}
