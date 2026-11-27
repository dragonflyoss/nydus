/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/cache"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/kmutex"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/registry"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd"
	systemdmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd/mocks"
)

var (
	mockPreheatUnit = "nydusd-preheat-" + mockID + ".service"

	mockOtherPreheatUnit = "nydusd-preheat-" + mockOtherID + ".service"

	mockPreheatCredential = &PreheatCredential{Username: "user", Password: "pass"}

	mockPreheatToken = &PreheatCredential{BearerToken: "token"}

	mockPreheatRecord = &preheatRecord{Image: "registry.example.com/team/app:v1", CreatedAt: time.Now().Add(-2 * time.Hour)}

	mockPreheatSucceeded = &preheatProgress{
		State: PreheatStateSucceeded,
		Blobs: []PreheatBlob{
			{Digest: "sha256:" + mockBlobID, ContentLength: 512, FinishedContentLength: 512, IsFinished: true},
			{Digest: "sha256:" + mockOtherBlobID, ContentLength: 512, FinishedContentLength: 512, IsFinished: true},
		},
		UpdatedAt: time.Now(),
	}

	mockPreheatFailed = &preheatProgress{
		State: PreheatStateFailed,
		Blobs: []PreheatBlob{
			{Digest: "sha256:" + mockBlobID, ContentLength: 512, FinishedContentLength: 512, IsFinished: true},
			{Digest: "sha256:" + mockOtherBlobID, ContentLength: 512},
		},
		Description: "blob sha256:" + mockOtherBlobID + ": 401 Unauthorized",
		UpdatedAt:   time.Now(),
	}

	mockPreheatRunning = &preheatProgress{
		State: PreheatStateRunning,
		Blobs: []PreheatBlob{
			{Digest: "sha256:" + mockBlobID, ContentLength: 512, FinishedContentLength: 512, IsFinished: true},
			{Digest: "sha256:" + mockOtherBlobID, ContentLength: 512},
		},
		UpdatedAt: time.Now(),
	}
)

func TestPreheatCredential_renderOptions(t *testing.T) {
	tests := []struct {
		name       string
		credential *PreheatCredential
		expect     func(t *testing.T, opts *renderOptions)
	}{
		{
			name:       "basic credential",
			credential: mockPreheatCredential,
			expect: func(t *testing.T, opts *renderOptions) {
				assert := assert.New(t)
				assert.Equal(&renderOptions{auth: mockCredential}, opts)
			},
		},
		{
			name:       "bearer token",
			credential: mockPreheatToken,
			expect: func(t *testing.T, opts *renderOptions) {
				assert := assert.New(t)
				assert.Equal(&renderOptions{registryToken: "token"}, opts)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, tc.credential.renderOptions())
		})
	}
}

func TestFileSystem_Preheat(t *testing.T) {
	tests := []struct {
		name    string
		running bool
		mock    func(m *systemdmocks.MockSystemdMockRecorder, f *fileSystem)
		expect  func(t *testing.T, f *fileSystem, image *Image)
	}{
		{
			name:    "download every blob of an image",
			running: true,
			mock: func(m *systemdmocks.MockSystemdMockRecorder, f *fileSystem) {
				m.StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, *systemd.Unit) error {
					return f.writePreheatFile(filepath.Join(f.cfg.Load().PreheatRuntimeDir(mockID), preheatStateFile), mockPreheatSucceeded)
				}).Times(1)
				m.ActiveState(gomock.Any(), mockPreheatUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image) {
				assert := assert.New(t)
				assert.NoError(f.Preheat(t.Context(), image, mockPreheatCredential))
				assert.Eventually(func() bool { return f.preheats.load(daemonID(mockID)) == nil }, time.Second, time.Millisecond)
				preheat, err := f.StatPreheat(mockChainID)
				assert.NoError(err)
				assert.Equal(PreheatStateSucceeded, preheat.State)
				assert.Equal(mockPreheatSucceeded.Blobs, preheat.Blobs)
				assert.Empty(preheat.Description)
				assert.NoFileExists(filepath.Join(f.cfg.Load().PreheatRuntimeDir(mockID), preheatConfigFile))
			},
		},
		{
			name:    "keep the running preheat of the same image",
			running: true,
			mock: func(m *systemdmocks.MockSystemdMockRecorder, f *fileSystem) {
				m.StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, *systemd.Unit) error {
					return f.writePreheatFile(filepath.Join(f.cfg.Load().PreheatRuntimeDir(mockID), preheatStateFile), mockPreheatRunning)
				}).Times(1)
				m.ActiveState(gomock.Any(), mockPreheatUnit).Return(systemd.ActiveStateActive, nil).AnyTimes()
			},
			expect: func(t *testing.T, f *fileSystem, image *Image) {
				assert := assert.New(t)
				assert.NoError(f.Preheat(t.Context(), image, mockPreheatCredential))
				assert.Eventually(func() bool {
					preheat, err := f.StatPreheat(mockChainID)
					return err == nil && preheat.State == PreheatStateRunning
				}, time.Second, time.Millisecond)
				first, err := f.StatPreheat(mockChainID)
				assert.NoError(err)

				assert.NoError(f.Preheat(t.Context(), image, mockPreheatToken))
				second, err := f.StatPreheat(mockChainID)
				assert.NoError(err)
				assert.Equal(PreheatStateRunning, second.State)
				assert.Equal(first.CreatedAt, second.CreatedAt)
				assert.Equal(mockPreheatRunning.Blobs, second.Blobs)
			},
		},
		{
			name:    "wait for a slot",
			running: true,
			mock: func(m *systemdmocks.MockSystemdMockRecorder, f *fileSystem) {
				m.StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, unit *systemd.Unit) error {
					id := mockID
					if unit.Name == mockOtherPreheatUnit {
						id = mockOtherID
					}

					return f.writePreheatFile(filepath.Join(f.cfg.Load().PreheatRuntimeDir(id), preheatStateFile), mockPreheatSucceeded)
				}).Times(2)
				m.ActiveState(gomock.Any(), mockPreheatUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				m.ActiveState(gomock.Any(), mockOtherPreheatUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image) {
				assert := assert.New(t)
				other := *image
				other.ChainID = "sha256:" + mockOtherID
				assert.NoError(f.preheats.slots.Acquire(t.Context(), 1))
				assert.NoError(f.Preheat(t.Context(), image, mockPreheatCredential))
				assert.NoError(f.Preheat(t.Context(), &other, mockPreheatCredential))
				for _, chainID := range []string{mockChainID, other.ChainID} {
					preheat, err := f.StatPreheat(chainID)
					assert.NoError(err)
					assert.Equal(PreheatStatePending, preheat.State)
				}

				f.preheats.slots.Release(1)
				assert.Eventually(func() bool { return f.preheats.load(daemonID(mockID)) == nil }, time.Second, time.Millisecond)
				assert.Eventually(func() bool { return f.preheats.load(daemonID(mockOtherID)) == nil }, time.Second, time.Millisecond)
				for _, chainID := range []string{mockChainID, other.ChainID} {
					preheat, err := f.StatPreheat(chainID)
					assert.NoError(err)
					assert.Equal(PreheatStateSucceeded, preheat.State)
				}
			},
		},
		{
			name:    "watch a unit that already runs",
			running: true,
			mock: func(m *systemdmocks.MockSystemdMockRecorder, f *fileSystem) {
				m.StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, *systemd.Unit) error {
					if err := f.writePreheatFile(filepath.Join(f.cfg.Load().PreheatRuntimeDir(mockID), preheatStateFile), mockPreheatSucceeded); err != nil {
						return err
					}

					return errdefs.ErrAlreadyExists
				}).Times(1)
				m.ActiveState(gomock.Any(), mockPreheatUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image) {
				assert := assert.New(t)
				assert.NoError(f.Preheat(t.Context(), image, mockPreheatCredential))
				assert.Eventually(func() bool { return f.preheats.load(daemonID(mockID)) == nil }, time.Second, time.Millisecond)
				preheat, err := f.StatPreheat(mockChainID)
				assert.NoError(err)
				assert.Equal(PreheatStateSucceeded, preheat.State)
			},
		},
		{
			name:    "process that reports a failed blob",
			running: true,
			mock: func(m *systemdmocks.MockSystemdMockRecorder, f *fileSystem) {
				m.StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, *systemd.Unit) error {
					return f.writePreheatFile(filepath.Join(f.cfg.Load().PreheatRuntimeDir(mockID), preheatStateFile), mockPreheatFailed)
				}).Times(1)
				m.ActiveState(gomock.Any(), mockPreheatUnit).Return(systemd.ActiveState(""), errors.New("foo")).Times(1)
				m.ActiveState(gomock.Any(), mockPreheatUnit).Return(systemd.ActiveStateFailed, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image) {
				assert := assert.New(t)
				assert.NoError(f.Preheat(t.Context(), image, mockPreheatCredential))
				assert.Eventually(func() bool { return f.preheats.load(daemonID(mockID)) == nil }, time.Second, time.Millisecond)
				preheat, err := f.StatPreheat(mockChainID)
				assert.NoError(err)
				assert.Equal(PreheatStateFailed, preheat.State)
				assert.Equal(mockPreheatFailed.Description, preheat.Description)
				assert.Equal(mockPreheatFailed.Blobs, preheat.Blobs)
			},
		},
		{
			name:    "process that exits without a result",
			running: true,
			mock: func(m *systemdmocks.MockSystemdMockRecorder, f *fileSystem) {
				m.StartTransientUnit(gomock.Any(), gomock.Any()).Return(nil).Times(1)
				m.ActiveState(gomock.Any(), mockPreheatUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image) {
				assert := assert.New(t)
				assert.NoError(f.Preheat(t.Context(), image, mockPreheatCredential))
				assert.Eventually(func() bool { return f.preheats.load(daemonID(mockID)) == nil }, time.Second, time.Millisecond)
				preheat, err := f.StatPreheat(mockChainID)
				assert.NoError(err)
				assert.Equal(PreheatStateFailed, preheat.State)
				assert.Equal("preheat process exited without a result, see journalctl -u "+mockPreheatUnit, preheat.Description)
			},
		},
		{
			name:    "unit that does not start",
			running: true,
			mock: func(m *systemdmocks.MockSystemdMockRecorder, f *fileSystem) {
				m.StartTransientUnit(gomock.Any(), gomock.Any()).Return(errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image) {
				assert := assert.New(t)
				assert.NoError(f.Preheat(t.Context(), image, mockPreheatCredential))
				assert.Eventually(func() bool { return f.preheats.load(daemonID(mockID)) == nil }, time.Second, time.Millisecond)
				preheat, err := f.StatPreheat(mockChainID)
				assert.NoError(err)
				assert.Equal(PreheatStateFailed, preheat.State)
				assert.Equal("start preheat: foo, see journalctl -u "+mockPreheatUnit, preheat.Description)
				assert.NoFileExists(filepath.Join(f.cfg.Load().PreheatRuntimeDir(mockID), preheatConfigFile))
			},
		},
		{
			name:    "bootstrap layer without a bootstrap",
			running: true,
			mock:    func(m *systemdmocks.MockSystemdMockRecorder, f *fileSystem) {},
			expect: func(t *testing.T, f *fileSystem, image *Image) {
				assert := assert.New(t)
				assert.NoError(os.Remove(filepath.Join(image.BootstrapDir, "image", bootstrapFile)))
				assert.NoError(f.Preheat(t.Context(), image, mockPreheatCredential))
				assert.Eventually(func() bool { return f.preheats.load(daemonID(mockID)) == nil }, time.Second, time.Millisecond)
				preheat, err := f.StatPreheat(mockChainID)
				assert.NoError(err)
				assert.Equal(PreheatStateFailed, preheat.State)
				assert.Contains(preheat.Description, "start preheat: stat ")
			},
		},
		{
			name:    "replace a finished preheat and remove the expired ones",
			running: true,
			mock: func(m *systemdmocks.MockSystemdMockRecorder, f *fileSystem) {
				m.StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, *systemd.Unit) error {
					return f.writePreheatFile(filepath.Join(f.cfg.Load().PreheatRuntimeDir(mockID), preheatStateFile), mockPreheatSucceeded)
				}).Times(1)
				m.ActiveState(gomock.Any(), mockPreheatUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image) {
				assert := assert.New(t)
				cfg := f.cfg.Load()
				assert.NoError(f.recordPreheat(f.cfg.Load().PreheatRuntimeDir(mockID), mockPreheatRecord))
				assert.NoError(f.writePreheatFile(filepath.Join(f.cfg.Load().PreheatRuntimeDir(mockID), preheatStateFile), mockPreheatFailed))
				expired := *mockPreheatSucceeded
				expired.UpdatedAt = time.Now().Add(-preheatRetention - time.Minute)
				assert.NoError(f.recordPreheat(f.cfg.Load().PreheatRuntimeDir(mockOtherID), mockPreheatRecord))
				assert.NoError(f.writePreheatFile(filepath.Join(f.cfg.Load().PreheatRuntimeDir(mockOtherID), preheatStateFile), &expired))

				assert.NoError(f.Preheat(t.Context(), image, mockPreheatCredential))
				assert.Eventually(func() bool { return f.preheats.load(daemonID(mockID)) == nil }, time.Second, time.Millisecond)
				preheat, err := f.StatPreheat(mockChainID)
				assert.NoError(err)
				assert.Equal(PreheatStateSucceeded, preheat.State)
				assert.NoDirExists(cfg.PreheatRuntimeDir(mockOtherID))
			},
		},
		{
			name: "chain id that is invalid",
			mock: func(m *systemdmocks.MockSystemdMockRecorder, f *fileSystem) {},
			expect: func(t *testing.T, f *fileSystem, image *Image) {
				assert := assert.New(t)
				image.ChainID = "foo"
				assert.ErrorIs(f.Preheat(t.Context(), image, mockPreheatCredential), errdefs.ErrInvalidArgument)
			},
		},
		{
			name: "reference that is invalid",
			mock: func(m *systemdmocks.MockSystemdMockRecorder, f *fileSystem) {},
			expect: func(t *testing.T, f *fileSystem, image *Image) {
				assert := assert.New(t)
				image.Ref = mockInvalidRef
				assert.Error(f.Preheat(t.Context(), image, mockPreheatCredential))
				assert.NoDirExists(f.cfg.Load().PreheatRuntimeDir(mockID))
			},
		},
		{
			name: "request that ends before the preheat is queued",
			mock: func(m *systemdmocks.MockSystemdMockRecorder, f *fileSystem) {},
			expect: func(t *testing.T, f *fileSystem, image *Image) {
				assert := assert.New(t)
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				assert.ErrorIs(f.Preheat(ctx, image, mockPreheatCredential), context.Canceled)
				assert.Nil(f.preheats.load(daemonID(mockID)))
				assert.NoDirExists(f.cfg.Load().PreheatRuntimeDir(mockID))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			mockSystemd := systemdmocks.NewMockSystemd(ctl)

			root := t.TempDir()
			cfg := config.New()
			cfg.RootDir = filepath.Join(root, "lib")
			cfg.RuntimeDir = filepath.Join(root, "run")
			cfg.Registry.ConfigPath = ""
			cfg.Nydusd.Binary = filepath.Join(root, "nydus")
			cfg.Nydusd.MountTimeout = config.Duration(2 * time.Second)
			cfg.Cgroup = config.CgroupConfig{Slice: config.DefaultCgroupSlice}
			assert.NoError(t, os.CopyFS(root, mockRootFS))
			assert.NoError(t, os.MkdirAll(cfg.CacheDir(), 0o700))

			s, err := store.New(filepath.Join(root, "nydusd.db"), store.DefaultOpenTimeout)
			assert.NoError(t, err)
			t.Cleanup(func() { s.Close() })

			f := &fileSystem{
				systemd:   mockSystemd,
				store:     s,
				hosts:     registry.NewHosts(""),
				locker:    kmutex.New(),
				startLock: &sync.Mutex{},
				preheats:  newPreheatQueue(cfg.Preheat.MaxConcurrentImages),
			}
			f.cfg.Store(cfg)
			image := &Image{ChainID: mockChainID, Ref: mockImageRef, BootstrapDir: filepath.Join(root, "bootstrap", "fs"), PrefetchScope: "all"}

			f.preheats.pollInterval = time.Millisecond
			tc.mock(mockSystemd.EXPECT(), f)
			if tc.running {
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan struct{})
				go func() {
					defer close(done)
					f.runPreheats(ctx)
				}()
				t.Cleanup(func() {
					cancel()
					<-done
				})
			}

			tc.expect(t, f, image)
		})
	}
}

func TestFileSystem_startPreheat(t *testing.T) {
	tests := []struct {
		name   string
		mock   func(m *systemdmocks.MockSystemdMockRecorder, started *atomic.Pointer[systemd.Unit])
		expect func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit])
	}{
		{
			name: "start the unit of a preheat read with a basic credential",
			mock: func(m *systemdmocks.MockSystemdMockRecorder, started *atomic.Pointer[systemd.Unit]) {
				m.StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, unit *systemd.Unit) error {
					started.Store(unit)
					return nil
				}).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				cfg := f.cfg.Load()
				dir := cfg.PreheatRuntimeDir(mockID)
				assert.NoError(f.recordPreheat(f.cfg.Load().PreheatRuntimeDir(mockID), mockPreheatRecord))
				job := f.preheats.add(daemonID(mockID), image, mockPreheatCredential)
				assert.NoError(f.startPreheat(t.Context(), cfg, job))
				assert.True(job.running.Load())
				assert.Nil(job.credential)
				assert.FileExists(filepath.Join(cfg.CacheDir(), mockBlobID+cache.BlobMetaSuffix))

				rendered, err := os.ReadFile(filepath.Join(dir, preheatConfigFile))
				assert.NoError(err)
				assert.Contains(string(rendered), "auth: "+mockCredential)
				assert.Contains(string(rendered), "repository: team/app")
				assert.NotContains(string(rendered), "registry_token:")

				unit := started.Load()
				assert.Equal(mockPreheatUnit, unit.Name)
				assert.Equal(cfg.Cgroup.Slice, unit.Slice)
				assert.False(unit.Notify)
				assert.Equal(f.daemonResources(cfg), unit.Resources)
				assert.Equal(cfg.Nydusd.Binary, unit.ExecStart[0])
				assert.Equal([]string{
					"preheat",
					"--bootstrap", filepath.Join(image.BootstrapDir, "image", bootstrapFile),
					"--config", filepath.Join(dir, preheatConfigFile),
					"--state-file", filepath.Join(dir, preheatStateFile),
					"--log-level", cfg.Nydusd.Log.Level,
					"--log-journald",
				}, unit.ExecStart[1:])
				assert.NotContains(strings.Join(unit.ExecStart, " "), mockCredential)
			},
		},
		{
			name: "render a bearer token",
			mock: func(m *systemdmocks.MockSystemdMockRecorder, started *atomic.Pointer[systemd.Unit]) {
				m.StartTransientUnit(gomock.Any(), gomock.Any()).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				cfg := f.cfg.Load()
				assert.NoError(f.recordPreheat(f.cfg.Load().PreheatRuntimeDir(mockID), mockPreheatRecord))
				job := f.preheats.add(daemonID(mockID), image, mockPreheatToken)
				assert.NoError(f.startPreheat(t.Context(), cfg, job))
				rendered, err := os.ReadFile(filepath.Join(cfg.PreheatRuntimeDir(mockID), preheatConfigFile))
				assert.NoError(err)
				assert.Contains(string(rendered), "registry_token: token")
				assert.NotContains(string(rendered), "auth:")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			mockSystemd := systemdmocks.NewMockSystemd(ctl)
			var started atomic.Pointer[systemd.Unit]
			tc.mock(mockSystemd.EXPECT(), &started)

			root := t.TempDir()
			cfg := config.New()
			cfg.RootDir = filepath.Join(root, "lib")
			cfg.RuntimeDir = filepath.Join(root, "run")
			cfg.Registry.ConfigPath = ""
			cfg.Nydusd.Binary = filepath.Join(root, "nydus")
			cfg.Nydusd.MountTimeout = config.Duration(2 * time.Second)
			cfg.Cgroup = config.CgroupConfig{Slice: config.DefaultCgroupSlice}
			assert.NoError(t, os.CopyFS(root, mockRootFS))
			assert.NoError(t, os.MkdirAll(cfg.CacheDir(), 0o700))

			s, err := store.New(filepath.Join(root, "nydusd.db"), store.DefaultOpenTimeout)
			assert.NoError(t, err)
			t.Cleanup(func() { s.Close() })

			f := &fileSystem{
				systemd:   mockSystemd,
				store:     s,
				hosts:     registry.NewHosts(""),
				locker:    kmutex.New(),
				startLock: &sync.Mutex{},
				preheats:  newPreheatQueue(cfg.Preheat.MaxConcurrentImages),
			}
			f.cfg.Store(cfg)
			image := &Image{ChainID: mockChainID, Ref: mockImageRef, BootstrapDir: filepath.Join(root, "bootstrap", "fs"), PrefetchScope: "all"}

			tc.expect(t, f, image, &started)
		})
	}
}

func TestFileSystem_StatPreheat(t *testing.T) {
	tests := []struct {
		name    string
		chainID string
		prepare func(t *testing.T, f *fileSystem)
		expect  func(t *testing.T, preheat *Preheat, err error)
	}{
		{
			name:    "chain id that is invalid",
			chainID: "foo",
			prepare: func(t *testing.T, f *fileSystem) {},
			expect: func(t *testing.T, preheat *Preheat, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrInvalidArgument)
			},
		},
		{
			name:    "preheat that does not exist",
			chainID: mockChainID,
			prepare: func(t *testing.T, f *fileSystem) {},
			expect: func(t *testing.T, preheat *Preheat, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name:    "finished preheat",
			chainID: mockChainID,
			prepare: func(t *testing.T, f *fileSystem) {
				failed := *mockPreheatFailed
				failed.UpdatedAt = time.Now().Add(-time.Hour)
				assert.NoError(t, f.recordPreheat(f.cfg.Load().PreheatRuntimeDir(mockID), mockPreheatRecord))
				assert.NoError(t, f.writePreheatFile(filepath.Join(f.cfg.Load().PreheatRuntimeDir(mockID), preheatStateFile), &failed))
			},
			expect: func(t *testing.T, preheat *Preheat, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(PreheatStateFailed, preheat.State)
				assert.Equal(mockPreheatFailed.Description, preheat.Description)
				assert.True(preheat.UpdatedAt.After(preheat.CreatedAt))
			},
		},
		{
			name:    "finished preheat that expired",
			chainID: mockChainID,
			prepare: func(t *testing.T, f *fileSystem) {
				succeeded := *mockPreheatSucceeded
				succeeded.UpdatedAt = time.Now().Add(-preheatRetention - time.Minute)
				assert.NoError(t, f.recordPreheat(f.cfg.Load().PreheatRuntimeDir(mockID), mockPreheatRecord))
				assert.NoError(t, f.writePreheatFile(filepath.Join(f.cfg.Load().PreheatRuntimeDir(mockID), preheatStateFile), &succeeded))
			},
			expect: func(t *testing.T, preheat *Preheat, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name:    "preheat without a job or a result",
			chainID: mockChainID,
			prepare: func(t *testing.T, f *fileSystem) {
				assert.NoError(t, f.recordPreheat(f.cfg.Load().PreheatRuntimeDir(mockID), mockPreheatRecord))
				assert.NoError(t, f.writePreheatFile(filepath.Join(f.cfg.Load().PreheatRuntimeDir(mockID), preheatStateFile), mockPreheatRunning))
			},
			expect: func(t *testing.T, preheat *Preheat, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name:    "pending preheat",
			chainID: mockChainID,
			prepare: func(t *testing.T, f *fileSystem) {
				assert.NoError(t, f.recordPreheat(f.cfg.Load().PreheatRuntimeDir(mockID), mockPreheatRecord))
				f.preheats.add(daemonID(mockID), nil, nil)
			},
			expect: func(t *testing.T, preheat *Preheat, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(PreheatStatePending, preheat.State)
				assert.Equal(preheat.CreatedAt, preheat.UpdatedAt)
				assert.Empty(preheat.Blobs)
			},
		},
		{
			name:    "state file that is not json",
			chainID: mockChainID,
			prepare: func(t *testing.T, f *fileSystem) {
				assert.NoError(t, f.recordPreheat(f.cfg.Load().PreheatRuntimeDir(mockID), mockPreheatRecord))
				assert.NoError(t, os.WriteFile(filepath.Join(f.cfg.Load().PreheatRuntimeDir(mockID), preheatStateFile), []byte("foo"), 0o600))
			},
			expect: func(t *testing.T, preheat *Preheat, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "decode ")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			root := t.TempDir()
			cfg := config.New()
			cfg.RootDir = filepath.Join(root, "lib")
			cfg.RuntimeDir = filepath.Join(root, "run")
			cfg.Registry.ConfigPath = ""
			cfg.Nydusd.Binary = filepath.Join(root, "nydus")
			cfg.Nydusd.MountTimeout = config.Duration(2 * time.Second)
			cfg.Cgroup = config.CgroupConfig{Slice: config.DefaultCgroupSlice}
			assert.NoError(t, os.CopyFS(root, mockRootFS))
			assert.NoError(t, os.MkdirAll(cfg.CacheDir(), 0o700))

			s, err := store.New(filepath.Join(root, "nydusd.db"), store.DefaultOpenTimeout)
			assert.NoError(t, err)
			t.Cleanup(func() { s.Close() })

			f := &fileSystem{
				systemd:   systemdmocks.NewMockSystemd(ctl),
				store:     s,
				hosts:     registry.NewHosts(""),
				locker:    kmutex.New(),
				startLock: &sync.Mutex{},
				preheats:  newPreheatQueue(cfg.Preheat.MaxConcurrentImages),
			}
			f.cfg.Store(cfg)

			tc.prepare(t, f)
			preheat, err := f.StatPreheat(tc.chainID)
			tc.expect(t, preheat, err)
		})
	}
}

func TestFileSystem_recoverPreheats(t *testing.T) {
	tests := []struct {
		name   string
		mock   func(m *systemdmocks.MockSystemdMockRecorder)
		expect func(t *testing.T, f *fileSystem)
	}{
		{
			name: "nothing left by a previous run",
			mock: func(m *systemdmocks.MockSystemdMockRecorder) {},
			expect: func(t *testing.T, f *fileSystem) {
				assert := assert.New(t)
				assert.Empty(f.recoverPreheats(t.Context()))
			},
		},
		{
			name: "watch the unit that outlived the restart",
			mock: func(m *systemdmocks.MockSystemdMockRecorder) {
				m.ListUnits(gomock.Any(), gomock.Any(), preheatUnitPattern).Return(map[string]systemd.ActiveState{mockPreheatUnit: systemd.ActiveStateActive}, nil).Times(1)
				m.ActiveState(gomock.Any(), mockPreheatUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem) {
				assert := assert.New(t)
				assert.NoError(f.recordPreheat(f.cfg.Load().PreheatRuntimeDir(mockID), mockPreheatRecord))
				assert.NoError(f.writePreheatFile(filepath.Join(f.cfg.Load().PreheatRuntimeDir(mockID), preheatStateFile), mockPreheatRunning))
				jobs := f.recoverPreheats(t.Context())
				assert.Len(jobs, 1)
				preheat, err := f.StatPreheat(mockChainID)
				assert.NoError(err)
				assert.Equal(PreheatStateRunning, preheat.State)
				assert.Equal(mockPreheatRunning.Blobs, preheat.Blobs)

				assert.NoError(f.writePreheatFile(filepath.Join(f.cfg.Load().PreheatRuntimeDir(mockID), preheatStateFile), mockPreheatSucceeded))
				f.runPreheat(t.Context(), jobs[0])
				assert.Nil(f.preheats.load(daemonID(mockID)))
				preheat, err = f.StatPreheat(mockChainID)
				assert.NoError(err)
				assert.Equal(PreheatStateSucceeded, preheat.State)
			},
		},
		{
			name: "sort out the preheats whose units are gone",
			mock: func(m *systemdmocks.MockSystemdMockRecorder) {
				m.ListUnits(gomock.Any(), gomock.Any(), preheatUnitPattern).Return(map[string]systemd.ActiveState{}, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem) {
				assert := assert.New(t)
				cfg := f.cfg.Load()
				finished, died, pending, expired := mockID, mockOtherID, mockBlobID, mockOtherBlobID
				assert.NoError(f.recordPreheat(f.cfg.Load().PreheatRuntimeDir(finished), mockPreheatRecord))
				assert.NoError(f.writePreheatFile(filepath.Join(f.cfg.Load().PreheatRuntimeDir(finished), preheatStateFile), mockPreheatSucceeded))
				assert.NoError(os.WriteFile(filepath.Join(cfg.PreheatRuntimeDir(finished), preheatConfigFile), nil, 0o600))
				assert.NoError(f.recordPreheat(f.cfg.Load().PreheatRuntimeDir(died), mockPreheatRecord))
				assert.NoError(f.writePreheatFile(filepath.Join(f.cfg.Load().PreheatRuntimeDir(died), preheatStateFile), mockPreheatRunning))
				assert.NoError(os.WriteFile(filepath.Join(cfg.PreheatRuntimeDir(died), preheatConfigFile), nil, 0o600))
				assert.NoError(f.recordPreheat(f.cfg.Load().PreheatRuntimeDir(pending), mockPreheatRecord))
				old := *mockPreheatFailed
				old.UpdatedAt = time.Now().Add(-preheatRetention - time.Minute)
				assert.NoError(f.recordPreheat(f.cfg.Load().PreheatRuntimeDir(expired), mockPreheatRecord))
				assert.NoError(f.writePreheatFile(filepath.Join(f.cfg.Load().PreheatRuntimeDir(expired), preheatStateFile), &old))
				assert.NoError(os.Mkdir(filepath.Join(cfg.PreheatRuntimesDir(), "foo"), 0o700))

				assert.Empty(f.recoverPreheats(t.Context()))
				preheat, err := f.StatPreheat(mockChainID)
				assert.NoError(err)
				assert.Equal(PreheatStateSucceeded, preheat.State)
				assert.NoFileExists(filepath.Join(cfg.PreheatRuntimeDir(finished), preheatConfigFile))

				preheat, err = f.StatPreheat("sha256:" + died)
				assert.NoError(err)
				assert.Equal(PreheatStateFailed, preheat.State)
				assert.Contains(preheat.Description, "exited without a result")
				assert.Equal(mockPreheatRunning.Blobs, preheat.Blobs)
				assert.NoFileExists(filepath.Join(cfg.PreheatRuntimeDir(died), preheatConfigFile))

				assert.NoDirExists(cfg.PreheatRuntimeDir(pending))
				assert.NoDirExists(cfg.PreheatRuntimeDir(expired))
				assert.DirExists(filepath.Join(cfg.PreheatRuntimesDir(), "foo"))
			},
		},
		{
			name: "units that cannot be listed",
			mock: func(m *systemdmocks.MockSystemdMockRecorder) {
				m.ListUnits(gomock.Any(), gomock.Any(), preheatUnitPattern).Return(nil, errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem) {
				assert := assert.New(t)
				assert.NoError(f.recordPreheat(f.cfg.Load().PreheatRuntimeDir(mockID), mockPreheatRecord))
				assert.Empty(f.recoverPreheats(t.Context()))
				assert.DirExists(f.cfg.Load().PreheatRuntimeDir(mockID))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			mockSystemd := systemdmocks.NewMockSystemd(ctl)
			tc.mock(mockSystemd.EXPECT())

			root := t.TempDir()
			cfg := config.New()
			cfg.RootDir = filepath.Join(root, "lib")
			cfg.RuntimeDir = filepath.Join(root, "run")
			cfg.Registry.ConfigPath = ""
			cfg.Nydusd.Binary = filepath.Join(root, "nydus")
			cfg.Nydusd.MountTimeout = config.Duration(2 * time.Second)
			cfg.Cgroup = config.CgroupConfig{Slice: config.DefaultCgroupSlice}
			assert.NoError(t, os.CopyFS(root, mockRootFS))
			assert.NoError(t, os.MkdirAll(cfg.CacheDir(), 0o700))

			s, err := store.New(filepath.Join(root, "nydusd.db"), store.DefaultOpenTimeout)
			assert.NoError(t, err)
			t.Cleanup(func() { s.Close() })

			f := &fileSystem{
				systemd:   mockSystemd,
				store:     s,
				hosts:     registry.NewHosts(""),
				locker:    kmutex.New(),
				startLock: &sync.Mutex{},
				preheats:  newPreheatQueue(cfg.Preheat.MaxConcurrentImages),
			}
			f.cfg.Store(cfg)

			f.preheats.pollInterval = time.Millisecond
			tc.expect(t, f)
		})
	}
}
