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
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/cache"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd"
	systemdmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd/mocks"
)

var (
	mockPreheatUnit = "nydusd-preheat-" + mockID + ".service"

	mockOtherPreheatUnit = "nydusd-preheat-" + mockOtherID + ".service"

	mockPreheatCredential = &PreheatCredential{Username: "user", Password: "pass"}

	mockPreheatToken = &PreheatCredential{BearerToken: "token"}

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
		name   string
		mock   func(m mockRecorders)
		expect func(t *testing.T, f *fileSystem, image *Image)
	}{
		{
			name: "download every blob of an image",
			mock: func(m mockRecorders) {
				m.systemd.StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, *systemd.Unit) error {
					f := m.fs.Load()
					return f.writePreheatFile(filepath.Join(f.cfg.Load().PreheatRuntimeDir(mockID), preheatStateFile), mockPreheatSucceeded)
				}).Times(1)
				m.systemd.ActiveState(gomock.Any(), mockPreheatUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image) {
				assert := assert.New(t)
				startPreheats(t, f)
				assert.NoError(f.Preheat(t.Context(), image, mockPreheatCredential))
				waitPreheat(t, f, mockID)
				preheat, err := f.StatPreheat(mockChainID)
				assert.NoError(err)
				assert.Equal(PreheatStateSucceeded, preheat.State)
				assert.Equal(mockPreheatSucceeded.Blobs, preheat.Blobs)
				assert.Empty(preheat.Description)
				assert.NoFileExists(filepath.Join(f.cfg.Load().PreheatRuntimeDir(mockID), preheatConfigFile))
			},
		},
		{
			name: "keep the running preheat of the same image",
			mock: func(m mockRecorders) {
				m.systemd.StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, *systemd.Unit) error {
					f := m.fs.Load()
					return f.writePreheatFile(filepath.Join(f.cfg.Load().PreheatRuntimeDir(mockID), preheatStateFile), mockPreheatRunning)
				}).Times(1)
				m.systemd.ActiveState(gomock.Any(), mockPreheatUnit).Return(systemd.ActiveStateActive, nil).AnyTimes()
			},
			expect: func(t *testing.T, f *fileSystem, image *Image) {
				assert := assert.New(t)
				startPreheats(t, f)
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
			name: "wait for a slot",
			mock: func(m mockRecorders) {
				m.systemd.StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, unit *systemd.Unit) error {
					f := m.fs.Load()
					id := mockID
					if unit.Name == mockOtherPreheatUnit {
						id = mockOtherID
					}

					return f.writePreheatFile(filepath.Join(f.cfg.Load().PreheatRuntimeDir(id), preheatStateFile), mockPreheatSucceeded)
				}).Times(2)
				m.systemd.ActiveState(gomock.Any(), mockPreheatUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				m.systemd.ActiveState(gomock.Any(), mockOtherPreheatUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image) {
				assert := assert.New(t)
				other := *image
				other.ChainID = "sha256:" + mockOtherID
				assert.NoError(f.preheats.slots.Acquire(t.Context(), 1))
				startPreheats(t, f)
				assert.NoError(f.Preheat(t.Context(), image, mockPreheatCredential))
				assert.NoError(f.Preheat(t.Context(), &other, mockPreheatCredential))
				for _, chainID := range []string{mockChainID, other.ChainID} {
					preheat, err := f.StatPreheat(chainID)
					assert.NoError(err)
					assert.Equal(PreheatStatePending, preheat.State)
				}

				f.preheats.slots.Release(1)
				waitPreheat(t, f, mockID)
				waitPreheat(t, f, mockOtherID)
				for _, chainID := range []string{mockChainID, other.ChainID} {
					preheat, err := f.StatPreheat(chainID)
					assert.NoError(err)
					assert.Equal(PreheatStateSucceeded, preheat.State)
				}
			},
		},
		{
			name: "watch a unit that already runs",
			mock: func(m mockRecorders) {
				m.systemd.StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, *systemd.Unit) error {
					f := m.fs.Load()
					if err := f.writePreheatFile(filepath.Join(f.cfg.Load().PreheatRuntimeDir(mockID), preheatStateFile), mockPreheatSucceeded); err != nil {
						return err
					}

					return errdefs.ErrAlreadyExists
				}).Times(1)
				m.systemd.ActiveState(gomock.Any(), mockPreheatUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image) {
				assert := assert.New(t)
				startPreheats(t, f)
				assert.NoError(f.Preheat(t.Context(), image, mockPreheatCredential))
				waitPreheat(t, f, mockID)
				preheat, err := f.StatPreheat(mockChainID)
				assert.NoError(err)
				assert.Equal(PreheatStateSucceeded, preheat.State)
			},
		},
		{
			name: "process that reports a failed blob",
			mock: func(m mockRecorders) {
				m.systemd.StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, *systemd.Unit) error {
					f := m.fs.Load()
					return f.writePreheatFile(filepath.Join(f.cfg.Load().PreheatRuntimeDir(mockID), preheatStateFile), mockPreheatFailed)
				}).Times(1)
				m.systemd.ActiveState(gomock.Any(), mockPreheatUnit).Return(systemd.ActiveState(""), errors.New("foo")).Times(1)
				m.systemd.ActiveState(gomock.Any(), mockPreheatUnit).Return(systemd.ActiveStateFailed, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image) {
				assert := assert.New(t)
				startPreheats(t, f)
				assert.NoError(f.Preheat(t.Context(), image, mockPreheatCredential))
				waitPreheat(t, f, mockID)
				preheat, err := f.StatPreheat(mockChainID)
				assert.NoError(err)
				assert.Equal(PreheatStateFailed, preheat.State)
				assert.Equal(mockPreheatFailed.Description, preheat.Description)
				assert.Equal(mockPreheatFailed.Blobs, preheat.Blobs)
			},
		},
		{
			name: "process that exits without a result",
			mock: func(m mockRecorders) {
				m.systemd.StartTransientUnit(gomock.Any(), gomock.Any()).Return(nil).Times(1)
				m.systemd.ActiveState(gomock.Any(), mockPreheatUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image) {
				assert := assert.New(t)
				startPreheats(t, f)
				assert.NoError(f.Preheat(t.Context(), image, mockPreheatCredential))
				waitPreheat(t, f, mockID)
				preheat, err := f.StatPreheat(mockChainID)
				assert.NoError(err)
				assert.Equal(PreheatStateFailed, preheat.State)
				assert.Equal("preheat process exited without a result, see journalctl -u "+mockPreheatUnit+" and "+f.cfg.Load().PreheatLogDir(), preheat.Description)
			},
		},
		{
			name: "unit that does not start",
			mock: func(m mockRecorders) {
				m.systemd.StartTransientUnit(gomock.Any(), gomock.Any()).Return(errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image) {
				assert := assert.New(t)
				startPreheats(t, f)
				assert.NoError(f.Preheat(t.Context(), image, mockPreheatCredential))
				waitPreheat(t, f, mockID)
				preheat, err := f.StatPreheat(mockChainID)
				assert.NoError(err)
				assert.Equal(PreheatStateFailed, preheat.State)
				assert.Equal("start preheat: foo, see journalctl -u "+mockPreheatUnit+" and "+f.cfg.Load().PreheatLogDir(), preheat.Description)
				assert.NoFileExists(filepath.Join(f.cfg.Load().PreheatRuntimeDir(mockID), preheatConfigFile))
			},
		},
		{
			name: "bootstrap layer without a bootstrap",
			mock: func(m mockRecorders) {},
			expect: func(t *testing.T, f *fileSystem, image *Image) {
				assert := assert.New(t)
				assert.NoError(os.Remove(filepath.Join(image.BootstrapDir, "image", bootstrapFile)))
				startPreheats(t, f)
				assert.NoError(f.Preheat(t.Context(), image, mockPreheatCredential))
				waitPreheat(t, f, mockID)
				preheat, err := f.StatPreheat(mockChainID)
				assert.NoError(err)
				assert.Equal(PreheatStateFailed, preheat.State)
				assert.Contains(preheat.Description, "start preheat: stat ")
			},
		},
		{
			name: "replace a finished preheat and remove the expired ones",
			mock: func(m mockRecorders) {
				m.systemd.StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, *systemd.Unit) error {
					f := m.fs.Load()
					return f.writePreheatFile(filepath.Join(f.cfg.Load().PreheatRuntimeDir(mockID), preheatStateFile), mockPreheatSucceeded)
				}).Times(1)
				m.systemd.ActiveState(gomock.Any(), mockPreheatUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image) {
				assert := assert.New(t)
				cfg := f.cfg.Load()
				writePreheat(t, f, mockID, mockPreheatFailed)
				expired := *mockPreheatSucceeded
				expired.UpdatedAt = time.Now().Add(-preheatRetention - time.Minute)
				writePreheat(t, f, mockOtherID, &expired)

				startPreheats(t, f)
				assert.NoError(f.Preheat(t.Context(), image, mockPreheatCredential))
				waitPreheat(t, f, mockID)
				preheat, err := f.StatPreheat(mockChainID)
				assert.NoError(err)
				assert.Equal(PreheatStateSucceeded, preheat.State)
				assert.NoDirExists(cfg.PreheatRuntimeDir(mockOtherID))
			},
		},
		{
			name: "chain id that is invalid",
			mock: func(m mockRecorders) {},
			expect: func(t *testing.T, f *fileSystem, image *Image) {
				assert := assert.New(t)
				image.ChainID = "foo"
				assert.ErrorIs(f.Preheat(t.Context(), image, mockPreheatCredential), errdefs.ErrInvalidArgument)
			},
		},
		{
			name: "reference that is invalid",
			mock: func(m mockRecorders) {},
			expect: func(t *testing.T, f *fileSystem, image *Image) {
				assert := assert.New(t)
				image.Ref = mockInvalidRef
				assert.Error(f.Preheat(t.Context(), image, mockPreheatCredential))
				assert.NoDirExists(f.cfg.Load().PreheatRuntimeDir(mockID))
			},
		},
		{
			name: "request that ends before the preheat is queued",
			mock: func(m mockRecorders) {},
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
			var fsys atomic.Pointer[fileSystem]
			tc.mock(mockRecorders{systemd: mockSystemd.EXPECT(), fs: &fsys})

			f, image := newTestFileSystem(t, mockSystemd, nil, nil, nil)
			f.preheats.pollInterval = time.Millisecond
			fsys.Store(f)
			tc.expect(t, f, image)
		})
	}
}

func TestFileSystem_startPreheat(t *testing.T) {
	tests := []struct {
		name   string
		mock   func(m mockRecorders)
		expect func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit])
	}{
		{
			name: "start the unit of a preheat read with a basic credential",
			mock: func(m mockRecorders) {
				m.systemd.StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, unit *systemd.Unit) error {
					m.started.Store(unit)
					return nil
				}).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				cfg := f.cfg.Load()
				dir := cfg.PreheatRuntimeDir(mockID)
				writePreheat(t, f, mockID, nil)
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
					"--log-dir", cfg.PreheatLogDir(),
					"--log-level", cfg.Nydusd.LogLevel,
					"--log-max-files", strconv.Itoa(cfg.Nydusd.LogMaxFiles),
				}, unit.ExecStart[1:])
				assert.Equal([]string{"NYDUS_PREHEAT_CONSOLE=false"}, unit.Environment)
				assert.NotContains(strings.Join(append(unit.ExecStart, unit.Environment...), " "), mockCredential)
			},
		},
		{
			name: "render a bearer token",
			mock: func(m mockRecorders) {
				m.systemd.StartTransientUnit(gomock.Any(), gomock.Any()).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				cfg := f.cfg.Load()
				writePreheat(t, f, mockID, nil)
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
			tc.mock(mockRecorders{systemd: mockSystemd.EXPECT(), started: &started})

			f, image := newTestFileSystem(t, mockSystemd, nil, nil, nil)
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
				writePreheat(t, f, mockID, &failed)
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
				writePreheat(t, f, mockID, &succeeded)
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
				writePreheat(t, f, mockID, mockPreheatRunning)
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
				writePreheat(t, f, mockID, nil)
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
				writePreheat(t, f, mockID, nil)
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
			f, _ := newTestFileSystem(t, systemdmocks.NewMockSystemd(ctl), nil, nil, nil)
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
				writePreheat(t, f, mockID, mockPreheatRunning)
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
				writePreheat(t, f, finished, mockPreheatSucceeded)
				assert.NoError(os.WriteFile(filepath.Join(cfg.PreheatRuntimeDir(finished), preheatConfigFile), nil, 0o600))
				writePreheat(t, f, died, mockPreheatRunning)
				assert.NoError(os.WriteFile(filepath.Join(cfg.PreheatRuntimeDir(died), preheatConfigFile), nil, 0o600))
				writePreheat(t, f, pending, nil)
				old := *mockPreheatFailed
				old.UpdatedAt = time.Now().Add(-preheatRetention - time.Minute)
				writePreheat(t, f, expired, &old)
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
				writePreheat(t, f, mockID, nil)
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

			f, _ := newTestFileSystem(t, mockSystemd, nil, nil, nil)
			f.preheats.pollInterval = time.Millisecond
			tc.expect(t, f)
		})
	}
}

func startPreheats(t *testing.T, f *fileSystem) {
	t.Helper()
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

func waitPreheat(t *testing.T, f *fileSystem, id string) {
	t.Helper()
	assert.Eventually(t, func() bool { return f.preheats.load(daemonID(id)) == nil }, time.Second, time.Millisecond)
}

func writePreheat(t *testing.T, f *fileSystem, id string, progress *preheatProgress) {
	t.Helper()
	dir := f.cfg.Load().PreheatRuntimeDir(id)
	assert.NoError(t, f.recordPreheat(dir, &preheatRecord{Image: "registry.example.com/team/app:v1", CreatedAt: time.Now().Add(-2 * time.Hour)}))
	if progress != nil {
		assert.NoError(t, f.writePreheatFile(filepath.Join(dir, preheatStateFile), progress))
	}
}
