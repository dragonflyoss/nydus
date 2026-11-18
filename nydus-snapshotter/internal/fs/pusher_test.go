/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	authmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/auth/mocks"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/metrics"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/nydusd"
	nydusdmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/nydusd/mocks"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store"
	storemocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store/mocks"
	systemdmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd/mocks"
)

func TestPusher_push(t *testing.T) {
	tests := []struct {
		name   string
		mock   func(k *authmocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder)
		expect func(t *testing.T, p *pusher)
	}{
		{
			name: "push changed credential",
			mock: func(k *authmocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(mockInstance, nil).Times(1)
				k.Resolve(gomock.Any(), gomock.Any()).Return(mockCredential, nil).Times(1)
				c.UpdateAuth(gomock.Any(), mockCredential).Return(nil).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				success := testutil.ToFloat64(metrics.AuthUpdatesTotal.WithLabelValues(metrics.ResultSuccess))
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
				assert.Equal(success+1, testutil.ToFloat64(metrics.AuthUpdatesTotal.WithLabelValues(metrics.ResultSuccess)))
			},
		},
		{
			name: "skip unchanged credential",
			mock: func(k *authmocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(mockInstance, nil).Times(2)
				k.Resolve(gomock.Any(), gomock.Any()).Return(mockCredential, nil).Times(2)
				c.UpdateAuth(gomock.Any(), mockCredential).Return(nil).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
			},
		},
		{
			name: "push rotated credential",
			mock: func(k *authmocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(mockInstance, nil).Times(2)
				gomock.InOrder(
					k.Resolve(gomock.Any(), gomock.Any()).Return(mockCredential, nil).Times(1),
					k.Resolve(gomock.Any(), gomock.Any()).Return(mockRotatedCredential, nil).Times(1),
				)
				c.UpdateAuth(gomock.Any(), mockCredential).Return(nil).Times(1)
				c.UpdateAuth(gomock.Any(), mockRotatedCredential).Return(nil).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
			},
		},
		{
			name: "push again to a restarted daemon",
			mock: func(k *authmocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				restarted := *mockInstance
				restarted.CreatedAt = mockInstance.CreatedAt.Add(time.Hour)
				gomock.InOrder(
					s.GetInstance(mockInstance.ChainID).Return(mockInstance, nil).Times(1),
					s.GetInstance(mockInstance.ChainID).Return(&restarted, nil).Times(1),
				)
				k.Resolve(gomock.Any(), gomock.Any()).Return(mockCredential, nil).Times(2)
				c.UpdateAuth(gomock.Any(), mockCredential).Return(nil).Times(2)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
			},
		},
		{
			name: "count a daemon without the auth capability once per credential",
			mock: func(k *authmocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				without := *mockInstance
				without.Capabilities = nil
				s.GetInstance(mockInstance.ChainID).Return(&without, nil).Times(2)
				k.Resolve(gomock.Any(), gomock.Any()).Return(mockCredential, nil).Times(2)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				unsupported := testutil.ToFloat64(metrics.AuthUpdatesTotal.WithLabelValues(metrics.ResultUnsupported))
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
				assert.Equal(unsupported+1, testutil.ToFloat64(metrics.AuthUpdatesTotal.WithLabelValues(metrics.ResultUnsupported)))
			},
		},
		{
			name: "retry a daemon that is not identified yet",
			mock: func(k *authmocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				starting := *mockInstance
				starting.Version, starting.Capabilities, starting.CreatedAt = "", nil, time.Now()
				s.GetInstance(mockInstance.ChainID).Return(&starting, nil).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				unsupported := testutil.ToFloat64(metrics.AuthUpdatesTotal.WithLabelValues(metrics.ResultUnsupported))
				assert.Error(p.push(t.Context(), mockInstance.ChainID))
				assert.Equal(unsupported, testutil.ToFloat64(metrics.AuthUpdatesTotal.WithLabelValues(metrics.ResultUnsupported)))
				assert.Empty(p.pushed)
			},
		},
		{
			name: "push to a daemon recorded without its version",
			mock: func(k *authmocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				old := *mockInstance
				old.Version, old.Capabilities = "", nil
				s.GetInstance(mockInstance.ChainID).Return(&old, nil).Times(1)
				k.Resolve(gomock.Any(), gomock.Any()).Return(mockCredential, nil).Times(1)
				c.UpdateAuth(gomock.Any(), mockCredential).Return(nil).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				success := testutil.ToFloat64(metrics.AuthUpdatesTotal.WithLabelValues(metrics.ResultSuccess))
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
				assert.Equal(success+1, testutil.ToFloat64(metrics.AuthUpdatesTotal.WithLabelValues(metrics.ResultSuccess)))
			},
		},
		{
			name: "keep credential when none is left",
			mock: func(k *authmocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(mockInstance, nil).Times(1)
				k.Resolve(gomock.Any(), gomock.Any()).Return("", nil).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
			},
		},
		{
			name: "forget removed instance",
			mock: func(k *authmocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(nil, fmt.Errorf("instance: %w", errdefs.ErrNotFound)).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				p.pushed[mockInstance.ChainID] = pushRecord{}
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
				assert.NotContains(p.pushed, mockInstance.ChainID)
			},
		},
		{
			name: "retry store failure",
			mock: func(k *authmocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(nil, errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				assert.EqualError(p.push(t.Context(), mockInstance.ChainID), "foo")
			},
		},
		{
			name: "skip invalid image reference",
			mock: func(k *authmocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				invalid := *mockInstance
				invalid.ImageRef = mockInvalidRef
				s.GetInstance(mockInstance.ChainID).Return(&invalid, nil).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
			},
		},
		{
			name: "skip unresolvable credential",
			mock: func(k *authmocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(mockInstance, nil).Times(1)
				k.Resolve(gomock.Any(), gomock.Any()).Return("", errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
			},
		},
		{
			name: "ask a daemon without the auth route once per credential",
			mock: func(k *authmocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(mockInstance, nil).Times(2)
				k.Resolve(gomock.Any(), gomock.Any()).Return(mockCredential, nil).Times(2)
				c.UpdateAuth(gomock.Any(), mockCredential).Return(fmt.Errorf("404: %w", errdefs.ErrNotImplemented)).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				unsupported := testutil.ToFloat64(metrics.AuthUpdatesTotal.WithLabelValues(metrics.ResultUnsupported))
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
				assert.Equal(unsupported+1, testutil.ToFloat64(metrics.AuthUpdatesTotal.WithLabelValues(metrics.ResultUnsupported)))
			},
		},
		{
			name: "send a credential the daemon rejects once",
			mock: func(k *authmocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(mockInstance, nil).Times(2)
				k.Resolve(gomock.Any(), gomock.Any()).Return(mockCredential, nil).Times(2)
				c.UpdateAuth(gomock.Any(), mockCredential).Return(fmt.Errorf("400: %w", errdefs.ErrInvalidArgument)).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				failure := testutil.ToFloat64(metrics.AuthUpdatesTotal.WithLabelValues(metrics.ResultFailure))
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
				assert.Equal(failure+1, testutil.ToFloat64(metrics.AuthUpdatesTotal.WithLabelValues(metrics.ResultFailure)))
			},
		},
		{
			name: "skip a stopped daemon and forget what it was given",
			mock: func(k *authmocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(mockInstance, nil).Times(2)
				gomock.InOrder(
					k.Resolve(gomock.Any(), gomock.Any()).Return(mockCredential, nil).Times(1),
					k.Resolve(gomock.Any(), gomock.Any()).Return(mockRotatedCredential, nil).Times(1),
				)
				c.UpdateAuth(gomock.Any(), mockCredential).Return(nil).Times(1)
				c.UpdateAuth(gomock.Any(), mockRotatedCredential).Return(fmt.Errorf("dial: %w", syscall.ECONNREFUSED)).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
				assert.Contains(p.pushed, mockInstance.ChainID)
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
				assert.NotContains(p.pushed, mockInstance.ChainID)
			},
		},
		{
			name: "retry a daemon that is starting",
			mock: func(k *authmocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				starting := *mockInstance
				starting.CreatedAt = time.Now()
				s.GetInstance(mockInstance.ChainID).Return(&starting, nil).Times(1)
				k.Resolve(gomock.Any(), gomock.Any()).Return(mockCredential, nil).Times(1)
				c.UpdateAuth(gomock.Any(), mockCredential).Return(fmt.Errorf("dial: %w", syscall.ENOENT)).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				failure := testutil.ToFloat64(metrics.AuthUpdatesTotal.WithLabelValues(metrics.ResultFailure))
				assert.ErrorIs(p.push(t.Context(), mockInstance.ChainID), syscall.ENOENT)
				assert.Equal(failure, testutil.ToFloat64(metrics.AuthUpdatesTotal.WithLabelValues(metrics.ResultFailure)))
				assert.Empty(p.pushed)
			},
		},
		{
			name: "retry failed push",
			mock: func(k *authmocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(mockInstance, nil).Times(1)
				k.Resolve(gomock.Any(), gomock.Any()).Return(mockCredential, nil).Times(1)
				c.UpdateAuth(gomock.Any(), mockCredential).Return(errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				failure := testutil.ToFloat64(metrics.AuthUpdatesTotal.WithLabelValues(metrics.ResultFailure))
				assert.EqualError(p.push(t.Context(), mockInstance.ChainID), "foo")
				assert.Equal(failure+1, testutil.ToFloat64(metrics.AuthUpdatesTotal.WithLabelValues(metrics.ResultFailure)))
				assert.Empty(p.pushed)
			},
		},
		{
			name: "push again after a push whose outcome is unknown",
			mock: func(k *authmocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(mockInstance, nil).Times(3)
				gomock.InOrder(
					k.Resolve(gomock.Any(), gomock.Any()).Return(mockCredential, nil).Times(1),
					k.Resolve(gomock.Any(), gomock.Any()).Return(mockRotatedCredential, nil).Times(1),
					k.Resolve(gomock.Any(), gomock.Any()).Return(mockCredential, nil).Times(1),
				)
				c.UpdateAuth(gomock.Any(), mockCredential).Return(nil).Times(2)
				c.UpdateAuth(gomock.Any(), mockRotatedCredential).Return(errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
				assert.EqualError(p.push(t.Context(), mockInstance.ChainID), "foo")
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			keychain := authmocks.NewMockKeychain(ctl)
			instances := storemocks.NewMockStore(ctl)
			client := nydusdmocks.NewMockClient(ctl)
			tc.mock(keychain.EXPECT(), instances.EXPECT(), client.EXPECT())

			p := newPusher(keychain, instances, func(string) nydusd.Client { return client }, time.Minute)
			defer p.queue.ShutDown()
			tc.expect(t, p)
		})
	}
}

func TestPusher_processNextWorkItem(t *testing.T) {
	tests := []struct {
		name   string
		mock   func(k *authmocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder)
		expect func(t *testing.T, p *pusher)
	}{
		{
			name: "forget a daemon that was pushed to",
			mock: func(k *authmocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(mockInstance, nil).Times(1)
				k.Resolve(gomock.Any(), gomock.Any()).Return(mockCredential, nil).Times(1)
				c.UpdateAuth(gomock.Any(), mockCredential).Return(nil).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				p.queue.Add(mockInstance.ChainID)
				assert.True(p.processNextWorkItem(t.Context()))
				assert.Zero(p.queue.NumRequeues(mockInstance.ChainID))
				assert.Zero(p.queue.Len())
			},
		},
		{
			name: "queue a daemon whose push failed again",
			mock: func(k *authmocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(nil, errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				p.queue.Add(mockInstance.ChainID)
				assert.True(p.processNextWorkItem(t.Context()))
				assert.Equal(1, p.queue.NumRequeues(mockInstance.ChainID))
			},
		},
		{
			name: "stop once the queue shuts down",
			mock: func(k *authmocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				p.queue.ShutDown()
				assert.False(p.processNextWorkItem(t.Context()))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			keychain := authmocks.NewMockKeychain(ctl)
			instances := storemocks.NewMockStore(ctl)
			client := nydusdmocks.NewMockClient(ctl)
			tc.mock(keychain.EXPECT(), instances.EXPECT(), client.EXPECT())

			p := newPusher(keychain, instances, func(string) nydusd.Client { return client }, time.Minute)
			defer p.queue.ShutDown()
			tc.expect(t, p)
		})
	}
}

func TestPusher_enqueue(t *testing.T) {
	tests := []struct {
		name   string
		mock   func(s *storemocks.MockStoreMockRecorder)
		expect func(t *testing.T, p *pusher)
	}{
		{
			name: "queue every recorded daemon",
			mock: func(s *storemocks.MockStoreMockRecorder) {
				s.ListInstances().Return([]*store.Instance{mockInstance, mockOtherInstance}, nil).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				assert.Equal(2, p.queue.Len())
			},
		},
		{
			name: "queue a daemon once",
			mock: func(s *storemocks.MockStoreMockRecorder) {
				s.ListInstances().Return([]*store.Instance{mockInstance}, nil).Times(2)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				p.enqueue()
				assert.Equal(1, p.queue.Len())
				chainID, _ := p.queue.Get()
				assert.Equal(mockInstance.ChainID, chainID)
			},
		},
		{
			name: "forget what was pushed to a daemon torn down since",
			mock: func(s *storemocks.MockStoreMockRecorder) {
				s.ListInstances().Return([]*store.Instance{mockInstance}, nil).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				assert.Contains(p.pushed, mockInstance.ChainID)
				assert.NotContains(p.pushed, mockOtherInstance.ChainID)
			},
		},
		{
			name: "store failure",
			mock: func(s *storemocks.MockStoreMockRecorder) {
				s.ListInstances().Return(nil, errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				assert.Equal(0, p.queue.Len())
				assert.Len(p.pushed, 2)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			instances := storemocks.NewMockStore(ctl)
			tc.mock(instances.EXPECT())

			p := newPusher(authmocks.NewMockKeychain(ctl), instances, nil, time.Minute)
			defer p.queue.ShutDown()
			p.pushed[mockInstance.ChainID] = pushRecord{}
			p.pushed[mockOtherInstance.ChainID] = pushRecord{}
			p.enqueue()
			tc.expect(t, p)
		})
	}
}

func TestFileSystem_Run(t *testing.T) {
	tests := []struct {
		name   string
		mock   func(k *authmocks.MockKeychainMockRecorder, c *nydusdmocks.MockClientMockRecorder, pushed chan<- string)
		expect func(t *testing.T, pushed <-chan string)
	}{
		{
			name: "push the credentials the keychain reports changed",
			mock: func(k *authmocks.MockKeychainMockRecorder, c *nydusdmocks.MockClientMockRecorder, pushed chan<- string) {
				rotated := make(chan struct{})
				k.Run(gomock.Any(), gomock.Any()).Do(func(ctx context.Context, onChange func()) {
					onChange()
					select {
					case <-rotated:
						onChange()
						<-ctx.Done()
					case <-ctx.Done():
					}
				}).Times(1)
				gomock.InOrder(
					k.Resolve(gomock.Any(), gomock.Any()).Return(mockCredential, nil).Times(1),
					k.Resolve(gomock.Any(), gomock.Any()).Return(mockRotatedCredential, nil).Times(1),
				)
				gomock.InOrder(
					c.UpdateAuth(gomock.Any(), mockCredential).DoAndReturn(func(context.Context, string) error {
						pushed <- mockCredential
						close(rotated)
						return nil
					}).Times(1),
					c.UpdateAuth(gomock.Any(), mockRotatedCredential).DoAndReturn(func(context.Context, string) error {
						pushed <- mockRotatedCredential
						return nil
					}).Times(1),
				)
			},
			expect: func(t *testing.T, pushed <-chan string) {
				assert := assert.New(t)
				if !assert.Eventually(func() bool { return len(pushed) == 2 }, 5*time.Second, 10*time.Millisecond) {
					return
				}

				assert.Equal(mockCredential, <-pushed)
				assert.Equal(mockRotatedCredential, <-pushed)
			},
		},
		{
			name: "push nothing while the keychain reports no change",
			mock: func(k *authmocks.MockKeychainMockRecorder, c *nydusdmocks.MockClientMockRecorder, pushed chan<- string) {
				k.Run(gomock.Any(), gomock.Any()).Times(1)
			},
			expect: func(t *testing.T, pushed <-chan string) {},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			keychain := authmocks.NewMockKeychain(ctl)
			client := nydusdmocks.NewMockClient(ctl)
			pushed := make(chan string, 2)
			tc.mock(keychain.EXPECT(), client.EXPECT(), pushed)

			f, _ := newTestFileSystem(t, systemdmocks.NewMockManager(ctl), keychain, NewMockDriver(ctl), client)
			assert.NoError(t, f.store.PutInstance(mockInstance))
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			go func() {
				defer close(done)
				f.Run(ctx)
			}()

			tc.expect(t, pushed)
			cancel()
			<-done
			ctl.Finish()
		})
	}
}
