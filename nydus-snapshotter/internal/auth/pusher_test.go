/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package auth

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/auth/mocks"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/metrics"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/nydusd"
	nydusdmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/nydusd/mocks"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store"
	storemocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store/mocks"
)

var (
	mockInstance = &store.Instance{
		ChainID:      "sha256:0000000000000000000000000000000000000000000000000000000000000001",
		ImageRef:     "registry.example.com/team/app:v1",
		RegistryHost: "registry.example.com",
		APISocket:    "/run/containerd-nydus-v3/nydusd/1.sock",
		CreatedAt:    time.Unix(1700000000, 0).UTC(),
	}

	mockOtherInstance = &store.Instance{
		ChainID:      "sha256:0000000000000000000000000000000000000000000000000000000000000002",
		ImageRef:     "other.example.com/app:v1",
		RegistryHost: "other.example.com",
		APISocket:    "/run/containerd-nydus-v3/nydusd/2.sock",
		CreatedAt:    time.Unix(1700000000, 0).UTC(),
	}

	mockDockerHubInstance = &store.Instance{
		ChainID:      "sha256:0000000000000000000000000000000000000000000000000000000000000003",
		ImageRef:     "ubuntu:24.04",
		RegistryHost: "index.docker.io",
		APISocket:    "/run/containerd-nydus-v3/nydusd/3.sock",
		CreatedAt:    time.Unix(1700000000, 0).UTC(),
	}

	mockRotatedBasic = "dXNlcjpyb3RhdGVk"
)

func counterValue(t *testing.T, result string) float64 {
	t.Helper()
	var m dto.Metric
	assert.NoError(t, metrics.AuthUpdateTotal.WithLabelValues(result).Write(&m))
	return m.GetCounter().GetValue()
}

func TestPusher_push(t *testing.T) {
	tests := []struct {
		name   string
		mock   func(k *mocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder)
		expect func(t *testing.T, p *pusher)
	}{
		{
			name: "push changed credential",
			mock: func(k *mocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(mockInstance, nil).Times(1)
				k.Resolve(gomock.Any(), gomock.Any()).Return(mockBasic, nil).Times(1)
				c.UpdateAuth(gomock.Any(), mockBasic).Return(nil).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				success := counterValue(t, resultSuccess)
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
				assert.Equal(success+1, counterValue(t, resultSuccess))
			},
		},
		{
			name: "skip unchanged credential",
			mock: func(k *mocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(mockInstance, nil).Times(2)
				k.Resolve(gomock.Any(), gomock.Any()).Return(mockBasic, nil).Times(2)
				c.UpdateAuth(gomock.Any(), mockBasic).Return(nil).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
			},
		},
		{
			name: "push rotated credential",
			mock: func(k *mocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(mockInstance, nil).Times(2)
				gomock.InOrder(
					k.Resolve(gomock.Any(), gomock.Any()).Return(mockBasic, nil).Times(1),
					k.Resolve(gomock.Any(), gomock.Any()).Return(mockRotatedBasic, nil).Times(1),
				)
				c.UpdateAuth(gomock.Any(), mockBasic).Return(nil).Times(1)
				c.UpdateAuth(gomock.Any(), mockRotatedBasic).Return(nil).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
			},
		},
		{
			name: "push again to a restarted daemon",
			mock: func(k *mocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				restarted := *mockInstance
				restarted.CreatedAt = mockInstance.CreatedAt.Add(time.Hour)
				gomock.InOrder(
					s.GetInstance(mockInstance.ChainID).Return(mockInstance, nil).Times(1),
					s.GetInstance(mockInstance.ChainID).Return(&restarted, nil).Times(1),
				)
				k.Resolve(gomock.Any(), gomock.Any()).Return(mockBasic, nil).Times(2)
				c.UpdateAuth(gomock.Any(), mockBasic).Return(nil).Times(2)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
			},
		},
		{
			name: "keep credential when none is left",
			mock: func(k *mocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(mockInstance, nil).Times(1)
				k.Resolve(gomock.Any(), gomock.Any()).Return("", nil).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert.NoError(t, p.push(t.Context(), mockInstance.ChainID))
			},
		},
		{
			name: "forget removed instance",
			mock: func(k *mocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
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
			mock: func(k *mocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(nil, errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert.EqualError(t, p.push(t.Context(), mockInstance.ChainID), "foo")
			},
		},
		{
			name: "skip invalid image reference",
			mock: func(k *mocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				invalid := *mockInstance
				invalid.ImageRef = "Registry.example.com/APP"
				s.GetInstance(mockInstance.ChainID).Return(&invalid, nil).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert.NoError(t, p.push(t.Context(), mockInstance.ChainID))
			},
		},
		{
			name: "skip unresolvable credential",
			mock: func(k *mocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(mockInstance, nil).Times(1)
				k.Resolve(gomock.Any(), gomock.Any()).Return("", errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert.NoError(t, p.push(t.Context(), mockInstance.ChainID))
			},
		},
		{
			name: "daemon without the auth route",
			mock: func(k *mocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(mockInstance, nil).Times(1)
				k.Resolve(gomock.Any(), gomock.Any()).Return(mockBasic, nil).Times(1)
				c.UpdateAuth(gomock.Any(), mockBasic).Return(fmt.Errorf("404: %w", errdefs.ErrNotImplemented)).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				unsupported := counterValue(t, resultUnsupported)
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
				assert.Equal(unsupported+1, counterValue(t, resultUnsupported))
				assert.Empty(p.pushed)
			},
		},
		{
			name: "drop credential the daemon rejects",
			mock: func(k *mocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(mockInstance, nil).Times(1)
				k.Resolve(gomock.Any(), gomock.Any()).Return(mockBasic, nil).Times(1)
				c.UpdateAuth(gomock.Any(), mockBasic).Return(fmt.Errorf("400: %w", errdefs.ErrInvalidArgument)).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				failure := counterValue(t, resultFailure)
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
				assert.Equal(failure+1, counterValue(t, resultFailure))
				assert.Empty(p.pushed)
			},
		},
		{
			name: "skip a stopped daemon",
			mock: func(k *mocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(mockInstance, nil).Times(1)
				k.Resolve(gomock.Any(), gomock.Any()).Return(mockBasic, nil).Times(1)
				c.UpdateAuth(gomock.Any(), mockBasic).Return(fmt.Errorf("dial: %w", syscall.ECONNREFUSED)).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				assert.NoError(p.push(t.Context(), mockInstance.ChainID))
				assert.Empty(p.pushed)
			},
		},
		{
			name: "retry failed push",
			mock: func(k *mocks.MockKeychainMockRecorder, s *storemocks.MockStoreMockRecorder, c *nydusdmocks.MockClientMockRecorder) {
				s.GetInstance(mockInstance.ChainID).Return(mockInstance, nil).Times(1)
				k.Resolve(gomock.Any(), gomock.Any()).Return(mockBasic, nil).Times(1)
				c.UpdateAuth(gomock.Any(), mockBasic).Return(errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				failure := counterValue(t, resultFailure)
				assert.EqualError(p.push(t.Context(), mockInstance.ChainID), "foo")
				assert.Equal(failure+1, counterValue(t, resultFailure))
				assert.Empty(p.pushed)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			keychain := mocks.NewMockKeychain(ctl)
			instances := storemocks.NewMockStore(ctl)
			client := nydusdmocks.NewMockClient(ctl)
			tc.mock(keychain.EXPECT(), instances.EXPECT(), client.EXPECT())

			p := newPusher(keychain, instances)
			defer p.queue.ShutDown()
			p.newClient = func(string) nydusd.Client { return client }
			tc.expect(t, p)
		})
	}
}

func TestPusher_enqueue(t *testing.T) {
	tests := []struct {
		name   string
		keys   []string
		mock   func(s *storemocks.MockStoreMockRecorder)
		expect func(t *testing.T, p *pusher)
	}{
		{
			name: "queue instances of the key host",
			keys: []string{"registry.example.com/team"},
			mock: func(s *storemocks.MockStoreMockRecorder) {
				s.ListInstances().Return([]*store.Instance{mockInstance, mockOtherInstance}, nil).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				assert.Equal(1, p.queue.Len())
				chainID, _ := p.queue.Get()
				assert.Equal(mockInstance.ChainID, chainID)
			},
		},
		{
			name: "queue instances of a wildcard key",
			keys: []string{"*.example.com"},
			mock: func(s *storemocks.MockStoreMockRecorder) {
				s.ListInstances().Return([]*store.Instance{mockInstance, mockOtherInstance}, nil).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert.Equal(t, 2, p.queue.Len())
			},
		},
		{
			name: "queue docker hub instances",
			keys: []string{"docker.io"},
			mock: func(s *storemocks.MockStoreMockRecorder) {
				s.ListInstances().Return([]*store.Instance{mockInstance, mockDockerHubInstance}, nil).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert := assert.New(t)
				assert.Equal(1, p.queue.Len())
				chainID, _ := p.queue.Get()
				assert.Equal(mockDockerHubInstance.ChainID, chainID)
			},
		},
		{
			name: "no instance of the key host",
			keys: []string{"registry.example.com:5000"},
			mock: func(s *storemocks.MockStoreMockRecorder) {
				s.ListInstances().Return([]*store.Instance{mockInstance}, nil).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert.Equal(t, 0, p.queue.Len())
			},
		},
		{
			name: "store failure",
			keys: []string{"registry.example.com"},
			mock: func(s *storemocks.MockStoreMockRecorder) {
				s.ListInstances().Return(nil, errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, p *pusher) {
				assert.Equal(t, 0, p.queue.Len())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			instances := storemocks.NewMockStore(ctl)
			tc.mock(instances.EXPECT())

			p := newPusher(mocks.NewMockKeychain(ctl), instances)
			defer p.queue.ShutDown()
			p.enqueue(tc.keys)
			tc.expect(t, p)
		})
	}
}
