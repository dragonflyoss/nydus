/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/proto"

	authmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/auth/mocks"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/kmutex"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/nydusd"
	nydusdmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/nydusd/mocks"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/registry"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store"
	systemdmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd/mocks"
)

func mockCounterFamilies(value float64) map[string]*dto.MetricFamily {
	return map[string]*dto.MetricFamily{
		"nydus_backend_read_total": {
			Name:   proto.String("nydus_backend_read_total"),
			Help:   proto.String("Backend reads."),
			Type:   dto.MetricType_COUNTER.Enum(),
			Metric: []*dto.Metric{{Counter: &dto.Counter{Value: proto.Float64(value)}}},
		},
	}
}

func TestFileSystem_Gather(t *testing.T) {
	tests := []struct {
		name      string
		instances []*store.Instance
		closed    bool
		mock      func(m, other *nydusdmocks.MockClientMockRecorder)
		expect    func(t *testing.T, families []*dto.MetricFamily, values map[string]float64, err error)
	}{
		{
			name:      "label the metrics of every daemon",
			instances: []*store.Instance{mockInstance, mockOtherInstance},
			mock: func(m, other *nydusdmocks.MockClientMockRecorder) {
				m.Metrics(gomock.Any()).Return(mockCounterFamilies(3), nil).Times(1)
				other.Metrics(gomock.Any()).Return(mockCounterFamilies(5), nil).Times(1)
			},
			expect: func(t *testing.T, families []*dto.MetricFamily, values map[string]float64, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Len(families, 1)
				assert.Equal("nydus_backend_read_total", families[0].GetName())
				assert.Equal(dto.MetricType_COUNTER, families[0].GetType())
				assert.Equal(map[string]float64{
					mockInstance.ChainID + " " + mockInstance.ImageRef:           3,
					mockOtherInstance.ChainID + " " + mockOtherInstance.ImageRef: 5,
				}, values)
			},
		},
		{
			name:      "leave out a daemon that does not answer",
			instances: []*store.Instance{mockInstance, mockOtherInstance},
			mock: func(m, other *nydusdmocks.MockClientMockRecorder) {
				m.Metrics(gomock.Any()).Return(mockCounterFamilies(3), nil).Times(1)
				other.Metrics(gomock.Any()).Return(nil, errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, families []*dto.MetricFamily, values map[string]float64, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Len(families, 1)
				assert.Equal(map[string]float64{mockInstance.ChainID + " " + mockInstance.ImageRef: 3}, values)
			},
		},
		{
			name:      "keep the family of the first daemon when two disagree on its type",
			instances: []*store.Instance{mockInstance, mockOtherInstance},
			mock: func(m, other *nydusdmocks.MockClientMockRecorder) {
				m.Metrics(gomock.Any()).Return(mockCounterFamilies(3), nil).Times(1)
				other.Metrics(gomock.Any()).Return(map[string]*dto.MetricFamily{
					"nydus_backend_read_total": {
						Name:   proto.String("nydus_backend_read_total"),
						Type:   dto.MetricType_GAUGE.Enum(),
						Metric: []*dto.Metric{{Gauge: &dto.Gauge{Value: proto.Float64(5)}}},
					},
				}, nil).Times(1)
			},
			expect: func(t *testing.T, families []*dto.MetricFamily, values map[string]float64, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Len(families, 1)
				assert.Equal(map[string]float64{mockInstance.ChainID + " " + mockInstance.ImageRef: 3}, values)
			},
		},
		{
			name:      "return the families sorted by name",
			instances: []*store.Instance{mockInstance},
			mock: func(m, other *nydusdmocks.MockClientMockRecorder) {
				families := map[string]*dto.MetricFamily{}
				for _, name := range []string{"nydus_e", "nydus_c", "nydus_a", "nydus_d", "nydus_b", "nydus_f"} {
					families[name] = &dto.MetricFamily{Name: proto.String(name), Type: dto.MetricType_COUNTER.Enum()}
				}

				m.Metrics(gomock.Any()).Return(families, nil).Times(1)
			},
			expect: func(t *testing.T, families []*dto.MetricFamily, values map[string]float64, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				names := make([]string, 0, len(families))
				for _, family := range families {
					names = append(names, family.GetName())
				}

				assert.Equal([]string{"nydus_a", "nydus_b", "nydus_c", "nydus_d", "nydus_e", "nydus_f"}, names)
			},
		},
		{
			name: "no daemon",
			mock: func(m, other *nydusdmocks.MockClientMockRecorder) {},
			expect: func(t *testing.T, families []*dto.MetricFamily, values map[string]float64, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(families)
			},
		},
		{
			name:      "records that cannot be read",
			instances: []*store.Instance{mockInstance},
			closed:    true,
			mock:      func(m, other *nydusdmocks.MockClientMockRecorder) {},
			expect: func(t *testing.T, families []*dto.MetricFamily, values map[string]float64, err error) {
				assert := assert.New(t)
				assert.Error(err)
				assert.Nil(families)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			client := nydusdmocks.NewMockClient(ctl)
			other := nydusdmocks.NewMockClient(ctl)
			tc.mock(client.EXPECT(), other.EXPECT())

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
				systemd:  systemdmocks.NewMockSystemd(ctl),
				store:    s,
				keychain: authmocks.NewMockKeychain(ctl),
				hosts:    registry.NewHosts(""),
				driver:   NewMockDriver(ctl),
				newClient: func(socket string) nydusd.Client {
					if socket == mockOtherInstance.APISocket {
						return other
					}

					return client
				},
				locker:    kmutex.New(),
				startLock: &sync.Mutex{},
				preheats:  newPreheatQueue(cfg.Preheat.MaxConcurrentImages),
			}
			f.cfg.Store(cfg)

			for _, instance := range tc.instances {
				assert.NoError(t, f.store.PutInstance(instance))
			}

			if tc.closed {
				assert.NoError(t, f.store.Close())
			}

			families, err := f.Gather()
			values := map[string]float64{}
			for _, family := range families {
				for _, metric := range family.GetMetric() {
					labels := make([]string, 0, len(metric.GetLabel()))
					for _, label := range metric.GetLabel() {
						labels = append(labels, label.GetValue())
					}

					values[strings.Join(labels, " ")] = metric.GetCounter().GetValue()
				}
			}

			tc.expect(t, families, values, err)
		})
	}
}
