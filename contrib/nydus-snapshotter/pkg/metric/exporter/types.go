/*
 * Copyright (c) 2021. Alibaba Cloud. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package exporter

import (
	"fmt"

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/nydussdk/model"
	"github.com/prometheus/client_golang/prometheus"
)

type Fop int

const (
	Getattr = iota
	Readlink
	Open
	Release
	Read
	Statfs
	Getxattr
	Listxattr
	Opendir
	Lookup
	Readdir
	Readdirplus
	Access
	Forget
	BatchForget

	MaxFops
)

func GetMaxFops() uint {
	return MaxFops
}

func MakeFopBuckets() []uint64 {
	s := make([]uint64, 0, MaxFops)
	for i := 0; i < MaxFops; i++ {
		s = append(s, uint64(i))
	}

	return s
}

type GetCountersFn func(*model.FsMetric) []uint64

type FsMetricHistogram struct {
	Desc        *prometheus.Desc
	Buckets     []uint64
	GetCounters GetCountersFn

	// Save the last generated histogram metric
	constHist prometheus.Metric
}

func (h *FsMetricHistogram) ToConstHistogram(m *model.FsMetric, imageRef string) (prometheus.Metric, error) {
	var count, sum uint64
	counters := h.GetCounters(m)
	hmap := make(map[float64]uint64)

	if len(counters) != len(h.Buckets) {
		return nil, fmt.Errorf("length of counters(%d) and buckets(%d) not equal: %+v", len(counters), len(h.Buckets), h.Buckets)
	}

	for i, c := range counters {
		count += c
		sum = sum + h.Buckets[i]*c
		hmap[float64(h.Buckets[i])] = c
	}

	return prometheus.MustNewConstHistogram(
		h.Desc,
		count, float64(sum),
		hmap,
		imageRef,
	), nil
}

func (h *FsMetricHistogram) Save(m prometheus.Metric) {
	h.constHist = m
}

// Implement prometheus.Collector interface
func (h *FsMetricHistogram) Describe(ch chan<- *prometheus.Desc) {
	if h.Desc != nil {
		ch <- h.Desc
	}
}

func (h *FsMetricHistogram) Collect(ch chan<- prometheus.Metric) {
	if h.constHist != nil {
		ch <- h.constHist
	}
}
