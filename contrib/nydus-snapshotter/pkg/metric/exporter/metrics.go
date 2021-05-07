/*
 * Copyright (c) 2021. Alibaba Cloud. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package exporter

import (
	"time"

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/metric/ttl"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/nydussdk/model"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	imageRefLabel = "image_ref"
	defaultTTL    = 3 * time.Minute
)

var (
	// Counters
	ReadCount = ttl.NewGaugeVecWithTTL(
		prometheus.GaugeOpts{
			Name: "nydusd_read_count",
			Help: "Total number read of a nydus fs, in Byte.",
		},
		[]string{imageRefLabel},
		defaultTTL,
	)

	OpenFdCount = ttl.NewGaugeVecWithTTL(
		prometheus.GaugeOpts{
			Name: "nydusd_open_fd_count",
			Help: "Number of current open files.",
		},
		[]string{imageRefLabel},
		defaultTTL,
	)

	OpenFdMaxCount = ttl.NewGaugeVecWithTTL(
		prometheus.GaugeOpts{
			Name: "nydusd_open_fd_max_count",
			Help: "Number of max open files.",
		},
		[]string{imageRefLabel},
		defaultTTL,
	)

	LastFopTimestamp = ttl.NewGaugeVecWithTTL(
		prometheus.GaugeOpts{
			Name: "nydusd_last_fop_timestamp",
			Help: "Timestamp of last file operation.",
		},
		[]string{imageRefLabel},
		defaultTTL,
	)
)

// Fs metric histograms
var FsMetricHists = []*FsMetricHistogram{
	{
		Desc: prometheus.NewDesc(
			"nydusd_block_count_read_hist",
			"Read size histogram, in 1KB, 4KB, 16KB, 64KB, 128KB, 512K, 1024K.",
			[]string{imageRefLabel},
			prometheus.Labels{},
		),
		Buckets: []uint64{1, 4, 16, 64, 128, 512, 1024, 2048},
		GetCounters: func(m *model.FsMetric) []uint64 {
			return m.BlockCountRead
		},
	},

	{
		Desc: prometheus.NewDesc(
			"nydusd_fop_hit_hist",
			"File operations histogram",
			[]string{imageRefLabel},
			prometheus.Labels{},
		),
		Buckets: MakeFopBuckets(),
		GetCounters: func(m *model.FsMetric) []uint64 {
			return m.FopHits
		},
	},

	{
		Desc: prometheus.NewDesc(
			"nydusd_fop_errors_hist",
			"File operations' error histogram",
			[]string{imageRefLabel},
			prometheus.Labels{},
		),
		Buckets: MakeFopBuckets(),
		GetCounters: func(m *model.FsMetric) []uint64 {
			return m.FopErrors
		},
	},

	{
		Desc: prometheus.NewDesc(
			"nydusd_read_latency_hist",
			"Read latency histogram, in microseconds",
			[]string{imageRefLabel},
			prometheus.Labels{},
		),
		Buckets: []uint64{1, 20, 50, 100, 500, 1000, 2000, 4000},
		GetCounters: func(m *model.FsMetric) []uint64 {
			return m.ReadLatencyDist
		},
	},
}
