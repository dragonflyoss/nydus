// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type Exporter interface {
	Export()
}

const (
	convertDurationKey    = "convert_duration_key"
	convertCountKey       = "convert_count_key"
	storeCacheDurationKey = "store_cache_duration"
	namespace             = "nydusify"
	subsystem             = "convert"
)

var (
	convertDuration = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      convertDurationKey,
			Help:      "The total duration of converting an OCI image. Broken down by source references/repo and layers count.",
		},
		[]string{"source_reference", "layers_count"},
	)

	convertCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      convertCountKey,
			Help:      "The total converting times. Broken down by source references.",
		},
		[]string{"source_reference"},
	)

	storeCacheDuration = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      storeCacheDurationKey,
			Help:      "The duration of pushing cache to registry. Broken down by source references.",
		},
		[]string{"source_reference"},
	)
)

var register sync.Once
var Registry *prometheus.Registry
var exporter Exporter

func sinceInSeconds(start time.Time) float64 {
	return time.Since(start).Seconds()
}

// Register registers metrics. This is always called only once.
func Register(exp Exporter) {
	register.Do(func() {
		Registry = prometheus.NewRegistry()
		Registry.MustRegister(convertDuration, convertCount, storeCacheDuration)
		exporter = exp
	})
}

func Export() {
	exporter.Export()
}

func ConversionDuration(ref string, layers int, start time.Time) {
	convertDuration.WithLabelValues(ref, strconv.Itoa(layers)).Add(sinceInSeconds(start))
}

func ConversionCount(ref string) {
	convertCount.WithLabelValues(ref).Inc()
}

func StoreCacheDuration(ref string, start time.Time) {
	storeCacheDuration.WithLabelValues(ref).Add(sinceInSeconds(start))
}
