/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package metrics holds the snapshotter's Prometheus collectors and serves
// them, refer to https://prometheus.io/docs/practices/naming/.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	// namespace prefixes every metric.
	namespace = "nydus_snapshotter"

	// labelResult is the outcome label.
	labelResult = "result"

	// labelReason is the eviction reason label.
	labelReason = "reason"

	// ResultSuccess is the result of a credential update a daemon accepted.
	ResultSuccess = "success"

	// ResultFailure is the result of a credential update a daemon rejected
	// or that failed.
	ResultFailure = "failure"

	// ResultUnsupported is the result of a credential update for a daemon
	// that takes none.
	ResultUnsupported = "unsupported"

	// ReasonOrphan is the reason for evicting a blob no bootstrap references.
	ReasonOrphan = "orphan"

	// ReasonTTL is the reason for evicting a blob unused for longer than the
	// TTL.
	ReasonTTL = "ttl"

	// ReasonWatermark is the reason for evicting a least recently used blob
	// over the high watermark.
	ReasonWatermark = "watermark"
)

var (
	// DaemonStartDuration observes how long a daemon takes to become ready.
	DaemonStartDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: "daemon",
		Name:      "start_duration_seconds",
		Help:      "Time for a nydus daemon to start and become ready.",
		Buckets:   prometheus.ExponentialBuckets(0.05, 2, 10),
	})

	// DaemonStartsTotal counts attempted daemon starts, the denominator of
	// DaemonStartFailuresTotal, refer to
	// https://prometheus.io/docs/practices/instrumentation/#failures.
	DaemonStartsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "daemon",
		Name:      "starts_total",
		Help:      "Number of nydus daemon starts attempted.",
	})

	// DaemonStartFailuresTotal counts daemons that failed to start.
	DaemonStartFailuresTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "daemon",
		Name:      "start_failures_total",
		Help:      "Number of nydus daemons that failed to start.",
	})

	// DaemonUnexpectedExitsTotal counts daemons that exited while snapshots
	// still used them.
	DaemonUnexpectedExitsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "daemon",
		Name:      "unexpected_exits_total",
		Help:      "Number of nydus daemons found exited while still in use.",
	})

	// RunningDaemons is the number of running daemons.
	RunningDaemons = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "running_daemons",
		Help:      "Number of running nydus daemons.",
	})

	// UnresponsiveDaemons is the number of running daemons whose mount is
	// gone or whose API did not answer the last health check.
	UnresponsiveDaemons = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "unresponsive_daemons",
		Help:      "Number of running nydus daemons that failed the last health check.",
	})

	// AuthUpdatesTotal counts credential pushes to daemons by result:
	// success, failure or unsupported.
	AuthUpdatesTotal = newCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "auth",
		Name:      "updates_total",
		Help:      "Number of credential updates pushed to nydus daemons.",
	}, labelResult, ResultSuccess, ResultFailure, ResultUnsupported)

	// CacheEvictedBytesTotal counts bytes evicted from the blob cache by
	// reason: ttl, watermark or orphan.
	CacheEvictedBytesTotal = newCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "cache",
		Name:      "evicted_bytes_total",
		Help:      "Bytes evicted from the blob cache.",
	}, labelReason, ReasonTTL, ReasonWatermark, ReasonOrphan)
)

// newCounterVec returns a registered counter vector of one label whose known
// values start at 0, so a series that has not counted yet reads 0 and not
// absent, refer to
// https://prometheus.io/docs/practices/instrumentation/#avoid-missing-metrics.
func newCounterVec(opts prometheus.CounterOpts, label string, values ...string) *prometheus.CounterVec {
	counter := promauto.NewCounterVec(opts, []string{label})
	for _, value := range values {
		counter.WithLabelValues(value)
	}

	return counter
}
