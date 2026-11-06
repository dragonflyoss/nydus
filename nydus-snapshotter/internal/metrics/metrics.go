/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package metrics holds the snapshotter's Prometheus collectors and serves
// them with the health endpoints, refer to
// https://prometheus.io/docs/practices/naming/ and
// https://kubernetes.io/docs/reference/using-api/health-checks/.
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

	// DaemonStartFailureTotal counts daemons that failed to start.
	DaemonStartFailureTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "daemon",
		Name:      "start_failure_total",
		Help:      "Number of nydus daemons that failed to start.",
	})

	// DaemonUnexpectedExitTotal counts daemons that exited while snapshots
	// still used them.
	DaemonUnexpectedExitTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "daemon",
		Name:      "unexpected_exit_total",
		Help:      "Number of nydus daemons found exited while still in use.",
	})

	// DaemonRunning is the number of running daemons.
	DaemonRunning = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "daemon",
		Name:      "running",
		Help:      "Number of running nydus daemons.",
	})

	// AuthUpdateTotal counts credential pushes to daemons by result:
	// success, failure or unsupported.
	AuthUpdateTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "auth",
		Name:      "update_total",
		Help:      "Number of credential updates pushed to nydus daemons.",
	}, []string{labelResult})

	// CacheEvictedBytesTotal counts bytes evicted from the blob cache by
	// reason: ttl, watermark or orphan.
	CacheEvictedBytesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "cache",
		Name:      "evicted_bytes_total",
		Help:      "Bytes evicted from the blob cache.",
	}, []string{labelReason})
)
