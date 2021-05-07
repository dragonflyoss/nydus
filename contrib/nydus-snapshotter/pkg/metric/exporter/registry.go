/*
 * Copyright (c) 2021. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package exporter

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	Registry = prometheus.NewRegistry()
)

func init() {
	Registry.MustRegister(
		ReadCount,
		OpenFdCount,
		OpenFdMaxCount,
		LastFopTimestamp,
	)

	for _, m := range FsMetricHists {
		Registry.MustRegister(m)
	}
}
