// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package file_exporter

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/metrics"
)

type FileExporter struct{ name string }

func New(name string) *FileExporter {
	return &FileExporter{
		name: name,
	}
}

func (exp *FileExporter) Export() {
	prometheus.WriteToTextfile(exp.name, metrics.Registry)
}
