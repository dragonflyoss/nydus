/*
 * Copyright (c) 2021. Alibaba Cloud. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package exporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/pkg/errors"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/nydussdk/model"
)

type Opt func(*Exporter) error

type Exporter struct {
	outputFile string
}

func WithOutputFile(metricsFile string) Opt {
	return func(e *Exporter) error {
		if metricsFile == "" {
			return errors.New("metrics file path is empty")
		}

		if _, err := os.Create(metricsFile); err != nil {
			return errors.Wrapf(err, "failed to create metrics file: %s", metricsFile)
		}
		e.outputFile = metricsFile
		return nil
	}
}

func NewExporter(opts ...Opt) (*Exporter, error) {
	var exp Exporter

	for _, o := range opts {
		if err := o(&exp); err != nil {
			return nil, err
		}
	}

	return &exp, nil
}

func (e *Exporter) ExportFsMetrics(m *model.FsMetric, imageRef string) error {
	ReadCount.WithLabelValues(imageRef).Set(float64(m.DataRead))
	OpenFdCount.WithLabelValues(imageRef).Set(float64(m.NrOpens))
	OpenFdMaxCount.WithLabelValues(imageRef).Set(float64(m.NrMaxOpens))
	LastFopTimestamp.WithLabelValues(imageRef).Set(float64(m.LastFopTp))

	for _, h := range FsMetricHists {
		o, err := h.ToConstHistogram(m, imageRef)
		if err != nil {
			return errors.Wrapf(err, "failed to new const histogram for %s", h.Desc.String())
		}
		h.Save(o)
	}

	return e.output()
}

func (e *Exporter) output() error {
	ms, err := Registry.Gather()
	if err != nil {
		return errors.Wrap(err, "failed to gather all prometheus collectors")
	}
	for _, m := range ms {
		if err := e.exportText(m); err != nil {
			return errors.Wrapf(err, "failed to export text metrics")
		}
	}

	return nil
}

func (e *Exporter) exportText(m *dto.MetricFamily) error {
	var b bytes.Buffer

	enc := expfmt.NewEncoder(&b, expfmt.FmtText)
	if err := enc.Encode(m); err != nil {
		return errors.Wrapf(err, "failed to encode metrics for %v", m)
	}

	data := map[string]string{
		"time":    time.Now().Format(time.RFC3339),
		"metrics": (&b).String(),
	}
	json, err := json.Marshal(data)
	if err != nil {
		return errors.Wrapf(err, "failed to marshal data for %v", data)
	}
	return e.writeToFile(string(json))
}

func (e *Exporter) writeToFile(data string) error {
	f, err := os.OpenFile(e.outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return errors.Wrapf(err, "failed to open metrics file on %s", e.outputFile)
	}
	defer f.Close()

	if _, err := f.WriteString(fmt.Sprintf("%s\n", data)); err != nil {
		return err
	}

	return nil
}
