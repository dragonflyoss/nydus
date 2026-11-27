/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"time"

	"github.com/containerd/log"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/proto"
	"k8s.io/client-go/util/workqueue"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store"
)

const (
	// gatherTimeout bounds reading the metrics of every daemon, within
	// Prometheus's default scrape timeout of 10s.
	gatherTimeout = 8 * time.Second

	// labelChainID is the label holding the chain ID of a daemon's image,
	// which tells apart two daemons of one image reference.
	labelChainID = "chain_id"

	// labelImage is the label holding the image reference of a daemon.
	labelImage = "image"
)

// Gather returns the metrics of every recorded daemon, each labelled with the
// chain ID and the image of its daemon. Prometheus cannot reach the daemons'
// sockets, so the snapshotter serves their metrics beside its own. A daemon
// that does not answer is left out.
func (f *fileSystem) Gather() ([]*dto.MetricFamily, error) {
	instances, err := f.store.ListInstances()
	if err != nil {
		return nil, err
	}

	// A Gatherer takes no context, so the scrape is bounded here.
	ctx, cancel := context.WithTimeout(context.Background(), gatherTimeout)
	defer cancel()

	scraped := make([]map[string]*dto.MetricFamily, len(instances))
	workqueue.ParallelizeUntil(ctx, daemonConcurrency, len(instances), func(i int) {
		families, err := f.newClient(instances[i].APISocket).Metrics(ctx)
		if err != nil {
			log.G(ctx).WithError(err).WithField("unit", instances[i].Unit).Debug("skip the metrics of a daemon")
			return
		}

		scraped[i] = families
	})

	merged := map[string]*dto.MetricFamily{}
	for i, families := range scraped {
		f.mergeMetricFamilies(merged, families, instances[i])
	}

	// A Gatherer returns its families sorted by name.
	return slices.SortedFunc(maps.Values(merged), func(a, b *dto.MetricFamily) int {
		return cmp.Compare(a.GetName(), b.GetName())
	}), nil
}

// mergeMetricFamilies adds the metric families of one daemon to merged, every
// metric labelled with the chain ID and the image of the daemon.
func (f *fileSystem) mergeMetricFamilies(merged, families map[string]*dto.MetricFamily, instance *store.Instance) {
	for name, family := range families {
		into, ok := merged[name]
		if !ok {
			into = &dto.MetricFamily{Name: family.Name, Help: family.Help, Type: family.Type}
			merged[name] = into
		}

		// Daemons of two nydus versions may disagree on a family; the first
		// one read defines it.
		if into.GetType() != family.GetType() {
			continue
		}

		for _, metric := range family.GetMetric() {
			metric.Label = append(metric.Label,
				&dto.LabelPair{Name: proto.String(labelChainID), Value: proto.String(instance.ChainID)},
				&dto.LabelPair{Name: proto.String(labelImage), Value: proto.String(instance.ImageRef)},
			)
			slices.SortFunc(metric.Label, func(a, b *dto.LabelPair) int {
				return cmp.Compare(a.GetName(), b.GetName())
			})
			into.Metric = append(into.Metric, metric)
		}
	}
}
