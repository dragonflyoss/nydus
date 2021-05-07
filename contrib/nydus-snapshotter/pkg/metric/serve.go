/*
 * Copyright (c) 2021. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package metrics

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/containerd/containerd/log"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/daemon"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/metric/exporter"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/nydussdk"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/process"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type ServerOpt func(*Server) error

const sockFileName = "metrics.sock"

type Server struct {
	listener    net.Listener
	rootDir     string
	metricsFile string
	pm          *process.Manager
	exp         *exporter.Exporter
}

func WithRootDir(rootDir string) ServerOpt {
	return func(s *Server) error {
		s.rootDir = rootDir
		return nil
	}
}

func WithMetricsFile(metricsFile string) ServerOpt {
	return func(s *Server) error {
		if s.rootDir == "" {
			return errors.New("root dir is required")
		}

		if metricsFile == "" {
			metricsFile = filepath.Join(s.rootDir, "metrics.log")
		}

		s.metricsFile = metricsFile
		return nil
	}
}

func WithProcessManager(pm *process.Manager) ServerOpt {
	return func(s *Server) error {
		s.pm = pm
		return nil
	}
}

func NewServer(ctx context.Context, opts ...ServerOpt) (*Server, error) {
	var s Server
	for _, o := range opts {
		if err := o(&s); err != nil {
			return nil, err
		}
	}

	exp, err := exporter.NewExporter(
		exporter.WithOutputFile(s.metricsFile),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to new metric exporter")
	}
	s.exp = exp

	sockPath := filepath.Join(s.rootDir, sockFileName)

	if _, err := os.Stat(sockPath); err == nil {
		err = os.Remove(sockPath)
		if err != nil {
			return nil, err
		}
	}
	ln, err := NewListener(sockPath)
	if err != nil {
		return nil, err
	}
	s.listener = ln

	log.G(ctx).Infof("Starting metrics server on %s", sockPath)

	return &s, nil
}

func (s *Server) collectDaemonMetric(ctx context.Context) error {
	// TODO(renzhen): make collect interval time configurable
	timer := time.NewTicker(time.Duration(1) * time.Minute)

outer:
	for {
		select {
		case <-timer.C:
			daemons := s.pm.ListDaemons()
			for _, d := range daemons {
				if d.ID == daemon.SharedNydusDaemonID {
					continue
				}

				client, err := nydussdk.NewNydusClient(d.APISock())
				if err != nil {
					log.G(ctx).Errorf("failed to connect nydusd: %v", err)
					continue
				}

				fsMetrics, err := client.GetFsMetric(s.pm.IsSharedDaemon(), d.SnapshotID)
				if err != nil {
					log.G(ctx).Errorf("failed to get fs metric: %v", err)
					continue
				}

				if err := s.exp.ExportFsMetrics(fsMetrics, d.ImageID); err != nil {
					log.G(ctx).Errorf("failed to export fs metrics for %s: %v", d.ImageID, err)
					continue
				}
			}
		case <-ctx.Done():
			log.G(ctx).Infof("cancel daemon metrics collecting")
			break outer
		}
	}

	return nil
}

func (s *Server) Serve(ctx context.Context) error {
	handler := promhttp.HandlerFor(exporter.Registry, promhttp.HandlerOpts{
		ErrorHandling: promhttp.HTTPErrorOnError,
	})
	mux := http.NewServeMux()
	mux.Handle("/metrics", handler)
	server := http.Server{
		Handler: mux,
	}

	// Process manager starts to collect metrics from daemons periodically.
	go func() {
		if err := s.collectDaemonMetric(ctx); err != nil {
			log.G(ctx).Errorf("failed to collect daemon metric, err: %v", err)
		}
	}()

	// Shutdown the server when stop is closed
	go func() {
		sig := <-ctx.Done()
		log.G(ctx).Infof("caught signal %s: shutting down", sig)
		if err := server.Shutdown(context.Background()); err != nil {
			log.G(ctx).Errorf("failed to shutdown metric server, err: %v", err)
		}
	}()

	// Run the server
	return errors.Wrap(server.Serve(s.listener), "failed to start metrics server")
}
