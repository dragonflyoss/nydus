/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package metrics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/containerd/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	// readHeaderTimeout bounds reading request headers.
	readHeaderTimeout = 10 * time.Second

	// shutdownTimeout bounds draining requests on stop.
	shutdownTimeout = 10 * time.Second
)

// Server serves /metrics.
type Server struct {
	// server is the HTTP server.
	server *http.Server

	// listener is the bound listener.
	listener net.Listener
}

// NewServer returns a server listening on addr. /metrics serves the
// snapshotter's own metrics and those the daemons gatherer returns.
func NewServer(addr string, daemons prometheus.Gatherer) (*Server, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen metrics %s: %w", addr, err)
	}

	mux := http.NewServeMux()
	// Serve what gathers and log the rest, so one daemon whose metrics
	// clash never costs the scrape of every other metric.
	mux.Handle("GET /metrics", promhttp.HandlerFor(prometheus.Gatherers{prometheus.DefaultGatherer, daemons}, promhttp.HandlerOpts{
		ErrorLog:      log.L,
		ErrorHandling: promhttp.ContinueOnError,
	}))

	return &Server{
		server: &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: readHeaderTimeout,
		},
		listener: listener,
	}, nil
}

// Serve serves until Stop.
func (s *Server) Serve() error {
	if err := s.server.Serve(s.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

// Stop shuts the server down, closing the listener even if Serve never ran.
func (s *Server) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := s.server.Shutdown(ctx); err != nil {
		log.G(ctx).WithError(err).Warn("shut down metrics server")
	}

	if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.G(ctx).WithError(err).Warn("close metrics listener")
	}
}
