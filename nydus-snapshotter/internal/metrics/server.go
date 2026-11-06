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
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	// readHeaderTimeout bounds reading request headers.
	readHeaderTimeout = 10 * time.Second

	// shutdownTimeout bounds draining requests on stop.
	shutdownTimeout = 10 * time.Second
)

// Server serves /metrics, /livez and /readyz.
type Server struct {
	// server is the HTTP server.
	server *http.Server

	// listener is the bound listener.
	listener net.Listener
}

// NewServer binds addr. ready answers /readyz; /livez only proves the
// process serves HTTP, so it never depends on the API server.
func NewServer(addr string, ready func() error) (*Server, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen metrics %s: %w", addr, err)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.Handler())
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		// A failed write means the client went away; nothing is left to do.
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if err := ready(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		// A failed write means the client went away; nothing is left to do.
		_, _ = w.Write([]byte("ok\n"))
	})

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
