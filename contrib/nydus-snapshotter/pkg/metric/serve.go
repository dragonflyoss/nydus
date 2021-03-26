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

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"
)

type ServerOpt func(*Server) error

const sockFileName = "metrics.sock"

type Server struct {
	listener     net.Listener
	SockPath     string
	exportToFile bool
}

func WithSockPath(rootDir string) ServerOpt {
	return func(s *Server) error {
		s.SockPath = filepath.Join(rootDir, sockFileName)
		return nil
	}
}

func WithExportToFile(toFile bool) ServerOpt {
	return func(s *Server) error {
		s.exportToFile = toFile
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

	if _, err := os.Stat(s.SockPath); err == nil {
		err = os.Remove(s.SockPath)
		if err != nil {
			return nil, err
		}
	}
	ln, err := NewListener(s.SockPath)
	if err != nil {
		return nil, err
	}
	s.listener = ln

	return &s, nil
}

func (s *Server) Serve(ctx context.Context, stop <-chan struct{}) error {
	handler := promhttp.HandlerFor(Registry, promhttp.HandlerOpts{
		ErrorHandling: promhttp.HTTPErrorOnError,
	})
	mux := http.NewServeMux()
	mux.Handle("/metrics", handler)
	server := http.Server{
		Handler: mux,
	}

	// Run the server
	errs, ctx := errgroup.WithContext(ctx)
	errs.Go(func() error {
		return server.Serve(s.listener)
	})
	if err := errs.Wait(); err != nil {
		return errors.Wrap(err, "failed to start metrics server")
	}

	// Shutdown the server when stop is closed
	select {
	case <-stop:
		if err := server.Shutdown(context.Background()); err != nil {
			return errors.Wrap(err, "failed to shutdown metric server")
		}
	}

	return nil
}
