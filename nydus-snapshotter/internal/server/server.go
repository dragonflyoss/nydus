/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package server wires the snapshotter together and serves it to containerd
// over gRPC as a proxy plugin.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	nydussnapshotterv1 "d7y.io/api/v2/pkg/apis/nydussnapshotter/v1"
	snapshotsapi "github.com/containerd/containerd/api/services/snapshots/v1"
	"github.com/containerd/containerd/v2/contrib/snapshotservice"
	"github.com/containerd/containerd/v2/defaults"
	"github.com/containerd/log"
	sddaemon "github.com/coreos/go-systemd/v22/daemon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/auth"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/cache"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/fs"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/metrics"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/preheat"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/snapshot"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd"
)

const (
	// gracefulStopTimeout is how long in-flight gRPC calls may finish on
	// stop before they are cancelled. Stop still waits for their handlers to
	// return, so no handler runs once the stores close.
	gracefulStopTimeout = 10 * time.Second

	// socketDialTimeout bounds probing an existing socket for a live server.
	socketDialTimeout = time.Second

	// credentialSyncPollInterval is how often the registry credentials are
	// checked for their first sync.
	credentialSyncPollInterval = 100 * time.Millisecond
)

// Server is the snapshotter server.
type Server struct {
	// cfg is the config the server started with. A reloaded config reaches
	// the file system only.
	cfg *config.Config

	// store persists daemon instances.
	store store.Store

	// systemd manages daemon units.
	systemd systemd.Systemd

	// keychain resolves registry credentials.
	keychain auth.Keychain

	// fileSystem is the Nydus v3 file system.
	fileSystem fs.FileSystem

	// snapshotter is the containerd snapshotter.
	snapshotter snapshot.Snapshotter

	// gc evicts unused blobs from the cache.
	gc cache.GC

	// grpcServer serves the snapshotter to containerd.
	grpcServer *grpc.Server

	// healthServer answers the gRPC health checking protocol on the same
	// socket.
	//
	//	Check answers ─▶ the snapshotter is alive
	//	NOT_SERVING   ─▶ credentials are not synced yet, or the snapshotter stops
	//	SERVING       ─▶ ready
	healthServer *health.Server

	// metricsServer serves /metrics; nil when disabled.
	metricsServer *metrics.Server

	// ctx is the context of the background workers.
	ctx context.Context

	// cancel stops the background workers.
	cancel context.CancelFunc

	// wg waits for the background workers.
	wg sync.WaitGroup
}

// New creates a new snapshotter server. Nothing runs until Serve.
func New(ctx context.Context, cfg *config.Config) (*Server, error) {
	// Initialize the root and runtime directories.
	for _, dir := range []string{cfg.RootDir, cfg.RuntimeDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create %s: %w", dir, err)
		}
	}

	s := &Server{
		cfg:     cfg,
		systemd: systemd.New(),
	}

	// Initialize the store.
	var err error
	s.store, err = store.New(filepath.Join(cfg.RootDir, "nydusd.db"), store.DefaultOpenTimeout)
	if err != nil {
		return nil, err
	}

	// Initialize the keychain.
	s.keychain = auth.New(cfg)

	// Initialize the GC and the file system, which need each other: the GC
	// asks for the blobs of running daemons, a starting daemon holds the
	// GC's start lock.
	s.gc = cache.New(cfg, s.store,
		func(ctx context.Context) (map[string]struct{}, error) { return s.fileSystem.RunningBlobs(ctx) },
		func(ctx context.Context) (map[string]struct{}, error) { return s.snapshotter.CommittedBlobs(ctx) },
	)

	s.fileSystem, err = fs.New(ctx, cfg, s.systemd, s.store, s.keychain, s.gc.DaemonStartLock())
	if err != nil {
		return nil, fmt.Errorf("init nydus file system: %w", err)
	}

	// Initialize the snapshotter.
	s.snapshotter, err = snapshot.New(cfg.RootDir, s.fileSystem)
	if err != nil {
		return nil, fmt.Errorf("init snapshotter: %w", err)
	}

	// Initialize the metrics server if metrics is enabled.
	if cfg.Metrics.Addr != "" {
		s.metricsServer, err = metrics.NewServer(cfg.Metrics.Addr, s.fileSystem)
		if err != nil {
			return nil, err
		}
	}

	// Initialize the health server, which answers NOT_SERVING until the
	// registry credentials are synced.
	s.healthServer = health.NewServer()
	s.healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)

	// Initialize the gRPC server. It matches containerd's proxy client
	// limits, and lets Stop wait for in-flight handlers before the stores
	// close. The preheat and health services share its socket.
	s.grpcServer = grpc.NewServer(
		grpc.MaxRecvMsgSize(defaults.DefaultMaxRecvMsgSize),
		grpc.MaxSendMsgSize(defaults.DefaultMaxSendMsgSize),
		grpc.WaitForHandlers(true),
	)
	snapshotsapi.RegisterSnapshotsServer(s.grpcServer, snapshotservice.FromSnapshotter(s.snapshotter))
	resolver := preheat.NewResolver(cfg.Containerd.Addr, s.snapshotter)
	nydussnapshotterv1.RegisterNydusSnapshotterServer(s.grpcServer, preheat.NewService(resolver, s.fileSystem))
	grpc_health_v1.RegisterHealthServer(s.grpcServer, s.healthServer)

	// Initialize the context of the background workers.
	s.ctx, s.cancel = context.WithCancel(ctx)

	return s, nil
}

// Serve starts the snapshotter server.
func (s *Server) Serve() error {
	// Serve the background workers.
	s.wg.Go(func() { s.snapshotter.Run(s.ctx) })
	s.wg.Go(func() { s.gc.Run(s.ctx) })
	s.wg.Go(func() { s.fileSystem.Run(s.ctx) })
	s.wg.Go(func() { s.cfg.Watch(s.ctx, s.fileSystem.Reload) })

	// Serve the health status, which is SERVING once the registry
	// credentials are synced.
	s.wg.Go(func() {
		if !s.waitForCredentialSync(s.ctx) {
			return
		}

		s.healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	})

	// Serve the metrics server.
	if s.metricsServer != nil {
		s.wg.Go(func() {
			if err := s.metricsServer.Serve(); err != nil {
				log.L.WithError(err).Error("serve metrics")
			}
		})
	}

	listener, err := s.newGRPCListener()
	if err != nil {
		return err
	}
	defer listener.Close()

	// Notify systemd. The listener is bound, so containerd's calls queue
	// until the gRPC server accepts them.
	if _, err := sddaemon.SdNotify(false, sddaemon.SdNotifyReady); err != nil {
		log.L.WithError(err).Warn("notify systemd ready")
	}

	// Serve the gRPC server.
	log.L.WithField("address", s.cfg.GRPC.Addr).Info("serving snapshotter")
	if err := s.grpcServer.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}

	return nil
}

// Stop stops the snapshotter server. Daemons and their mounts keep running.
func (s *Server) Stop() {
	// Notify systemd.
	if _, err := sddaemon.SdNotify(false, sddaemon.SdNotifyStopping); err != nil {
		log.L.WithError(err).Warn("notify systemd stopping")
	}

	// Stop the gRPC server. Health checks answer NOT_SERVING while the calls
	// drain.
	s.healthServer.Shutdown()
	stopped := make(chan struct{})
	go func() {
		s.grpcServer.GracefulStop()
		close(stopped)
	}()

	timer := time.NewTimer(gracefulStopTimeout)
	select {
	case <-stopped:
	case <-timer.C:
		s.grpcServer.Stop()
		<-stopped
	}
	timer.Stop()

	// Stop the metrics server.
	if s.metricsServer != nil {
		s.metricsServer.Stop()
	}

	// Stop the background workers.
	s.cancel()
	s.wg.Wait()

	// Stop the snapshotter.
	if err := s.snapshotter.Close(); err != nil {
		log.L.WithError(err).Warn("close snapshotter")
	}

	// Stop the store.
	if err := s.store.Close(); err != nil {
		log.L.WithError(err).Warn("close store")
	}

	// Stop the systemd connection.
	s.systemd.Close()
}

// newGRPCListener returns the listener of the gRPC server, a socket bound at
// grpc.addr.
func (s *Server) newGRPCListener() (net.Listener, error) {
	address := s.cfg.GRPC.Addr
	if err := os.MkdirAll(filepath.Dir(address), 0o700); err != nil {
		return nil, fmt.Errorf("create socket dir: %w", err)
	}

	// Remove a stale socket, never one another snapshotter still serves.
	if conn, err := net.DialTimeout("unix", address, socketDialTimeout); err == nil {
		conn.Close()
		return nil, fmt.Errorf("socket %s is served by another process", address)
	}

	if err := os.Remove(address); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove stale socket: %w", err)
	}

	listener, err := net.Listen("unix", address)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", address, err)
	}

	if err := os.Chmod(address, 0o600); err != nil {
		listener.Close()
		return nil, fmt.Errorf("chmod %s: %w", address, err)
	}

	return listener, nil
}

// waitForCredentialSync waits for the first sync of the registry credentials
// and reports whether they synced before ctx was done.
func (s *Server) waitForCredentialSync(ctx context.Context) bool {
	tick := time.NewTicker(credentialSyncPollInterval)
	defer tick.Stop()

	for !s.keychain.Synced() {
		select {
		case <-tick.C:
		case <-ctx.Done():
			return false
		}
	}

	return true
}
