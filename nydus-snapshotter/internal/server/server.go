/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package server wires the snapshotter together and serves it to containerd
// over gRPC as a proxy plugin, refer to
// https://github.com/containerd/containerd/blob/main/docs/PLUGINS.md.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	snapshotsapi "github.com/containerd/containerd/api/services/snapshots/v1"
	"github.com/containerd/containerd/v2/contrib/snapshotservice"
	"github.com/containerd/containerd/v2/defaults"
	"github.com/containerd/log"
	"github.com/coreos/go-systemd/v22/activation"
	sddaemon "github.com/coreos/go-systemd/v22/daemon"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/auth"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/cache"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/fs"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/metrics"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/snapshot"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd"
)

const (
	// fsVersionV3 is the nydus-fs-version of Nydus v3 images.
	fsVersionV3 = "7"

	// gracefulStopTimeout bounds draining in-flight gRPC calls on stop.
	gracefulStopTimeout = 10 * time.Second

	// dialTimeout bounds probing an existing socket for a live server.
	dialTimeout = time.Second

	// jobTimeoutMargin pads the systemd job timeout over the daemon's stop
	// timeout.
	jobTimeoutMargin = 5 * time.Second

	// reloadTimeout bounds applying a reloaded config.
	reloadTimeout = time.Minute
)

// Server is the snapshotter process.
type Server struct {
	// cfg is the running config.
	cfg *config.Config

	// store persists daemon instances.
	store store.Store

	// systemd manages daemon units.
	systemd systemd.Manager

	// keychain resolves registry credentials.
	keychain auth.Keychain

	// fileSystem is the Nydus v3 file system.
	fileSystem fs.FileSystem

	// snapshotter is the containerd snapshotter.
	snapshotter snapshot.Snapshotter

	// gc evicts unused blobs from the cache.
	gc cache.GC

	// grpc serves the snapshotter to containerd.
	grpc *grpc.Server

	// listener is the gRPC listener.
	listener net.Listener

	// serving reports whether gRPC is serving.
	serving atomic.Bool

	// metrics serves /metrics, /livez and /readyz; nil when disabled.
	metrics *metrics.Server

	// cancel stops the background workers.
	cancel context.CancelFunc

	// wg waits for the background workers.
	wg sync.WaitGroup
}

// New server. The background workers start once every component is built
// and stop on Stop.
func New(ctx context.Context, cfg *config.Config, configPath string) (*Server, error) {
	for _, dir := range []string{cfg.Root, cfg.RunDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create %s: %w", dir, err)
		}
	}

	// Rendered daemon configs hold credentials, which stay off persistent
	// disk only on tmpfs; a failed statfs is caught by the first daemon.
	var stat unix.Statfs_t
	if err := unix.Statfs(cfg.RunDir, &stat); err == nil && stat.Type != unix.TMPFS_MAGIC {
		log.G(ctx).WithField("path", cfg.RunDir).Warn("run_dir is not on tmpfs, so rendered daemon configs keep credentials on disk")
	}

	// A stop job takes up to twice TimeoutStopSec, SIGTERM then SIGKILL,
	// refer to https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html.
	s := &Server{
		cfg:     cfg,
		systemd: systemd.New(2*time.Duration(cfg.Nydusd.MountTimeout) + jobTimeoutMargin),
	}

	ctx, s.cancel = context.WithCancel(ctx)
	if err := s.setup(ctx); err != nil {
		s.Stop()
		return nil, err
	}

	s.wg.Go(func() { s.snapshotter.Run(ctx) })
	s.wg.Go(func() { s.gc.Run(ctx) })
	s.wg.Go(func() { s.keychain.Run(ctx) })
	s.wg.Go(func() { config.NewWatcher(configPath, config.DefaultWatchInterval, cfg).Run(ctx, s.reload) })
	if s.metrics != nil {
		s.wg.Go(func() {
			if err := s.metrics.Serve(); err != nil {
				log.G(ctx).WithError(err).Error("serve metrics")
			}
		})
	}

	return s, nil
}

// setup builds the components in dependency order.
func (s *Server) setup(ctx context.Context) error {
	var err error
	s.store, err = store.New(filepath.Join(s.cfg.Root, "nydusd.db"), store.DefaultOpenTimeout)
	if err != nil {
		return err
	}

	s.keychain = auth.New(s.cfg, s.store)

	// The GC and the file system need each other: the GC asks for the blobs
	// of running daemons, a starting daemon holds the GC's start lock.
	s.gc = cache.New(s.cfg, s.store,
		func(ctx context.Context) (map[string]struct{}, error) { return s.fileSystem.RunningBlobs(ctx) },
		func(ctx context.Context) (map[string]struct{}, error) { return s.snapshotter.CommittedBlobs(ctx) },
	)

	s.fileSystem, err = fs.New(ctx, s.cfg, s.systemd, s.store, s.keychain, s.gc.StartLock())
	if err != nil {
		return fmt.Errorf("init nydus file system: %w", err)
	}

	s.snapshotter, err = snapshot.New(s.cfg.Root, map[string]fs.FileSystem{fsVersionV3: s.fileSystem})
	if err != nil {
		return fmt.Errorf("init snapshotter: %w", err)
	}

	if s.cfg.Metrics.Address != "" {
		s.metrics, err = metrics.NewServer(s.cfg.Metrics.Address, s.ready)
		if err != nil {
			return err
		}
	}

	// Bind the gRPC socket last, as nothing closes it before Serve owns it.
	s.listener, err = s.listen(ctx)
	if err != nil {
		return err
	}

	// Match containerd's proxy client limits, and let Stop wait for in-flight
	// handlers before the stores close, refer to
	// https://github.com/containerd/containerd/blob/main/cmd/containerd/server/server.go.
	s.grpc = grpc.NewServer(
		grpc.MaxRecvMsgSize(defaults.DefaultMaxRecvMsgSize),
		grpc.MaxSendMsgSize(defaults.DefaultMaxSendMsgSize),
		grpc.WaitForHandlers(true),
	)
	snapshotsapi.RegisterSnapshotsServer(s.grpc, snapshotservice.FromSnapshotter(s.snapshotter))

	return nil
}

// Serve serves gRPC until Stop, and tells systemd the snapshotter is ready.
func (s *Server) Serve(ctx context.Context) error {
	s.serving.Store(true)
	defer s.serving.Store(false)

	// The listener is bound, so containerd's calls queue until Serve accepts
	// them, refer to https://github.com/containerd/containerd/blob/main/cmd/containerd/command/notify_linux.go.
	if _, err := sddaemon.SdNotify(false, sddaemon.SdNotifyReady); err != nil {
		log.G(ctx).WithError(err).Warn("notify systemd ready")
	}

	log.G(ctx).WithField("address", s.cfg.Address).Info("serving snapshotter")
	if err := s.grpc.Serve(s.listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}

	return nil
}

// Stop drains gRPC calls, stops the workers and closes the stores. Daemons
// and their mounts keep running.
func (s *Server) Stop() {
	if _, err := sddaemon.SdNotify(false, sddaemon.SdNotifyStopping); err != nil {
		log.L.WithError(err).Warn("notify systemd stopping")
	}

	if s.grpc != nil {
		stopped := make(chan struct{})
		go func() {
			s.grpc.GracefulStop()
			close(stopped)
		}()

		timer := time.NewTimer(gracefulStopTimeout)
		select {
		case <-stopped:
		case <-timer.C:
			s.grpc.Stop()
			<-stopped
		}
		timer.Stop()
	} else if s.listener != nil {
		s.listener.Close()
	}

	if s.metrics != nil {
		s.metrics.Stop()
	}

	s.cancel()
	s.wg.Wait()

	if s.snapshotter != nil {
		if err := s.snapshotter.Close(); err != nil {
			log.L.WithError(err).Warn("close snapshotter")
		}
	}

	if s.store != nil {
		if err := s.store.Close(); err != nil {
			log.L.WithError(err).Warn("close store")
		}
	}

	s.systemd.Close()
}

// ready reports why the snapshotter cannot serve yet, nil once it can.
func (s *Server) ready() error {
	if !s.serving.Load() {
		return errors.New("grpc is not serving")
	}

	if !s.keychain.Synced() {
		return errors.New("registry credentials are not synced")
	}

	return nil
}

// reload applies the reloadable sections of a changed config file.
func (s *Server) reload(ctx context.Context, next *config.Config) {
	ctx, cancel := context.WithTimeout(ctx, reloadTimeout)
	defer cancel()

	merged, restartOnly := s.cfg.Merge(next)
	if restartOnly {
		log.G(ctx).Warn("config changes outside cgroup and nydusd.dragonfly apply after a restart")
	}

	if err := s.fileSystem.Reload(ctx, merged); err != nil {
		log.G(ctx).WithError(err).Error("apply reloaded config")
	}
}

// listen returns the gRPC listener: the socket systemd passes when socket
// activated, as soci-snapshotter does, or a socket bound at address.
func (s *Server) listen(ctx context.Context) (net.Listener, error) {
	address := s.cfg.Address
	listeners, err := activation.Listeners()
	if err != nil {
		return nil, fmt.Errorf("get activated sockets: %w", err)
	}

	if len(listeners) > 0 {
		if listeners[0] == nil {
			return nil, errors.New("socket passed by systemd is not a listener")
		}

		log.G(ctx).Info("using the socket passed by systemd")
		return listeners[0], nil
	}

	if err := os.MkdirAll(filepath.Dir(address), 0o700); err != nil {
		return nil, fmt.Errorf("create socket dir: %w", err)
	}

	// Remove a stale socket, never one another snapshotter still serves.
	if conn, err := net.DialTimeout("unix", address, dialTimeout); err == nil {
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
