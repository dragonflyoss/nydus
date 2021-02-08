/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package snapshotter

import (
	"context"
	"net"
	"os"
	"path/filepath"

	snapshotsapi "github.com/containerd/containerd/api/services/snapshots/v1"
	"github.com/containerd/containerd/contrib/snapshotservice"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/snapshots"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
)

type ServeOptions struct {
	ListeningSocketPath string
}

func Serve(ctx context.Context, rs snapshots.Snapshotter, options ServeOptions, stop <-chan struct{}) error {
	err := ensureSocketNotExists(options.ListeningSocketPath)
	if err != nil {
		return err
	}

	rpc := grpc.NewServer()
	snapshotsapi.RegisterSnapshotsServer(rpc, snapshotservice.FromSnapshotter(rs))
	l, err := net.Listen("unix", options.ListeningSocketPath)
	if err != nil {
		return errors.Wrapf(err, "error on listen socket %q", options.ListeningSocketPath)
	}
	go func() {
		sig := <-stop
		log.G(ctx).Infof("caught signal %s: shutting down", sig)
		err := l.Close()
		if err != nil {
			log.G(ctx).Errorf("failed to close listener %s, err: %v", options.ListeningSocketPath, err)
		}
	}()
	return rpc.Serve(l)
}

func ensureSocketNotExists(listeningSocketPath string) error {
	if err := os.MkdirAll(filepath.Dir(listeningSocketPath), 0700); err != nil {
		return errors.Wrapf(err, "failed to create directory %q", filepath.Dir(listeningSocketPath))
	}
	_, err := os.Stat(listeningSocketPath)
	// err is nil means listening socket path exists, remove before serve
	if err == nil {
		err := os.Remove(listeningSocketPath)
		if err != nil {
			return err
		}
	}
	return nil
}
