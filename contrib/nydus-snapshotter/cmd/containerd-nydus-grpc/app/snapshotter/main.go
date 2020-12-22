/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package snapshotter

import (
	"context"

	"github.com/pkg/errors"

	"contrib/nydus-snapshotter/config"
	"contrib/nydus-snapshotter/pkg/filesystem/nydus"
	"contrib/nydus-snapshotter/pkg/filesystem/stargz"
	"contrib/nydus-snapshotter/pkg/signature"
	"contrib/nydus-snapshotter/pkg/utils/signals"
	"contrib/nydus-snapshotter/snapshot"
)

func Start(ctx context.Context, cfg config.Config) error {
	verifier, err := signature.NewVerifier(cfg.PublicKeyFile, cfg.ValidateSignature)
	if err != nil {
		return errors.Wrap(err, "failed to initialize verifier")
	}
	fs, err := nydus.NewFileSystem(
		ctx,
		nydus.WithNydusdBinaryPath(cfg.NydusdBinaryPath),
		nydus.WithMeta(cfg.RootDir),
		nydus.WithDaemonConfig(cfg.DaemonCfg),
		nydus.WithVPCRegistry(cfg.ConvertVpcRegistry),
		nydus.WithVerifier(verifier),
		nydus.WithSharedDaemon(cfg.SharedDaemon),
	)
	if err != nil {
		return errors.Wrap(err, "failed to initialize nydus filesystem")
	}

	stargzFs, err := stargz.NewFileSystem(
		ctx,
		stargz.WithMeta(cfg.RootDir),
		stargz.WithNydusdBinaryPath(cfg.NydusdBinaryPath),
		stargz.WithNydusImageBinaryPath(cfg.NydusImageBinaryPath),
		stargz.WithDaemonConfig(cfg.DaemonCfg),
	)
	if err != nil {
		return errors.Wrap(err, "failed to initialize stargz filesystem")
	}

	rs, err := snapshot.NewSnapshotter(ctx, cfg.RootDir, cfg.NydusdBinaryPath, fs, stargzFs, snapshot.AsynchronousRemove)
	if err != nil {
		return errors.Wrap(err, "failed to initialize snapshotter")
	}

	stopSignal := signals.SetupSignalHandler()
	opt := snapshot.ServeOptions{
		ListeningSocketPath: cfg.Address,
	}
	return snapshot.Serve(ctx, rs, opt, stopSignal)
}
