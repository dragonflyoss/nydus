/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package snapshotter

import (
	"context"

	"github.com/pkg/errors"

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/config"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/filesystem/nydus"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/filesystem/stargz"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/signature"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/utils/signals"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/snapshot"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/process"
)

func Start(ctx context.Context, cfg config.Config) error {
	verifier, err := signature.NewVerifier(cfg.PublicKeyFile, cfg.ValidateSignature)
	if err != nil {
		return errors.Wrap(err, "failed to initialize verifier")
	}

	mgr, err := process.NewManager(process.Opt{
		NydusdBinaryPath: cfg.NydusdBinaryPath,
		RootDir:          cfg.RootDir,
		SharedDaemon:     cfg.SharedDaemon,
	})
	if err != nil {
		return errors.Wrap(err, "failed to new process manager")
	}

	fs, err := nydus.NewFileSystem(
		ctx,
		nydus.WithProcessManager(mgr),
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
		stargz.WithProcessManager(mgr),
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
	opt := ServeOptions{
		ListeningSocketPath: cfg.Address,
	}
	return Serve(ctx, rs, opt, stopSignal)
}
