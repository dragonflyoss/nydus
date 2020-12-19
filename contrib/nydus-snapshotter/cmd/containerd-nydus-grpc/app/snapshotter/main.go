/*
 * Copyright (c) 2020. Ant Financial. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package snapshotter

import (
	"context"

	"github.com/pkg/errors"

	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/filesystem/nydus"
	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/filesystem/stargz"
	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/signature"
	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/utils/signals"
	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/snapshot"
)

func Start(ctx context.Context, cfg Config) error {
	verifier, err := signature.NewVerifier(cfg.PublicKeyFile, cfg.ValidateSignature)
	if err != nil {
		return errors.Wrap(err, "failed to initialize verifier")
	}
	fs, err := nydus.NewFileSystem(
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
