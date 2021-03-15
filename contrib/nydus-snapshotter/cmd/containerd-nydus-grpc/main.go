/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"os"

	"github.com/containerd/containerd/log"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/cmd/containerd-nydus-grpc/app/snapshotter"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/cmd/containerd-nydus-grpc/pkg/command"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/cmd/containerd-nydus-grpc/pkg/logging"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/config"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/errdefs"
)

func main() {
	flags := command.NewFlags()
	app := &cli.App{
		Name:    "containerd-nydus-grpc",
		Usage:   "nydus containerd proxy snapshotter plugin",
		Version: Version,
		Flags:   flags.F,
		Action: func(c *cli.Context) error {
			ctx := logging.WithContext()
			if err := logging.SetUp(flags.Args.LogLevel); err != nil {
				return errors.Wrap(err, "failed to prepare logger")
			}

			var cfg config.Config
			if err := command.Validate(flags.Args, &cfg); err != nil {
				return errors.Wrap(err, "invalid argument")
			}
			return snapshotter.Start(ctx, cfg)
		},
	}
	if err := app.Run(os.Args); err != nil {
		if errdefs.IsConnectionClosed(err) {
			log.L.Info("snapshotter exited")
			return
		}
		log.L.WithError(err).Fatal("failed to start nydus snapshotter")
	}
}
