/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package snapshotter

import (
	"os"

	"github.com/pkg/errors"

	"contrib/nydus-snapshotter/cmd/containerd-nydus-grpc/pkg/command"
	"contrib/nydus-snapshotter/pkg/filesystem/nydus"
)

type Config struct {
	Address              string
	ConvertVpcRegistry   bool
	DaemonCfg            nydus.DaemonConfig
	PublicKeyFile        string
	RootDir              string
	ValidateSignature    bool
	NydusdBinaryPath     string
	NydusImageBinaryPath string
	SharedDaemon         bool
}

func Validate(args *command.Args, cfg *Config) error {
	var daemonCfg nydus.DaemonConfig
	if err := nydus.LoadConfig(args.ConfigPath, &daemonCfg); err != nil {
		return errors.Wrapf(err, "failed to load config file %q", args.ConfigPath)
	}

	if args.ValidateSignature && args.PublicKeyFile != "" {
		if _, err := os.Stat(args.PublicKeyFile); err != nil {
			return errors.Wrapf(err, "failed to find publicKey file %q", args.PublicKeyFile)
		}
	}
	cfg.DaemonCfg = daemonCfg
	cfg.RootDir = args.RootDir
	cfg.ValidateSignature = args.ValidateSignature
	cfg.PublicKeyFile = args.PublicKeyFile
	cfg.ConvertVpcRegistry = args.ConvertVpcRegistry
	cfg.Address = args.Address
	cfg.NydusdBinaryPath = args.NydusdBinaryPath
	cfg.NydusImageBinaryPath = args.NydusImageBinaryPath
	cfg.SharedDaemon = args.SharedDaemon
	return nil
}
