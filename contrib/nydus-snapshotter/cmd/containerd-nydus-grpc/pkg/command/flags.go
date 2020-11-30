/*
 * Copyright (c) 2020. Ant Financial. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package command

import (
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

const (
	defaultAddress        = "/run/containerd-nydus-grpc/containerd-nydus-grpc.sock"
	defaultLogLevel       = logrus.InfoLevel
	defaultRootDir        = "/var/lib/containerd-nydus-grpc"
	defaultPublicKey      = "/signing/nydus-image-signing-public.key"
	defaultNydusdPath     = "/bin/nydusd"
	defaultNydusImagePath = "/bin/nydusd-img"
)

type Args struct {
	Address              string
	LogLevel             string
	ConfigPath           string
	RootDir              string
	ValidateSignature    bool
	PublicKeyFile        string
	ConvertVpcRegistry   bool
	NydusdBinaryPath     string
	NydusImageBinaryPath string
	SharedDaemon         bool
}

type Flags struct {
	Args *Args
	F    []cli.Flag
}

func buildFlags(args *Args) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "address",
			Value:       defaultAddress,
			Destination: &args.Address,
		},
		&cli.StringFlag{
			Name:        "log-level",
			Value:       defaultLogLevel.String(),
			Usage:       "set the logging level [trace, debug, info, warn, error, fatal, panic]",
			Destination: &args.LogLevel,
		},
		&cli.StringFlag{
			Name:        "config-path",
			Required:    true,
			Usage:       "path to the configuration file",
			Destination: &args.ConfigPath,
		},
		&cli.StringFlag{
			Name:        "root",
			Value:       defaultRootDir,
			Usage:       "path to the root directory for this snapshotter",
			Destination: &args.RootDir,
		},
		&cli.BoolFlag{
			Name:        "validate-signature",
			Value:       false,
			Usage:       "whether force validate image bootstrap",
			Destination: &args.ValidateSignature,
		},
		&cli.StringFlag{
			Name:        "publickey-file",
			Value:       defaultPublicKey,
			Usage:       "path to publickey file of signature validation",
			Destination: &args.PublicKeyFile,
		},
		&cli.StringFlag{
			Name:        "nydusd-path",
			Value:       defaultNydusdPath,
			Usage:       "path to nydusd binary",
			Destination: &args.NydusdBinaryPath,
		},
		&cli.StringFlag{
			Name:        "nydusimg-path",
			Value:       defaultNydusImagePath,
			Usage:       "path to nydus-img binary path",
			Destination: &args.NydusImageBinaryPath,
		},
		&cli.BoolFlag{
			Name:        "convert-vpc-registry",
			Value:       false,
			Usage:       "whether automatically convert the image to vpc registry to accelerate image pulling",
			Destination: &args.ConvertVpcRegistry,
		},
		&cli.BoolFlag{
			Name:        "shared-daemon",
			Value:       false,
			Usage:       "whether to use a single shared nydus daemon",
			Destination: &args.SharedDaemon,
		},
	}
}

func NewFlags() *Flags {
	var args Args
	return &Flags{
		Args: &args,
		F:    buildFlags(&args),
	}
}
