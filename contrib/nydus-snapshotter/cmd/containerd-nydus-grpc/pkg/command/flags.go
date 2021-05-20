/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package command

import (
	"os"
	"path/filepath"
	"time"

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/config"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

const (
	defaultAddress        = "/run/containerd-nydus-grpc/containerd-nydus-grpc.sock"
	defaultLogLevel       = logrus.InfoLevel
	defaultRootDir        = "/var/lib/containerd-nydus-grpc"
	defaultGCPeriod       = "24h"
	defaultPublicKey      = "/signing/nydus-image-signing-public.key"
	defaultNydusdPath     = "/bin/nydusd"
	defaultNydusImagePath = "/bin/nydusd-img"
)

type Args struct {
	Address              string
	LogLevel             string
	ConfigPath           string
	RootDir              string
	CacheDir             string
	GCPeriod             string
	ValidateSignature    bool
	PublicKeyFile        string
	ConvertVpcRegistry   bool
	NydusdBinaryPath     string
	NydusImageBinaryPath string
	SharedDaemon         bool
	DaemonMode           string
	AsyncRemove          bool
	EnableMetrics        bool
	MetricsFile          string
	EnableStargz         bool
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
		&cli.StringFlag{
			Name:        "cache-dir",
			Value:       "",
			Usage:       "path to the cache dir",
			Destination: &args.CacheDir,
		},
		&cli.StringFlag{
			Name:        "gc-period",
			Value:       defaultGCPeriod,
			Usage:       "period for gc blob cache, for example, 1m, 2h",
			Destination: &args.GCPeriod,
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
			Usage:       "Deprecated, equivalent to \"--daemon-mode shared\"",
			Destination: &args.SharedDaemon,
		},
		&cli.StringFlag{
			Name:        "daemon-mode",
			Value:       config.DefaultDaemonMode,
			Usage:       "daemon mode to use, could be \"multiple\", \"shared\" or \"none\"",
			Destination: &args.DaemonMode,
		},
		&cli.BoolFlag{
			Name:        "async-remove",
			Value:       true,
			Usage:       "whether to cleanup snapshots asynchronously",
			Destination: &args.AsyncRemove,
		},
		&cli.BoolFlag{
			Name:        "enable-metrics",
			Value:       false,
			Usage:       "whether to collect metrics",
			Destination: &args.EnableMetrics,
		},
		&cli.StringFlag{
			Name:        "metrics-file",
			Usage:       "file path to output metrics",
			Destination: &args.MetricsFile,
		},
		&cli.BoolFlag{
			Name:        "enable-stargz",
			Value:       false,
			Usage:       "whether to support stargz image",
			Destination: &args.EnableStargz,
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

func Validate(args *Args, cfg *config.Config) error {
	var daemonCfg config.DaemonConfig
	if err := config.LoadConfig(args.ConfigPath, &daemonCfg); err != nil {
		return errors.Wrapf(err, "failed to load config file %q", args.ConfigPath)
	}

	if args.ValidateSignature && args.PublicKeyFile != "" {
		if _, err := os.Stat(args.PublicKeyFile); err != nil {
			return errors.Wrapf(err, "failed to find publicKey file %q", args.PublicKeyFile)
		}
	}
	cfg.DaemonCfg = daemonCfg
	cfg.RootDir = args.RootDir

	cfg.CacheDir = args.CacheDir
	if len(cfg.CacheDir) == 0 {
		cfg.CacheDir = filepath.Join(cfg.RootDir, "cache")
	}
	cfg.ValidateSignature = args.ValidateSignature
	cfg.PublicKeyFile = args.PublicKeyFile
	cfg.ConvertVpcRegistry = args.ConvertVpcRegistry
	cfg.Address = args.Address
	cfg.NydusdBinaryPath = args.NydusdBinaryPath
	cfg.NydusImageBinaryPath = args.NydusImageBinaryPath
	cfg.DaemonMode = args.DaemonMode
	// Give --shared-daemon higher priority
	if args.SharedDaemon {
		cfg.DaemonMode = config.DaemonModeShared
	}
	cfg.AsyncRemove = args.AsyncRemove
	cfg.EnableMetrics = args.EnableMetrics
	cfg.MetricsFile = args.MetricsFile
	cfg.EnableStargz = args.EnableStargz

	d, err := time.ParseDuration(args.GCPeriod)
	if err != nil {
		return errors.Wrapf(err, "parse gc period %v failed", args.GCPeriod)
	}
	cfg.GCPeriod = d
	return nil
}
