/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package cmd holds the nydus-snapshotter commands.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"syscall"

	"github.com/containerd/log"
	"github.com/spf13/cobra"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/server"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/version"
)

// configPath is the path to the config file, which --config sets.
var configPath string

// rootCmd represents the nydus-snapshotter command, which serves the
// snapshotter to containerd.
var rootCmd = &cobra.Command{
	Use:               "nydus-snapshotter",
	Short:             "A containerd snapshotter for Nydus v3 images",
	Version:           version.String(),
	Args:              cobra.NoArgs,
	DisableAutoGenTag: true,
	SilenceUsage:      true,
	SilenceErrors:     true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig(cmd.Context(), configPath, cmd.Flags().Changed("config"))
		if err != nil {
			return err
		}

		if err := log.SetLevel(cfg.Log.Level); err != nil {
			return fmt.Errorf("set log level: %w", err)
		}

		return runSnapshotter(cmd.Context(), cfg, configPath)
	},
}

// Execute adds all child commands to the root command and runs it. It is
// called by main.main and exits on error.
func Execute() {
	// The first signal stops the snapshotter; give the next one its default
	// disposition back, so it kills a stop that hangs.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	context.AfterFunc(ctx, stop)

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		log.L.WithError(err).Error("nydus-snapshotter failed")
		os.Exit(1)
	}
}

// init initializes the root command.
func init() {
	// The install command reads the same config file, the one it installs.
	flags := rootCmd.PersistentFlags()
	flags.StringVar(&configPath, "config", config.DefaultPath, "Specify the path to the config file")

	// Add sub command.
	rootCmd.AddCommand(installCmd)
	rootCmd.AddCommand(uninstallCmd)
}

// loadConfig loads the config at path. Only a path that was not asked for
// explicitly, the default one, may be missing and yields the defaults, as
// containerd's config, refer to
// https://github.com/containerd/containerd/blob/main/cmd/containerd/command/main.go.
func loadConfig(ctx context.Context, path string, explicit bool) (*config.Config, error) {
	cfg, err := config.Load(path)
	if errors.Is(err, fs.ErrNotExist) && !explicit {
		log.G(ctx).WithField("path", path).Warn("config not found, using defaults")
		return config.Parse(nil)
	}

	return cfg, err
}

// runSnapshotter serves the snapshotter until ctx is done, reloading the
// config file at path.
func runSnapshotter(ctx context.Context, cfg *config.Config, path string) error {
	log.G(ctx).WithField("version", version.String()).Info("starting nydus-snapshotter")

	s, err := server.New(ctx, cfg, path)
	if err != nil {
		return err
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Serve()
	}()

	select {
	case err := <-errCh:
		s.Stop()
		return err
	case <-ctx.Done():
		log.G(ctx).Info("stopping nydus-snapshotter")
		s.Stop()
		return <-errCh
	}
}
