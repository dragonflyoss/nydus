/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package cmd holds the nydus-snapshotter commands.
package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/containerd/log"
	"github.com/spf13/cobra"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/server"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/version"
)

// configPath is the --config flag.
var configPath string

// rootCmd serves the snapshotter.
var rootCmd = &cobra.Command{
	Use:           "nydus-snapshotter",
	Short:         "containerd snapshotter for Nydus v3 images",
	Version:       version.String(),
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.Load(configPath)
		if err != nil {
			return err
		}

		if err := log.SetLevel(cfg.Log.Level); err != nil {
			return fmt.Errorf("set log level: %w", err)
		}

		return runSnapshotter(cmd.Context(), cfg, configPath)
	},
}

// init registers the flags and subcommands.
func init() {
	rootCmd.Flags().StringVar(&configPath, "config", config.DefaultPath, "path to the config file")
	rootCmd.AddCommand(newInstallCmd())
}

// Execute runs the root command and exits on error.
func Execute() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	err := rootCmd.ExecuteContext(ctx)
	stop()
	if err != nil {
		log.L.WithError(err).Error("nydus-snapshotter failed")
		os.Exit(1)
	}
}

// runSnapshotter serves until ctx is done, reloading the config at
// configPath.
func runSnapshotter(ctx context.Context, cfg *config.Config, configPath string) error {
	log.G(ctx).WithField("version", version.String()).Info("starting nydus-snapshotter")

	s, err := server.New(ctx, cfg, configPath)
	if err != nil {
		return err
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Serve(ctx)
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
