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

// Execute runs the root command and exits on error.
func Execute() {
	// The first signal stops the snapshotter; give the next one its default
	// disposition back, so it kills a stop that hangs.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	context.AfterFunc(ctx, stop)

	if err := newRootCmd().ExecuteContext(ctx); err != nil {
		log.L.WithError(err).Error("nydus-snapshotter failed")
		os.Exit(1)
	}
}

// rootOptions holds the flags of the root command, as a kubectl command
// keeps its flags and what it runs on an options struct, refer to
// https://github.com/kubernetes/kubectl/blob/master/pkg/cmd/apply/apply.go.
type rootOptions struct {
	// configPath is the path to the config file.
	configPath string
}

// newRootCmd returns the command serving the snapshotter, with its
// subcommands.
func newRootCmd() *cobra.Command {
	o := &rootOptions{}
	cmd := &cobra.Command{
		Use:           "nydus-snapshotter",
		Short:         "containerd snapshotter for Nydus v3 images",
		Version:       version.String(),
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := o.loadConfig(cmd.Context(), cmd.Flags().Changed("config"))
			if err != nil {
				return err
			}

			if err := log.SetLevel(cfg.Log.Level); err != nil {
				return fmt.Errorf("set log level: %w", err)
			}

			return o.run(cmd.Context(), cfg)
		},
	}

	cmd.Flags().StringVar(&o.configPath, "config", config.DefaultPath, "path to the config file")
	cmd.AddCommand(newInstallCmd())
	return cmd
}

// loadConfig loads the config. Only a path that was not asked for
// explicitly, the default one, may be missing and yields the defaults, as
// containerd's config, refer to
// https://github.com/containerd/containerd/blob/main/cmd/containerd/command/main.go.
func (o *rootOptions) loadConfig(ctx context.Context, explicit bool) (*config.Config, error) {
	cfg, err := config.Load(o.configPath)
	if errors.Is(err, fs.ErrNotExist) && !explicit {
		log.G(ctx).WithField("path", o.configPath).Warn("config not found, using defaults")
		return config.Parse(nil)
	}

	return cfg, err
}

// run serves the snapshotter until ctx is done, reloading the config file.
func (o *rootOptions) run(ctx context.Context, cfg *config.Config) error {
	log.G(ctx).WithField("version", version.String()).Info("starting nydus-snapshotter")

	s, err := server.New(ctx, cfg, o.configPath)
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
