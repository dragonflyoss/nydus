/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package cmd

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/installer"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd"
)

// installConfig is the installer config, which the flags of the install
// command set.
var installConfig = &installer.Config{}

// installCmd represents the install command, the DaemonSet entrypoint.
var installCmd = &cobra.Command{
	Use:               "install [flags]",
	Short:             "Install nydus-snapshotter onto the host and keep its config and credentials in sync",
	Args:              cobra.NoArgs,
	DisableAutoGenTag: true,
	SilenceUsage:      true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runInstall(cmd.Context(), installConfig)
	},
}

// init initializes the install command.
func init() {
	flags := installCmd.Flags()
	flags.StringVar(&installConfig.RootfsDir, "rootfs-dir", installer.DefaultRootfsDir, "Specify the directory the root filesystem of the host is mounted at, / on the host")
	flags.StringVar(&installConfig.PayloadDir, "payload-dir", installer.DefaultPayloadDir, "Specify the directory holding bin/, systemd/ and config/ to install")
	flags.StringVar(&installConfig.TokenDir, "token-dir", installer.DefaultTokenDir, "Specify the service account token directory to copy to the host when kube_secret is enabled")
	flags.DurationVar(&installConfig.SyncInterval, "sync-interval", installer.DefaultSyncInterval, "Specify how often the token and the config are copied to the host")
}

// runInstall installs the snapshotter onto the host, then keeps its config
// and Kubernetes credentials in sync until ctx is done.
func runInstall(ctx context.Context, cfg *installer.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	manager := systemd.New(installer.JobTimeout)
	defer manager.Close()

	return installer.New(cfg, manager).Run(ctx)
}
