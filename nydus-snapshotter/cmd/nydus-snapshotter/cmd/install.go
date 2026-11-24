/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package cmd

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/installer"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd"
)

// installCmd represents the install command, the DaemonSet entrypoint. It
// has no flag of its own: the installer section of the config file holds its
// settings.
var installCmd = &cobra.Command{
	Use:               "install",
	Short:             "Install nydus-snapshotter onto the host and keep its config and credentials in sync",
	Args:              cobra.NoArgs,
	DisableAutoGenTag: true,
	SilenceUsage:      true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runInstall(cmd.Context(), cfg, configPath)
	},
}

// runInstall installs the snapshotter onto the host as the config says, with
// the config file at configPath, then keeps its config and Kubernetes
// credentials in sync until ctx is done.
func runInstall(ctx context.Context, cfg *config.Config, configPath string) error {
	systemd := systemd.New()
	defer systemd.Close()

	return installer.New(cfg, configPath, systemd).Run(ctx)
}
