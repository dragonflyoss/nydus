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
)

// uninstallCmd represents the uninstall command, the post-delete hook of the
// chart. It removes what the installers left in the cluster, the node label;
// a host keeps its snapshotter, which containers still run on.
var uninstallCmd = &cobra.Command{
	Use:               "uninstall",
	Short:             "Remove what the installers left in the cluster: the " + installer.NodeLabel + " label of every node",
	Args:              cobra.NoArgs,
	DisableAutoGenTag: true,
	SilenceUsage:      true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig(cmd.Context(), configPath, cmd.Flags().Changed("config"))
		if err != nil {
			return err
		}

		return runUninstall(cmd.Context(), cfg)
	},
}

// runUninstall removes the label the installers keep on their nodes from
// every node, with the service account of the Pod.
func runUninstall(ctx context.Context, cfg *config.Config) error {
	return installer.New(&installer.Config{InstallerConfig: cfg.Installer}, nil).UnlabelNodes(ctx)
}
