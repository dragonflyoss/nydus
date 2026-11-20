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

// unlabelCmd represents the unlabel command, the post-delete hook of the
// chart.
var unlabelCmd = &cobra.Command{
	Use:               "unlabel",
	Short:             "Remove the " + installer.NodeLabel + " label from every node",
	Args:              cobra.NoArgs,
	DisableAutoGenTag: true,
	SilenceUsage:      true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig(cmd.Context(), configPath, cmd.Flags().Changed("config"))
		if err != nil {
			return err
		}

		return runUnlabel(cmd.Context(), cfg)
	},
}

// runUnlabel removes the label the installers keep on their nodes from every
// node, with the service account of the Pod.
func runUnlabel(ctx context.Context, cfg *config.Config) error {
	return installer.New(&installer.Config{InstallerConfig: cfg.Installer}, nil).UnlabelNodes(ctx)
}
