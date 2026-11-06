/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/installer"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd"
)

// newInstallCmd returns the DaemonSet entrypoint: it installs the snapshotter
// onto the host and keeps its config and Kubernetes credentials in sync.
func newInstallCmd() *cobra.Command {
	var cfg installer.Config
	cmd := &cobra.Command{
		Use:   "install",
		Short: "install nydus-snapshotter onto the host and keep its config and credentials in sync",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := cfg.Validate(); err != nil {
				return err
			}

			manager := systemd.New(installer.DefaultJobTimeout)
			defer manager.Close()

			return installer.New(&cfg, manager).Run(cmd.Context())
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&cfg.HostRoot, "host-root", installer.DefaultHostRoot, "path the host root is mounted at, / on the host")
	flags.StringVar(&cfg.PayloadDir, "payload-dir", installer.DefaultPayloadDir, "directory holding bin/, systemd/ and config/ to install")
	flags.StringVar(&cfg.TokenDir, "token-dir", installer.DefaultTokenDir, "service account token directory to copy to the host when kubesecret is enabled")
	flags.DurationVar(&cfg.SyncInterval, "sync-interval", installer.DefaultSyncInterval, "how often the token and the config are copied to the host")

	return cmd
}
