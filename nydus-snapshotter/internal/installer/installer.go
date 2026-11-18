/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package installer installs the snapshotter onto the host from the
// DaemonSet Pod and keeps its config and Kubernetes credentials in sync, as
// the installer of a CNI plugin does for its binary and kubeconfig, refer to
// https://github.com/projectcalico/calico/blob/master/cni-plugin/pkg/install/install.go.
package installer

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	continuityfs "github.com/containerd/continuity/fs"
	"github.com/containerd/log"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd"
)

const (
	// DefaultHostRoot is where the DaemonSet mounts the host root.
	DefaultHostRoot = "/host"

	// DefaultPayloadDir holds what is installed: bin/ and systemd/ from the
	// image, config/ from the ConfigMap.
	DefaultPayloadDir = "/opt/nydus-snapshotter/payload"

	// DefaultTokenDir is the Pod's projected service account token directory.
	DefaultTokenDir = "/var/run/secrets/kubernetes.io/serviceaccount"

	// DefaultSyncInterval is how often the token and the config are copied to
	// the host, well within the hour a projected token lives.
	DefaultSyncInterval = time.Minute

	// JobTimeout bounds a unit start or restart. Restarting the socket stops
	// the service, then starts the socket and the service again; systemd
	// gives a stop and a start 90s each by default, refer to
	// https://www.freedesktop.org/software/systemd/man/latest/systemd-system.conf.html#DefaultTimeoutStartSec=.
	JobTimeout = 5 * time.Minute

	// serviceUnit is the snapshotter service.
	serviceUnit = "nydus-snapshotter.service"

	// socketUnit is the snapshotter's gRPC socket.
	socketUnit = "nydus-snapshotter.socket"

	// snapshotterBinary is the host path of the snapshotter binary.
	snapshotterBinary = "/usr/local/bin/nydus-snapshotter"

	// unitDir is the host directory of the unit files.
	unitDir = "/etc/systemd/system"

	// restartPending holds the units due a restart until they restart. It
	// lives on tmpfs because a reboot starts the units from the new files
	// anyway.
	restartPending = "/run/nydus-snapshotter/restart-pending"
)

// Config is the installer config.
type Config struct {
	// HostRoot is where the host root is mounted, / when run on the host.
	HostRoot string

	// PayloadDir holds what is installed.
	PayloadDir string

	// TokenDir is the Pod's service account token directory.
	TokenDir string

	// SyncInterval is how often the token and the config are copied to the
	// host.
	SyncInterval time.Duration
}

// Validate checks the config.
func (c *Config) Validate() error {
	if c.SyncInterval <= 0 {
		return fmt.Errorf("invalid sync interval %s", c.SyncInterval)
	}

	return nil
}

// host returns where a host path is in the Pod. Symlinks in its parent
// directories resolve within the host root, as an absolute link on the host
// must, refer to https://github.com/containerd/continuity/blob/main/fs/path.go.
// The last element is kept, so a link itself can be replaced.
func (c *Config) host(path string) (string, error) {
	dir, err := continuityfs.RootPath(c.HostRoot, filepath.Dir(path))
	if err != nil {
		return "", fmt.Errorf("resolve host path %s: %w", path, err)
	}

	return filepath.Join(dir, filepath.Base(path)), nil
}

// payload returns where a payload file is.
func (c *Config) payload(path string) string {
	return filepath.Join(c.PayloadDir, path)
}

// Installer installs the snapshotter onto the host from the DaemonSet Pod.
type Installer struct {
	// cfg is the installer config.
	cfg *Config

	// systemd manages the host's snapshotter units.
	systemd systemd.Manager
}

// New returns an installer that drives the host's units through manager.
func New(cfg *Config, manager systemd.Manager) *Installer {
	return &Installer{cfg: cfg, systemd: manager}
}

// Run checks the host's systemd, syncs the Kubernetes credentials, installs
// the payload and restarts the snapshotter when anything it reads at start
// changed, then keeps the credentials and the config in sync until ctx is
// done. A host whose systemd cannot be used is left untouched. A synced
// config is not followed by a restart: the snapshotter reloads cgroup and
// nydusd.dragonfly itself and reads the template and certs.d per daemon
// start; other keys apply on its next restart. It never stops daemons, edits
// containerd's config or uninstalls.
func (i *Installer) Run(ctx context.Context) error {
	// Check the host's systemd before anything is written to the host, as
	// kubeadm runs its preflight checks before its first change, refer to
	// https://github.com/kubernetes/kubernetes/blob/v1.34.0/cmd/kubeadm/app/cmd/phases/init/preflight.go.
	if err := i.systemd.Ping(ctx); err != nil {
		return err
	}

	// Sync the credentials before the install, so a restarted snapshotter finds
	// a valid token.
	if err := i.syncKubeconfig(ctx); err != nil {
		return err
	}

	if err := i.install(ctx); err != nil {
		return err
	}

	log.G(ctx).Info("installed, keeping the config and the credentials in sync")
	tick := time.NewTicker(i.cfg.SyncInterval)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			if err := i.syncKubeconfig(ctx); err != nil {
				log.G(ctx).WithError(err).Error("sync kubernetes credentials")
			}

			if err := i.syncConfig(ctx); err != nil {
				log.G(ctx).WithError(err).Error("sync config")
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// install copies the payload onto the host, enables the units and starts
// them.
func (i *Installer) install(ctx context.Context) error {
	version, err := i.nydusVersion(ctx)
	if err != nil {
		return err
	}

	files := []file{
		{path: i.nydusBinary(version), perm: 0o755, src: i.cfg.payload(payloadNydusBinary)},
		{path: snapshotterBinary, perm: 0o755, src: i.cfg.payload(payloadSnapshotterBinary)},
		{path: filepath.Join(unitDir, socketUnit), perm: 0o644, src: i.cfg.payload(filepath.Join(payloadUnitDir, socketUnit))},
		{path: filepath.Join(unitDir, serviceUnit), perm: 0o644, src: i.cfg.payload(filepath.Join(payloadUnitDir, serviceUnit))},
	}

	configFiles, err := i.configFiles()
	if err != nil {
		return err
	}

	if err := i.installFiles(ctx, append(files, configFiles...)); err != nil {
		return err
	}

	// Point current at the version only once its binary is in place.
	if err := i.switchVersion(ctx, version); err != nil {
		return err
	}

	if err := i.systemd.EnableUnitFiles(ctx, []string{socketUnit, serviceUnit}); err != nil {
		return err
	}

	return i.startUnits(ctx)
}

// startUnits restarts the units pending a restart, starts the others and
// clears the mark once both are up. A changed socket unit restarts the
// service once, with the socket.
func (i *Installer) startUnits(ctx context.Context) error {
	pending, err := i.pendingRestarts()
	if err != nil {
		return err
	}

	socketPending := slices.Contains(pending, socketUnit)
	if err := i.startUnit(ctx, socketUnit, socketPending); err != nil {
		return err
	}

	// Restarting the socket restarts a running service with it, which
	// Requires= the socket, refer to
	// https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html#Requires=.
	// The service is then only started: a start waits for that restart, where
	// a restart of its own would stop the service as it starts and start it
	// once more.
	if err := i.startUnit(ctx, serviceUnit, slices.Contains(pending, serviceUnit) && !socketPending); err != nil {
		return err
	}

	return i.clearRestarts()
}

// startUnit restarts a unit whose files changed and starts any other, which
// leaves a running unit alone, as a package's maintainer script does, refer
// to
// https://salsa.debian.org/debian/debhelper/-/blob/main/autoscripts/postinst-systemd-restart.
func (i *Installer) startUnit(ctx context.Context, unit string, restart bool) error {
	if restart {
		log.G(ctx).WithField("unit", unit).Info("restarting unit")
		return i.systemd.RestartUnit(ctx, unit)
	}

	return i.systemd.StartUnit(ctx, unit)
}
