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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	continuityfs "github.com/containerd/continuity/fs"
	"github.com/containerd/log"
	"k8s.io/client-go/kubernetes"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd"
)

const (
	// NodeNameEnvVar is the environment variable the DaemonSet sets to the
	// spec.nodeName of the Pod, as node-problem-detector reads its node,
	// refer to
	// https://github.com/kubernetes/node-problem-detector/blob/master/cmd/options/options.go.
	NodeNameEnvVar = "NODE_NAME"

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
	// InstallerConfig is the installer section of the config file, as it was
	// when the installer started.
	config.InstallerConfig

	// Path is the config file to install, the ConfigMap, with certs.d beside
	// it as on the host.
	Path string

	// NodeName is the node to label with NodeLabel, the spec.nodeName of the
	// Pod.
	NodeName string
}

// NewConfig returns the installer config of the config file at path.
//
//	config.yaml (ConfigMap) ──▶ installer section ─┐
//	NODE_NAME (Downward API) ─▶ node name ─────────┴─▶ Config
func NewConfig(path string) (*Config, error) {
	c := &Config{
		InstallerConfig: config.New().Installer,
		Path:            path,
		NodeName:        os.Getenv(NodeNameEnvVar),
	}

	c.load()
	if c.NodeLabel.Enable && c.NodeName == "" {
		return nil, errors.New(NodeNameEnvVar + " must name the node when installer.node_label.enable is set")
	}

	return c, nil
}

// load sets the installer settings from the config file. A file that cannot
// be used is left for the install to reject, and the settings fall back, so
// a broken ConfigMap does not stop the token rotation of a running
// snapshotter. The installed config is looked up under the rootfs directory
// c holds, the default one, where the chart mounts the host.
//
//	config.yaml ─▶ usable ─────────────────────────▶ its installer section
//	            └▶ not usable ─▶ installed config ─▶ its installer section
//	                            └▶ none ───────────▶ the settings c holds
func (c *Config) load() {
	cfg, err := config.Load(c.Path)
	if err == nil {
		c.InstallerConfig = cfg.Installer
		return
	}

	logger := log.L.WithError(err)
	installed, err := c.installed()
	if err != nil {
		logger.WithField("installed", err).Warn("config is not usable and none is installed, keeping the default installer settings")
		return
	}

	logger.Warn("config is not usable, keeping the installer settings of the installed config")
	c.InstallerConfig = installed.Installer
}

// installed returns the config installed on the host.
func (c *Config) installed() (*config.Config, error) {
	path, err := c.host(config.DefaultPath)
	if err != nil {
		return nil, err
	}

	return config.Load(path)
}

// host returns where a host path is in the Pod. Symlinks in its parent
// directories resolve within the host root, as an absolute link on the host
// must, refer to https://github.com/containerd/continuity/blob/main/fs/path.go.
// The last element is kept, so a link itself can be replaced.
func (c *Config) host(path string) (string, error) {
	dir, err := continuityfs.RootPath(c.RootfsDir, filepath.Dir(path))
	if err != nil {
		return "", fmt.Errorf("resolve host path %s: %w", path, err)
	}

	return filepath.Join(dir, filepath.Base(path)), nil
}

// payload returns where a payload file is.
func (c *Config) payload(path string) string {
	return filepath.Join(c.PayloadDir, path)
}

// certsDir returns the certs.d directory to install, beside the config file
// as config.DefaultRegistryConfigPath is on the host.
func (c *Config) certsDir() string {
	return filepath.Join(filepath.Dir(c.Path), filepath.Base(config.DefaultRegistryConfigPath))
}

// Installer installs the snapshotter onto the host from the DaemonSet Pod.
type Installer struct {
	// cfg is the installer config.
	cfg *Config

	// systemd manages the host's snapshotter units.
	systemd systemd.Manager

	// kubeClient is the client of the API server the node is labeled
	// through, built once.
	kubeClient kubernetes.Interface

	// snapshotterAddr is the snapshotter's socket on the host, read once
	// from the config installed there.
	snapshotterAddr string

	// notReadyChecks is how many checks in a row found the node not ready.
	notReadyChecks int

	// notReady is why the node had no label coming at the last sync, empty
	// when it had.
	notReady string
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
// nydusd.config itself and reads certs.d per daemon start; other keys apply
// on its next restart. Only with installer.node_label.enable it labels the
// node while the snapshotter serves and containerd has loaded it. It never
// stops daemons, edits containerd's config, removes the label when it stops
// or uninstalls.
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

	// The snapshotter just started serves a moment later, with kube_secret
	// once the secrets are listed.
	i.waitServing(ctx)
	if err := i.syncNodeLabel(ctx); err != nil {
		log.G(ctx).WithError(err).Error("sync node label")
	}

	log.G(ctx).Info("installed, keeping the config and the credentials in sync")
	tick := time.NewTicker(time.Duration(i.cfg.SyncInterval))
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

			if err := i.syncNodeLabel(ctx); err != nil {
				log.G(ctx).WithError(err).Error("sync node label")
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
