/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package installer installs the snapshotter onto the host from the DaemonSet
// Pod and keeps its config and Kubernetes credentials in sync.
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
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/util/kubeutil"
)

const (
	// NodeNameEnvVar is the environment variable the DaemonSet sets to the
	// spec.nodeName of the Pod.
	NodeNameEnvVar = "NODE_NAME"

	// nydusSnapshotterServiceUnit is the snapshotter service. It carries the
	// major version so it runs beside a v2 snapshotter, whose deploy script
	// installs, stops and removes nydus-snapshotter.service by name, refer to
	// https://github.com/containerd/nydus-snapshotter/blob/main/misc/snapshotter/snapshotter.sh.
	nydusSnapshotterServiceUnit = "nydus-snapshotter-v3.service"

	// nydusSnapshotterBinary is the snapshotter binary. The image keeps what
	// it installs at the path it has on the host.
	nydusSnapshotterBinary = "/usr/local/bin/nydus-snapshotter"

	// nydusBinary is the nydus binary of the image. On the host each version
	// has a directory of its own, see nydusBinaryVersionsDir.
	nydusBinary = "/usr/local/bin/nydus"

	// nydusBinaryVersionsDir holds the nydus binary of each version on the
	// host. nydusd.binary is a link to the installed one.
	nydusBinaryVersionsDir = "/opt/nydus-snapshotter/versions"

	// unitDir is the directory of the unit files, in the image and on the
	// host.
	unitDir = "/etc/systemd/system"

	// hostRootMount is where the DaemonSet mounts the root filesystem of the host.
	hostRootMount = "/host"

	// restartRequiredFile marks the service due a restart until it restarts.
	// It is at a path no config change can move, so the next install finds
	// it, and on tmpfs because a reboot starts the service from the new files
	// anyway.
	restartRequiredFile = "/run/nydus-snapshotter/restart-required"
)

// Installer installs the snapshotter onto the host from the DaemonSet Pod.
type Installer struct {
	// cfg is the config the installer started with. Its installer section
	// holds the installer's own settings.
	cfg *config.Config

	// configPath is the config file of the ConfigMap, which every sync reads
	// again and copies to the host.
	configPath string

	// nodeName is the node to label with NodeLabel, the spec.nodeName of the
	// Pod.
	nodeName string

	// systemd manages the host's snapshotter units.
	systemd systemd.Systemd

	// kubeClient is the client of the API server the node is labeled
	// through, nil without installer.node_label.enable.
	kubeClient kubernetes.Interface
}

// New returns an installer that drives the host's units through systemd. The
// file at configPath is used twice: cfg, loaded from it at start, holds the
// installer's own settings, and every sync reads the file again to copy it
// to the host, so a ConfigMap update reaches the snapshotter.
//
//	                         ┌─ cfg, loaded at start ──▶ installer settings
//	config.yaml (ConfigMap) ─┤
//	                         └─ configPath, each sync ─▶ config.yaml on the host
//	NODE_NAME (Downward API) ──▶ node name
func New(cfg *config.Config, configPath string, systemd systemd.Systemd) (*Installer, error) {
	i := &Installer{
		cfg:        cfg,
		configPath: configPath,
		nodeName:   os.Getenv(NodeNameEnvVar),
		systemd:    systemd,
	}

	if err := i.validate(); err != nil {
		return nil, err
	}

	// A client that cannot be built stops the installer before it touches the
	// host.
	if cfg.Installer.NodeLabel.Enable {
		kubeClient, err := kubeutil.NewClient(cfg.Installer.ServiceAccountPath)
		if err != nil {
			return nil, err
		}

		i.kubeClient = kubeClient
	}

	return i, nil
}

// validate checks what the installer needs besides its config.
func (i *Installer) validate() error {
	// The label goes on the node of the Pod.
	if i.cfg.Installer.NodeLabel.Enable && i.nodeName == "" {
		return errors.New(NodeNameEnvVar + " must name the node when installer.node_label.enable is set")
	}

	return nil
}

// Run checks the host's systemd, syncs the Kubernetes credentials, installs
// the files of the image and restarts the snapshotter when anything it reads
// at start changed, then keeps the credentials and the config in sync until
// ctx is done. A host whose systemd cannot be used is left untouched. A
// synced config is not followed by a restart: the snapshotter reloads cgroup
// and nydusd.config itself and reads certs.d per daemon start; other keys
// apply on its next restart. Only with installer.node_label.enable it labels
// the node while the snapshotter serves and containerd has loaded it. It
// never stops daemons, edits containerd's config, removes the label when it
// stops or uninstalls.
func (i *Installer) Run(ctx context.Context) error {
	// Check the host's systemd before anything is written to the host.
	if err := i.systemd.Ping(ctx); err != nil {
		return err
	}

	// Sync the credentials before the install, so a restarted snapshotter finds
	// a valid token.
	if i.cfg.Auth.KubeSecret.Enable {
		if err := i.syncKubeconfig(ctx); err != nil {
			return err
		}
	}

	// Install the binaries, the units and the config, then start the units.
	if err := i.install(ctx); err != nil {
		return err
	}

	// The snapshotter just started serves a moment later, with kube_secret
	// once the secrets are listed.
	if i.cfg.Installer.NodeLabel.Enable {
		i.waitForNydusSnapshotter(ctx)
		if err := i.syncNodeLabel(ctx); err != nil {
			log.G(ctx).WithError(err).Error("sync node label")
		}
	}

	log.G(ctx).Info("installed, keeping the config and the credentials in sync")
	tick := time.NewTicker(time.Duration(i.cfg.Installer.SyncInterval))
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			if i.cfg.Auth.KubeSecret.Enable {
				if err := i.syncKubeconfig(ctx); err != nil {
					log.G(ctx).WithError(err).Error("sync kubernetes credentials")
				}
			}

			if err := i.syncConfig(ctx); err != nil {
				log.G(ctx).WithError(err).Error("sync config")
			}

			if i.cfg.Installer.NodeLabel.Enable {
				if err := i.syncNodeLabel(ctx); err != nil {
					log.G(ctx).WithError(err).Error("sync node label")
				}
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// install copies the files of the image and the config onto the host,
// enables the service and starts it.
func (i *Installer) install(ctx context.Context) error {
	version, err := i.nydusBinaryVersion(ctx)
	if err != nil {
		return err
	}

	configFiles, err := i.configFiles()
	if err != nil {
		return err
	}

	files := slices.Concat(i.binaryFiles(version), i.unitFiles(), configFiles)

	// Without the switch the host keeps the certs.d it has.
	if i.cfg.Installer.Registries.Enable {
		certsFiles, err := i.certsFiles()
		if err != nil {
			return err
		}

		files = append(files, certsFiles...)
	}

	if err := i.installFiles(ctx, files); err != nil {
		return err
	}

	// Link nydusd.binary to the version only once its binary is in place.
	if err := i.switchNydusBinaryVersion(ctx, version); err != nil {
		return err
	}

	if err := i.systemd.EnableUnitFiles(ctx, []string{nydusSnapshotterServiceUnit}); err != nil {
		return err
	}

	return i.startOrRestartNydusSnapshotter(ctx)
}

// startOrRestartNydusSnapshotter restarts the service when a restart is
// required and removes the restart-required file once it is up. Otherwise it
// starts the service, which leaves a running one alone.
func (i *Installer) startOrRestartNydusSnapshotter(ctx context.Context) error {
	restart, err := i.restartRequired()
	if err != nil {
		return err
	}

	if restart {
		log.G(ctx).WithField("unit", nydusSnapshotterServiceUnit).Info("restarting unit")
		if err := i.systemd.RestartUnit(ctx, nydusSnapshotterServiceUnit); err != nil {
			return err
		}

		return i.removeRestartRequiredFile()
	}

	return i.systemd.StartUnit(ctx, nydusSnapshotterServiceUnit)
}

// containerPath returns where the DaemonSet mounts a host path in the
// container, under hostRootMount. Symlinks in its parent directories resolve
// within the mount, as an absolute link on the host must. The last element
// is kept, so a link itself can be replaced.
func (i *Installer) containerPath(hostPath string) (string, error) {
	dir, err := continuityfs.RootPath(hostRootMount, filepath.Dir(hostPath))
	if err != nil {
		return "", fmt.Errorf("resolve host path %s: %w", hostPath, err)
	}

	return filepath.Join(dir, filepath.Base(hostPath)), nil
}
