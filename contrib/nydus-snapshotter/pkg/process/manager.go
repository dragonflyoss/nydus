/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package process

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/containerd/containerd/log"
	"github.com/pkg/errors"

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/config"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/daemon"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/errdefs"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/store"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/utils/mount"
)

type configGenerator = func(*daemon.Daemon) error

type Manager struct {
	store            Store
	nydusdBinaryPath string
	DaemonMode       string
	mounter          mount.Interface
	mu               sync.Mutex
}

type Opt struct {
	NydusdBinaryPath string
	Database         *store.Database
	DaemonMode       string
}

func NewManager(opt Opt) (*Manager, error) {
	s, err := store.NewDaemonStore(opt.Database)
	if err != nil {
		return nil, err
	}

	return &Manager{
		store:            s,
		mounter:          &mount.Mounter{},
		nydusdBinaryPath: opt.NydusdBinaryPath,
		DaemonMode:       opt.DaemonMode,
	}, nil
}

func (m *Manager) NewDaemon(daemon *daemon.Daemon) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.store.GetBySnapshot(daemon.SnapshotID)
	if err == nil && d != nil {
		return errdefs.ErrAlreadyExists
	}
	return m.store.Add(daemon)
}

func (m *Manager) DeleteBySnapshotID(id string) (*daemon.Daemon, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.store.GetBySnapshot(id)
	if err != nil {
		return nil, err
	}
	m.store.Delete(s)
	return s, nil
}

func (m *Manager) GetBySnapshotID(id string) (*daemon.Daemon, error) {
	return m.store.GetBySnapshot(id)
}

func (m *Manager) GetByID(id string) (*daemon.Daemon, error) {
	return m.store.Get(id)
}

func (m *Manager) DeleteDaemon(daemon *daemon.Daemon) {
	if daemon == nil {
		return
	}
	m.store.Delete(daemon)
}

func (m *Manager) ListDaemons() []*daemon.Daemon {
	return m.store.List()
}

func (m *Manager) CleanUpDaemonResource(d *daemon.Daemon) {
	resource := []string{d.ConfigDir, d.LogDir}
	if d.IsMultipleDaemon() {
		resource = append(resource, d.SocketDir)
	}
	for _, dir := range resource {
		if err := os.RemoveAll(dir); err != nil {
			log.L.Errorf("failed to remove dir %s err %v", dir, err)
		}
	}
}

func (m *Manager) StartDaemon(d *daemon.Daemon) error {
	// if cg != nil {
	// 	err := cg(d)
	// 	if err != nil {
	// 		return err
	// 	}
	// }
	cmd, err := m.buildStartCommand(d)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to create start command for daemon %s", d.ID))
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	d.Pid = cmd.Process.Pid
	// process wait when destroy daemon and kill process
	return nil

}

func (m *Manager) buildStartCommand(d *daemon.Daemon) (*exec.Cmd, error) {
	args := []string{
		"--apisock", d.APISock(),
		"--log-level", "info",
		"--log-file", d.LogFile(),
		"--thread-num", "10",
	}
	if d.IsMultipleDaemon() {
		bootstrap, err := d.BootstrapFile()
		if err != nil {
			return nil, err
		}
		args = append(args,
			"--config",
			d.ConfigFile(),
			"--bootstrap",
			bootstrap,
			"--mountpoint",
			d.MountPoint(),
		)
	} else {
		args = append(args,
			"--mountpoint",
			*d.RootMountPoint,
		)
	}
	return exec.Command(m.nydusdBinaryPath, args...), nil
}

func (m *Manager) DestroyBySnapshotID(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.store.GetBySnapshot(id)
	if err != nil {
		return err
	}
	return m.DestroyDaemon(d)
}

func (m *Manager) DestroyDaemon(d *daemon.Daemon) error {
	m.store.Delete(d)
	m.CleanUpDaemonResource(d)
	log.L.Infof("umount remote snapshot, mountpoint %s", d.MountPoint())
	// if daemon is shared mount, we should only umount the daemon with api instead of
	// umount entire mountpoint
	if d.IsSharedDaemon() {
		return d.SharedUmount()
	}
	// if we found pid here, we need to kill and wait process to exit, Pid=0 means somehow we lost
	// the daemon pid, so that we can't kill the process, just roughly umount the mountpoint
	if d.Pid > 0 {
		p, err := os.FindProcess(d.Pid)
		if err != nil {
			return err
		}
		err = p.Signal(syscall.SIGTERM)
		if err != nil {
			return err
		}
		_, err = p.Wait()
		if err != nil {
			return err
		}
	}
	if err := m.mounter.Umount(d.MountPoint()); err != nil && err != syscall.EINVAL {
		return errors.Wrap(err, fmt.Sprintf("failed to umount mountpoint %s", d.MountPoint()))
	}
	return nil
}

func (m *Manager) IsSharedDaemon() bool {
	return m.DaemonMode == config.DaemonModeShared || m.DaemonMode == config.DaemonModeSingle
}

// Reconnect already running daemons，and rebuild daemons management structs.
func (m *Manager) Reconnect(ctx context.Context) error {
	var (
		daemons      []*daemon.Daemon
		sharedDaemon *daemon.Daemon = nil
	)

	if err := m.store.WalkDaemons(ctx, func(d *daemon.Daemon) error {
		log.L.WithField("daemon", d.ID).
			WithField("shared", d.IsSharedDaemon()).
			Info("found daemon in database")

		// Do not check status on virtual daemons
		if m.IsSharedDaemon() && d.ID != daemon.SharedNydusDaemonID {
			daemons = append(daemons, d)
			log.L.WithField("daemon", d.ID).Infof("found virtual daemon")
			return nil
		}

		_, err := d.CheckStatus()
		if err != nil {
			log.L.WithField("daemon", d.ID).Warnf("failed to check daemon status")
			return nil
		}
		log.L.WithField("daemon", d.ID).Infof("found alive daemon")
		daemons = append(daemons, d)

		// Get the global shared daemon here after CheckStatus() by attention
		// so that we're sure it's alive.
		if d.ID == daemon.SharedNydusDaemonID {
			sharedDaemon = d
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "failed to walk daemons to reconnect")
	}

	if !m.IsSharedDaemon() && sharedDaemon != nil {
		return errors.Errorf("SharedDaemon disabled, but shared daemon is found")
	}

	if m.IsSharedDaemon() && sharedDaemon == nil && len(daemons) > 0 {
		log.L.Warnf("SharedDaemon enabled, but cannot find alive shared daemon")
		// Clear daemon list to skip adding them into daemon store
		daemons = nil
	}

	// cleanup database so that we'll have a clean database for this snapshotter process lifetime
	log.L.Infof("found %d daemons running", len(daemons))
	if err := m.store.CleanupDaemons(ctx); err != nil {
		return errors.Wrapf(err, "failed to cleanup database")
	}

	for _, d := range daemons {
		if err := m.NewDaemon(d); err != nil {
			return errors.Wrapf(err, "failed to add daemon(%s) to daemon store", d.ID)
		}
	}

	return nil
}
