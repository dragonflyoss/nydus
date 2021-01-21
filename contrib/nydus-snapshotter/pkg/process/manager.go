/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package process

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/containerd/containerd/log"
	"github.com/pkg/errors"

	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/daemon"
	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/errdefs"
	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/store"
	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/utils/mount"
)

type configGenerator = func(*daemon.Daemon) error

type Manager struct {
	store            Store
	nydusdBinaryPath string
	mounter          mount.Interface
	mu               sync.Mutex
}

type Opt struct {
	NydusdBinaryPath string
}

func NewManager(opt Opt) *Manager {
	return &Manager{
		store:            store.NewDaemonStore(),
		mounter:          &mount.Mounter{},
		nydusdBinaryPath: opt.NydusdBinaryPath,
	}
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
	_ = d.Stderr.Close()
	_ = d.Stdout.Close()
	resource := []string{d.ConfigDir, d.LogDir}
	if !d.SharedDaemon {
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
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to get stderr pipe for daemon %s", d.ID))
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	d.Process = cmd.Process
	// make sure to wait after start
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			log.L.WithField("daemon", d.ID).Debug(scanner.Text())
		}
		log.L.WithField("daemon", d.ID).Info("quits")
		cmd.Wait()
	}()
	return nil
}

func (m *Manager) buildStartCommand(d *daemon.Daemon) (*exec.Cmd, error) {
	args := []string{
		"--apisock", d.APISock(),
		"--log-level", "info",
		"--thread-num", "10",
	}
	if !d.SharedDaemon {
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
	// The process only needs to be wait if it's a non shared daemon.
	if d.Process != nil && !d.SharedDaemon {
		err := d.Process.Kill()
		if err != nil {
			return err
		}
		_, err = d.Process.Wait()
		if err != nil {
			return err
		}
	}
	err := m.mounter.Umount(d.MountPoint())
	// EINVAL means it already is not a mount point
	if err != nil && err != syscall.EINVAL {
		return errors.Wrap(err, fmt.Sprintf("failed to umount mountpoint %s", d.MountPoint()))
	}
	return nil
}
