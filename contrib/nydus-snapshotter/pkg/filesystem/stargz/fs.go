/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package stargz

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/snapshots/storage"
	"github.com/pkg/errors"

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/config"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/auth"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/daemon"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/errdefs"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/filesystem/fs"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/filesystem/meta"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/label"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/process"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/utils/retry"
)

type filesystem struct {
	meta.FileSystemMeta
	manager               *process.Manager
	daemonCfg             config.DaemonConfig
	resolver              *Resolver
	vpcRegistry           bool
	nydusdBinaryPath      string
	nydusdImageBinaryPath string
}

func NewFileSystem(ctx context.Context, opt ...NewFSOpt) (fs.FileSystem, error) {
	var fs filesystem
	for _, o := range opt {
		err := o(&fs)
		if err != nil {
			return nil, err
		}
	}
	fs.resolver = NewResolver()

	return &fs, nil
}

func parseLabels(labels map[string]string) (rRef, rDigest string) {
	if ref, ok := labels[label.ImageRef]; ok {
		rRef = ref
	}
	if layerDigest, ok := labels[label.CRIDigest]; ok {
		rDigest = layerDigest
	}
	return
}

func (f *filesystem) PrepareLayer(ctx context.Context, s storage.Snapshot, labels map[string]string) error {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		log.G(ctx).Infof("total stargz prepare layer duration %d", duration.Milliseconds())
	}()
	ref, layerDigest := parseLabels(labels)
	if ref == "" || layerDigest == "" {
		return fmt.Errorf("can not find ref and digest from label %+v", labels)
	}
	keychain := auth.FromLabels(labels)
	blob, err := f.resolver.GetBlob(ref, layerDigest, keychain)
	if err != nil {
		return errors.Wrapf(err, "failed to get blob from ref %s, digest %s", ref, layerDigest)
	}
	r, err := blob.ReadToc()
	if err != nil {
		return errors.Wrapf(err, "failed to read toc from ref %s, digest %s", ref, layerDigest)
	}
	starGzToc, err := os.OpenFile(filepath.Join(f.UpperPath(s.ID), stargzToc), os.O_CREATE|os.O_RDWR, 0755)
	if err != nil {
		return errors.Wrap(err, "failed to create stargz index")
	}
	_, err = io.Copy(starGzToc, r)
	if err != nil {
		return errors.Wrap(err, "failed to save stargz index")
	}
	options := []string{
		"create",
		"--source-type", "stargz_index",
		"--bootstrap", filepath.Join(f.UpperPath(s.ID), "image.boot"),
		"--blob-id", digest(layerDigest).Sha256(),
		"--repeatable",
		"--disable-check",
	}
	if getParentSnapshotID(s) != "" {
		parentBootstrap := filepath.Join(f.UpperPath(getParentSnapshotID(s)), "image.boot")
		if _, err := os.Stat(parentBootstrap); err != nil {
			return fmt.Errorf("failed to find parentBootstrap from %s", parentBootstrap)
		}
		options = append(options,
			"--parent-bootstrap", parentBootstrap)
	}
	options = append(options, filepath.Join(f.UpperPath(s.ID), stargzToc))
	log.G(ctx).Infof("nydus image command %v", options)
	cmd := exec.Command(f.nydusdImageBinaryPath, options...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	return cmd.Run()
}

func getParentSnapshotID(s storage.Snapshot) string {
	if len(s.ParentIDs) == 0 {
		return ""
	}
	return s.ParentIDs[0]
}

func (f *filesystem) Support(ctx context.Context, labels map[string]string) bool {
	ref, layerDigest := parseLabels(labels)
	if ref == "" || layerDigest == "" {
		return false
	}
	log.G(ctx).Infof("image ref %s digest %s", ref, layerDigest)
	keychain := auth.FromLabels(labels)
	blob, err := f.resolver.GetBlob(ref, layerDigest, keychain)
	if err != nil {
		return false
	}
	off, err := blob.getTocOffset()
	return err == nil && off > 0
}

func (f *filesystem) createNewDaemon(snapshotID string, imageID string) (*daemon.Daemon, error) {
	d, err := daemon.NewDaemon(
		daemon.WithSnapshotID(snapshotID),
		daemon.WithSocketDir(f.SocketRoot()),
		daemon.WithConfigDir(f.ConfigRoot()),
		daemon.WithSnapshotDir(f.SnapshotRoot()),
		daemon.WithLogDir(f.LogRoot()),
		daemon.WithCacheDir(f.CacheRoot()),
		daemon.WithImageID(imageID),
	)
	if err != nil {
		return nil, err
	}
	err = f.manager.NewDaemon(d)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (f *filesystem) Mount(ctx context.Context, snapshotID string, labels map[string]string) error {
	imageID, ok := labels[label.ImageRef]
	if !ok {
		return fmt.Errorf("failed to find image ref of snapshot %s, labels %v", snapshotID, labels)
	}
	d, err := f.createNewDaemon(snapshotID, imageID)
	// if daemon already exists for snapshotID, just return
	if err != nil {
		if errdefs.IsAlreadyExists(err) {
			return nil
		}
		return err
	}
	defer func() {
		if err != nil {
			_ = f.manager.DestroyDaemon(d)
		}
	}()
	err = f.mount(d, labels)
	if err != nil {
		return errors.Wrapf(err, "failed to start daemon %s", d.ID)
	}
	return nil
}

func (fs *filesystem) BootstrapFile(id string) (string, error) {
	panic("stargz has no bootstrap file")
}

func (fs *filesystem) NewDaemonConfig(labels map[string]string) (config.DaemonConfig, error) {
	panic("implement me")
}

func (f *filesystem) mount(d *daemon.Daemon, labels map[string]string) error {
	err := f.generateDaemonConfig(d, labels)
	if err != nil {
		return err
	}
	return f.manager.StartDaemon(d)
}

func (f *filesystem) generateDaemonConfig(d *daemon.Daemon, labels map[string]string) error {
	cfg, err := config.NewDaemonConfig(f.daemonCfg, d.ImageID, f.vpcRegistry, labels)
	if err != nil {
		return errors.Wrapf(err, "failed to generate daemon config for daemon %s", d.ID)
	}
	cfg.Device.Cache.Compressed = true
	cfg.DigestValidate = false
	return config.SaveConfig(cfg, d.ConfigFile())
}

func (f *filesystem) WaitUntilReady(ctx context.Context, snapshotID string) error {
	s, err := f.manager.GetBySnapshotID(snapshotID)
	if err != nil {
		return err
	}
	return retry.Do(func() error {
		info, err := s.CheckStatus()
		if err != nil {
			return err
		}
		log.G(ctx).Infof("daemon %s snapshotID %s info %v", s.ID, snapshotID, info)
		if info.State != "Running" {
			return errors.Wrap(err, fmt.Sprintf("daemon %s snapshotID %s is not ready", s.ID, snapshotID))
		}
		return nil
	},
		retry.Attempts(3),
		retry.LastErrorOnly(true),
		retry.Delay(100*time.Millisecond),
	)
}

func (f *filesystem) Umount(ctx context.Context, mountPoint string) error {
	id := filepath.Base(mountPoint)
	log.G(ctx).Infof("umount nydus daemon of id %s, mountpoint %s", id, mountPoint)
	return f.manager.DestroyBySnapshotID(id)
}

func (f *filesystem) Cleanup(ctx context.Context) error {
	for _, d := range f.manager.ListDaemons() {
		err := f.Umount(ctx, filepath.Dir(d.MountPoint()))
		if err != nil {
			log.G(ctx).Infof("failed to umount %s err %+v", d.MountPoint(), err)
		}
	}
	return nil
}

func (f *filesystem) MountPoint(snapshotID string) (string, error) {
	if d, err := f.manager.GetBySnapshotID(snapshotID); err == nil {
		return d.MountPoint(), nil
	}
	return "", fmt.Errorf("failed to find mountpoint of snapshot %s", snapshotID)
}
