// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

package nydus

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/pkg/errors"

	"github.com/docker/docker/daemon/graphdriver"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/containerfs"
	"github.com/docker/docker/pkg/directory"
	"github.com/docker/docker/pkg/idtools"
	"github.com/docker/docker/pkg/system"
	"github.com/moby/sys/mountinfo"
	"github.com/opencontainers/selinux/go-selinux/label"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// With nydus image layer, there won't be plenty of layers that need to be stacked.
const (
	diffDirName       = "diff"
	workDirName       = "work"
	mergedDirName     = "merged"
	lowerFile         = "lower"
	nydusDirName      = "nydus"
	nydusMetaRelapath = "image/image.boot"
	parentFile        = "parent"
)

var backingFs = "<unknown>"

func isFileExisted(file string) (bool, error) {
	if _, err := os.Stat(file); err == nil {
		return true, nil
	} else if os.IsNotExist(err) {
		return false, nil
	} else {
		return false, err
	}
}

// Nydus graphdriver contains information about the home directory and the list of active
// mounts that are created using this driver.
type Driver struct {
	home            string
	nydus           *Nydus
	NydusMountpoint string
	uidMaps         []idtools.IDMap
	gidMaps         []idtools.IDMap
	ctr             *graphdriver.RefCounter
}

func (d *Driver) dir(id string) string {
	return path.Join(d.home, id)
}

func Init(home string, options []string, uidMaps, gidMaps []idtools.IDMap) (graphdriver.Driver, error) {

	os.MkdirAll(home, os.ModePerm)

	fsMagic, err := graphdriver.GetFSMagic(home)
	if err != nil {
		return nil, err
	}
	if fsName, ok := graphdriver.FsNames[fsMagic]; ok {
		backingFs = fsName
	}

	// check if they are running over btrfs, aufs, zfs, overlay, or ecryptfs
	switch fsMagic {
	case graphdriver.FsMagicBtrfs, graphdriver.FsMagicAufs, graphdriver.FsMagicZfs, graphdriver.FsMagicOverlay, graphdriver.FsMagicEcryptfs:
		logrus.Errorf("'overlay2' is not supported over %s", backingFs)
		return nil, graphdriver.ErrIncompatibleFS
	}

	return &Driver{
		home:    home,
		uidMaps: uidMaps,
		gidMaps: gidMaps,
		ctr:     graphdriver.NewRefCounter(graphdriver.NewFsChecker(graphdriver.FsMagicOverlay))}, nil
}

// Status returns current driver information in a two dimensional string array.
// Output contains "Backing Filesystem" used in this implementation.
func (d *Driver) Status() [][2]string {
	return [][2]string{
		{"Backing Filesystem", backingFs},
		// TODO: Add nydusd working status and version here.
		{"Nydusd", "TBD"},
	}
}

func (d *Driver) String() string {
	return "Nydus graph driver"
}

// GetMetadata returns meta data about the overlay driver such as
// LowerDir, UpperDir, WorkDir and MergeDir used to store data.
func (d *Driver) GetMetadata(id string) (map[string]string, error) {

	dir := d.dir(id)
	if _, err := os.Stat(dir); err != nil {
		return nil, err
	}

	metadata := map[string]string{
		"WorkDir":   path.Join(dir, "work"),
		"MergedDir": path.Join(dir, "merged"),
		"UpperDir":  path.Join(dir, "diff"),
	}

	lowerDirs, err := d.getLowerDirs(id)
	if err != nil {
		return nil, err
	}

	if len(lowerDirs) > 0 {
		metadata["LowerDir"] = strings.Join(lowerDirs, ":")
	}

	return metadata, nil
}

// Cleanup any state created by overlay which should be cleaned when daemon
// is being shutdown. For now, we just have to unmount the bind mounted
// we had created.
func (d *Driver) Cleanup() error {
	if d.nydus != nil {
		d.nydus.command.Process.Signal(os.Interrupt)
		d.nydus.command.Wait()
	}

	return nil
}

// CreateReadWrite creates a layer that is writable for use as a container
// file system.
func (d *Driver) CreateReadWrite(id, parent string, opts *graphdriver.CreateOpts) error {
	logrus.Infof("Create read write - id %s parent %s", id, parent)
	return d.Create(id, parent, opts)
}

// Create is used to create the upper, lower, and merged directories required for
// overlay fs for a given id.
// The parent filesystem is used to configure these directories for the overlay.
func (d *Driver) Create(id, parent string, opts *graphdriver.CreateOpts) (retErr error) {
	logrus.Infof("Create. id %s, parent %s", id, parent)

	dir := d.dir(id)

	rootUID, rootGID, err := idtools.GetRootUIDGID(d.uidMaps, d.gidMaps)
	if err != nil {
		return err
	}
	root := idtools.Identity{UID: rootUID, GID: rootGID}

	if err := idtools.MkdirAllAndChown(path.Dir(dir), 0700, root); err != nil {
		return err
	}
	if err := idtools.MkdirAndChown(dir, 0700, root); err != nil {
		return err
	}

	defer func() {
		// Clean up on failure
		if retErr != nil {
			os.RemoveAll(dir)
		}
	}()

	if err := idtools.MkdirAndChown(path.Join(dir, diffDirName), 0755, root); err != nil {
		return err
	}

	// if no parent directory, done
	if parent == "" {
		return nil
	}

	if err := idtools.MkdirAndChown(path.Join(dir, mergedDirName), 0700, root); err != nil {
		return err
	}

	if err := idtools.MkdirAndChown(path.Join(dir, workDirName), 0700, root); err != nil {
		return err
	}

	if err := ioutil.WriteFile(path.Join(dir, parentFile), []byte(parent), 0666); err != nil {
		return err
	}

	if parentLowers, err := d.getLowerDirs(parent); err == nil {
		lowers := strings.Join(append(parentLowers, parent), ":")
		lowerFilePath := path.Join(d.dir(id), lowerFile)

		if len(lowers) > 0 {
			if err := ioutil.WriteFile(lowerFilePath, []byte(lowers), 0666); err != nil {
				return err
			}
		}
	} else {
		return err
	}

	return nil
}

func (d *Driver) getLowerDirs(id string) ([]string, error) {
	var lowersArray []string
	lowers, err := ioutil.ReadFile(path.Join(d.dir(id), lowerFile))
	if err == nil {
		lowersArray = strings.Split(string(lowers), ":")
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	return lowersArray, nil
}

// Remove cleans the directories that are created for this id.
func (d *Driver) Remove(id string) error {
	logrus.Infof("Remove %s", id)

	dir := d.dir(id)

	if err := system.EnsureRemoveAll(dir); err != nil && !os.IsNotExist(err) {
		return errors.Errorf("Can't remove %s", dir)
	}

	return nil
}

// Get creates and mounts the required file system for the given id and returns the mount path.
// The `id` is mount-id.
func (d *Driver) Get(id, mountLabel string) (fs containerfs.ContainerFS, retErr error) {
	logrus.Infof("Mount layer - id %s, label %s", id, mountLabel)

	dir := d.dir(id)
	if _, err := os.Stat(dir); err != nil {
		return nil, err
	}

	var lowers []string
	lowers, retErr = d.getLowerDirs(id)
	if retErr != nil {
		return
	}

	for _, l := range lowers {
		if l == id {
			break
		}

		// Encounter nydus layer, start nydusd daemon, thus to mount rafs as
		// overlay lower dir for later use.
		if isNydus, err := d.isNydusLayer(l); isNydus {
			if mounted, err := d.isNydusMounted(l); !mounted {
				bootstrapPath := path.Join(d.dir(l), diffDirName, nydusMetaRelapath)
				absMountpoint := path.Join(d.dir(l), nydusDirName)

				rootUID, rootGID, err := idtools.GetRootUIDGID(d.uidMaps, d.gidMaps)
				if err != nil {
					return nil, err
				}

				root := idtools.Identity{UID: rootUID, GID: rootGID}
				if err := idtools.MkdirAllAndChown(absMountpoint, 0700, root); err != nil {
					return nil, errors.Wrap(err, "failed in creating nydus mountpoint")
				}

				nydus := New()
				// Keep it, so we can wait for process termination.
				d.nydus = nydus
				if e := nydus.Mount(bootstrapPath, absMountpoint); e != nil {
					return nil, e
				}

			} else if err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		}

		// Relative path
		nydusRelaMountpoint := path.Join(l, nydusDirName)
		if _, err := os.Stat(path.Join(d.home, nydusRelaMountpoint)); err == nil {
			lowers = append(lowers, nydusRelaMountpoint)
		} else {
			diffDir := path.Join(l, "diff")
			if _, err := os.Stat(diffDir); err == nil {
				lowers = append(lowers, diffDir)
			}
		}
	}

	mergedDir := path.Join(dir, mergedDirName)
	if count := d.ctr.Increment(mergedDir); count > 1 {
		return containerfs.NewLocalContainerFS(mergedDir), nil
	}

	defer func() {
		if retErr != nil {
			if c := d.ctr.Decrement(mergedDir); c <= 0 {

				if err := unix.Unmount(mergedDir, 0); err != nil {
					logrus.Warnf("unmount error %v: %v", mergedDir, err)
				}

				if err := unix.Rmdir(mergedDir); err != nil && !os.IsNotExist(err) {
					logrus.Warnf("failed to remove %s: %v", id, err)
				}
			}
		}
	}()

	os.Chdir(path.Join(d.home))

	upperDir := path.Join(id, diffDirName)
	workDir := path.Join(id, workDirName)
	opts := "lowerdir=" + strings.Join(lowers, ":") + ",upperdir=" + upperDir + ",workdir=" + workDir

	mountData := label.FormatMountLabel(opts, mountLabel)
	mount := unix.Mount
	mountTarget := mergedDir

	logrus.Infof("mount options %s, target %s", opts, mountTarget)

	rootUID, rootGID, err := idtools.GetRootUIDGID(d.uidMaps, d.gidMaps)
	if err != nil {
		return nil, err
	}

	if err := idtools.MkdirAndChown(mergedDir, 0700, idtools.Identity{UID: rootUID, GID: rootGID}); err != nil {
		return nil, err
	}

	pageSize := unix.Getpagesize()

	if len(mountData) > pageSize {
		return nil, fmt.Errorf("cannot mount layer, mount label too large %d", len(mountData))

	}

	if err := mount("overlay", mountTarget, "overlay", 0, mountData); err != nil {
		return nil, fmt.Errorf("error creating overlay mount to %s: %v", mergedDir, err)
	}

	// chown "workdir/work" to the remapped root UID/GID. Overlay fs inside a
	// user namespace requires this to move a directory from lower to upper.
	if err := os.Chown(path.Join(workDir, workDirName), rootUID, rootGID); err != nil {
		return nil, err
	}

	return containerfs.NewLocalContainerFS(mergedDir), nil
}

func (d *Driver) isNydusLayer(id string) (bool, error) {
	dir := d.dir(id)
	bootstrapPath := path.Join(dir, diffDirName, nydusMetaRelapath)
	return isFileExisted(bootstrapPath)
}

func (d *Driver) isNydusMounted(id string) (bool, error) {

	if isNydus, err := d.isNydusLayer(id); !isNydus {
		return isNydus, err
	}

	mp := path.Join(d.dir(id), nydusDirName)

	if exited, err := isFileExisted(mp); !exited {
		return exited, err
	}

	if mounted, err := mountinfo.Mounted(mp); !mounted {
		return mounted, err
	}

	return true, nil
}

// Put unmounts the mount path created for the give id.
func (d *Driver) Put(id string) error {
	if mounted, _ := d.isNydusMounted(id); mounted {
		if d.nydus != nil {
			// Signal to nydusd causes it umount itself before terminating.
			// So we don't have to invoke os/umount here.
			// Note: this only umount nydusd fuse mount point rather than overlay merged dir
			d.nydus.command.Process.Signal(os.Interrupt)
			d.nydus.command.Wait()
		}
	}

	dir := d.dir(id)

	mountpoint := path.Join(dir, mergedDirName)
	if count := d.ctr.Decrement(mountpoint); count > 0 {
		return nil
	}

	if err := unix.Unmount(mountpoint, unix.MNT_DETACH); err != nil {
		return errors.Wrapf(err, "failed to unmount from %s", mountpoint)
	}

	if err := unix.Rmdir(mountpoint); err != nil && !os.IsNotExist(err) {
		return errors.Wrapf(err, "failed in removing %s", mountpoint)
	}

	return nil
}

// Exists checks to see if the id is already mounted.
func (d *Driver) Exists(id string) bool {
	logrus.Info("Execute `Exists()`")
	_, err := os.Stat(d.dir(id))
	return err == nil
}

// isParent returns if the passed in parent is the direct parent of the passed in layer
func (d *Driver) isParent(id, parent string) bool {
	lowers, err := d.getLowerDirs(id)
	if err != nil || len(lowers) == 0 && parent != "" {
		return false
	}

	if parent == "" {
		if len(lowers) == 0 {
			return true
		} else {
			return false
		}

	}

	return parent == lowers[len(lowers)-1]
}

// ApplyDiff applies the new layer into a root
func (d *Driver) ApplyDiff(id, parent string, diff io.Reader) (size int64, err error) {
	if !d.isParent(id, parent) {
		return 0, errors.Errorf("Parent %s is not true parent of id %s", parent, id)
	}

	applyDir := path.Join(d.dir(id), diffDirName)
	if err := archive.Unpack(diff, applyDir, &archive.TarOptions{
		UIDMaps:        d.uidMaps,
		GIDMaps:        d.gidMaps,
		WhiteoutFormat: archive.OverlayWhiteoutFormat,
		InUserNS:       false,
	}); err != nil {
		return 0, err
	}

	parentLowers, err := d.getLowerDirs(parent)
	if err != nil {
		return 0, err
	}

	newLowers := strings.Join(append(parentLowers, parent), ":")
	lowerFilePath := path.Join(d.dir(id), lowerFile)

	if len(newLowers) > 0 {
		ioutil.WriteFile(lowerFilePath, []byte(newLowers), 0666)
	}

	return directory.Size(context.TODO(), applyDir)
}

// DiffSize calculates the changes between the specified id
// and its parent and returns the size in bytes of the changes
// relative to its base filesystem directory.
func (d *Driver) DiffSize(id, parent string) (size int64, err error) {
	return 0, errors.Errorf("Not implemented. id=%s, parent=%s", id, parent)
}

// Diff produces an archive of the changes between the specified
// layer and its parent layer which may be "".
func (d *Driver) Diff(id, parent string) (io.ReadCloser, error) {
	return nil, errors.Errorf("Not implemented. id=%s, parent=%s", id, parent)
}

// Changes produces a list of changes between the specified layer
// and its parent layer. If parent is "", then all changes will be ADD changes.
func (d *Driver) Changes(id, parent string) ([]archive.Change, error) {
	return nil, errors.Errorf("Not implemented. id=%s, parent=%s", id, parent)
}
