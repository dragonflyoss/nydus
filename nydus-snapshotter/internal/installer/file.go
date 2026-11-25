/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package installer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/containerd/log"
	"github.com/opencontainers/go-digest"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/registry"
)

const (
	// temporarySuffix names the file a write goes to before it is renamed
	// into place.
	temporarySuffix = ".tmp"
)

// file is a file the installer puts on the host.
type file struct {
	// hostPath is where the file goes on the host.
	hostPath string

	// perm is the mode of the file.
	perm os.FileMode

	// src is the file of the image holding the content, read when data is
	// nil.
	src string

	// data is the content when it was validated or generated. A ConfigMap can
	// change between two reads, so a validated file is installed from the
	// bytes that were validated.
	data []byte
}

// open returns the content.
func (f *file) open() (io.ReadCloser, error) {
	if f.data != nil {
		return io.NopCloser(bytes.NewReader(f.data)), nil
	}

	src, err := os.Open(f.src)
	if err != nil {
		return nil, fmt.Errorf("read source: %w", err)
	}

	return src, nil
}

// installed reports whether the file at containerPath, where the DaemonSet
// mounts its host path, is a regular file with the content and the mode.
// Contents are compared by digest, so a binary is never held in memory.
func (f *file) installed(containerPath string) (bool, error) {
	src, err := f.open()
	if err != nil {
		return false, err
	}
	defer src.Close()

	srcDigest, err := digest.FromReader(src)
	if err != nil {
		return false, fmt.Errorf("read source: %w", err)
	}

	dst, err := os.Open(containerPath)
	if err != nil {
		return false, nil
	}
	defer dst.Close()

	if info, err := dst.Stat(); err != nil || info.Mode() != f.perm {
		return false, nil
	}

	dstDigest, err := digest.FromReader(dst)
	return err == nil && dstDigest == srcDigest, nil
}

// write atomically writes the content to containerPath, where the DaemonSet
// mounts the file's host path, with the mode, creating its directory. The
// content is copied to a temporary file beside it, synced and renamed over
// it. The temporary name is fixed, so a file left by a write that died is
// replaced by the next write.
func (f *file) write(containerPath string) (err error) {
	if err := os.MkdirAll(filepath.Dir(containerPath), 0o755); err != nil {
		return fmt.Errorf("create dir of %s: %w", containerPath, err)
	}

	src, err := f.open()
	if err != nil {
		return err
	}
	defer src.Close()

	// Remove a leftover temporary file rather than write into it, so a
	// symlink planted under that name is never followed.
	tmp := containerPath + temporarySuffix
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", tmp, err)
	}

	dst, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, f.perm)
	if err != nil {
		return fmt.Errorf("write %s: %w", containerPath, err)
	}

	// A temporary file left behind would keep a full disk full.
	defer func() {
		if err != nil {
			_ = dst.Close()
			_ = os.Remove(tmp)
			err = fmt.Errorf("write %s: %w", containerPath, err)
		}
	}()

	if _, err := io.Copy(dst, src); err != nil {
		return err
	}

	// Set the exact mode: OpenFile applied the umask.
	if err := dst.Chmod(f.perm); err != nil {
		return err
	}

	if err := dst.Sync(); err != nil {
		return err
	}

	if err := dst.Close(); err != nil {
		return err
	}

	return os.Rename(tmp, containerPath)
}

// syncConfig copies the config files onto the host without restarting the
// snapshotter. A changed config.yaml writes the restart-required file. The
// next install, run by the rollout the ConfigMap checksum triggers, finds
// the host config already in place and restarts the service because of that
// file, so keys the snapshotter cannot reload still apply.
func (i *Installer) syncConfig(ctx context.Context) error {
	files, err := i.configFiles()
	if err != nil {
		return err
	}

	// Without the switch the host keeps the certs.d it has.
	if i.cfg.Installer.Registries.Enable {
		certsFiles, err := i.certsFiles()
		if err != nil {
			return err
		}

		files = append(files, certsFiles...)
	}

	return i.installFiles(ctx, files)
}

// binaryFiles returns the binaries to install. nydus goes to the directory of
// its version, so running daemons keep the binary they started with.
func (i *Installer) binaryFiles(version string) []file {
	return []file{
		{hostPath: filepath.Join(nydusBinaryVersionsDir, version, filepath.Base(nydusBinary)), perm: 0o755, src: nydusBinary},
		{hostPath: nydusSnapshotterBinary, perm: 0o755, src: nydusSnapshotterBinary},
	}
}

// unitFiles returns the systemd unit files to install.
func (i *Installer) unitFiles() []file {
	return []file{
		{hostPath: filepath.Join(unitDir, nydusSnapshotterServiceUnit), perm: 0o644, src: filepath.Join(unitDir, nydusSnapshotterServiceUnit)},
	}
}

// configFiles returns the config file to install, validated before anything
// touches the host so a broken ConfigMap leaves the running snapshotter
// alone.
func (i *Installer) configFiles() ([]file, error) {
	// Read the config file as it is now: a ConfigMap update may have changed
	// it since the installer started.
	data, err := os.ReadFile(i.configPath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	if _, err := config.Parse(data); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return []file{{hostPath: config.DefaultPath, perm: 0o644, data: data}}, nil
}

// certsFiles returns the certs.d files to install, validated as configFiles
// validates config.yaml, none without a certs.d. They go to
// registry.config_path, where the snapshotter reads them. A hosts.toml is
// checked as a daemon start reads it. Files dropped from certs.d stay on the
// host, so hosts.toml baked into the node image survive.
func (i *Installer) certsFiles() ([]file, error) {
	if _, err := os.Stat(config.DefaultRegistryConfigPath); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}

	// A file vanishing during the walk fails it, so a certs.d read in part is
	// never installed.
	var files []file
	fsys := os.DirFS(config.DefaultRegistryConfigPath)
	if err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}

		if d.Name() == registry.HostsFile {
			if err := (&registry.Endpoint{}).Apply(data, filepath.Dir(path)); err != nil {
				return fmt.Errorf("validate %s: %w", path, err)
			}
		}

		files = append(files, file{hostPath: filepath.Join(i.cfg.Registry.ConfigPath, path), perm: 0o644, data: data})
		return nil
	}); err != nil {
		return nil, fmt.Errorf("walk certs.d: %w", err)
	}

	return files, nil
}

// installFiles puts files on the host, skipping those already there. The
// restart-required file is written before any of them, so a run that dies
// before restarting the service is finished by the next one.
func (i *Installer) installFiles(ctx context.Context, files []file) error {
	var changed []file
	for _, f := range files {
		containerPath, err := i.containerPath(f.hostPath)
		if err != nil {
			return err
		}

		installed, err := f.installed(containerPath)
		if err != nil {
			return err
		}

		if !installed {
			changed = append(changed, f)
		}
	}

	if i.shouldRestart(changed) {
		if err := i.writeRestartRequiredFile(); err != nil {
			return err
		}
	}

	for _, f := range changed {
		containerPath, err := i.containerPath(f.hostPath)
		if err != nil {
			return err
		}

		if err := f.write(containerPath); err != nil {
			return err
		}

		log.G(ctx).WithField("path", f.hostPath).Info("installed file")
	}

	return nil
}

// shouldRestart reports whether a changed file is one the service reads only
// at start: its unit file, its binary or config.yaml. certs.d and nydus
// binaries are read per daemon start.
func (i *Installer) shouldRestart(changed []file) bool {
	for _, f := range changed {
		switch f.hostPath {
		case filepath.Join(unitDir, nydusSnapshotterServiceUnit), nydusSnapshotterBinary, config.DefaultPath:
			return true
		}
	}

	return false
}

// restartRequired reports whether the restart-required file exists.
func (i *Installer) restartRequired() (bool, error) {
	containerPath, err := i.containerPath(restartRequiredFile)
	if err != nil {
		return false, err
	}

	_, err = os.Lstat(containerPath)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("stat %s: %w", containerPath, err)
	}

	return true, nil
}

// writeRestartRequiredFile writes the empty restart-required file.
func (i *Installer) writeRestartRequiredFile() error {
	containerPath, err := i.containerPath(restartRequiredFile)
	if err != nil {
		return err
	}

	// The file lives in the snapshotter's runtime directory, which holds
	// daemon sockets and credentials: create it private to root, as the
	// snapshotter does, when the installer is the first to need it.
	if err := os.MkdirAll(filepath.Dir(containerPath), 0o700); err != nil {
		return fmt.Errorf("create dir of %s: %w", containerPath, err)
	}

	f := &file{hostPath: restartRequiredFile, perm: 0o644, data: []byte{}}
	return f.write(containerPath)
}

// removeRestartRequiredFile removes the restart-required file, which may be
// absent.
func (i *Installer) removeRestartRequiredFile() error {
	containerPath, err := i.containerPath(restartRequiredFile)
	if err != nil {
		return err
	}

	if err := os.Remove(containerPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", containerPath, err)
	}

	return nil
}
