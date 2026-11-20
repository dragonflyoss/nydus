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
	"slices"
	"strings"

	"github.com/containerd/log"
	"github.com/opencontainers/go-digest"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/registry"
)

const (
	// payloadNydusBinary is the nydus binary in the payload.
	payloadNydusBinary = "bin/nydus"

	// payloadSnapshotterBinary is the snapshotter binary in the payload.
	payloadSnapshotterBinary = "bin/nydus-snapshotter"

	// payloadUnitDir is the directory of the unit files in the payload.
	payloadUnitDir = "systemd"

	// temporarySuffix names the file a write goes to before it is renamed
	// into place.
	temporarySuffix = ".tmp"
)

// file is a file the installer puts on the host.
type file struct {
	// path is the host path.
	path string

	// target is the host path as seen from the Pod, set when the file is
	// installed.
	target string

	// perm is the mode of the file.
	perm os.FileMode

	// src is the file holding the content, read when data is nil.
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
		return nil, fmt.Errorf("read payload: %w", err)
	}

	return src, nil
}

// installed reports whether the target is a regular file with the content
// and the mode. Contents are compared by digest, so a binary is never held in
// memory.
func (f *file) installed() (bool, error) {
	src, err := f.open()
	if err != nil {
		return false, err
	}
	defer src.Close()

	want, err := digest.FromReader(src)
	if err != nil {
		return false, fmt.Errorf("read payload: %w", err)
	}

	dst, err := os.Open(f.target)
	if err != nil {
		return false, nil
	}
	defer dst.Close()

	if info, err := dst.Stat(); err != nil || info.Mode() != f.perm {
		return false, nil
	}

	got, err := digest.FromReader(dst)
	return err == nil && got == want, nil
}

// write atomically writes the content to the target with the mode, creating
// its directory. The content is copied to target.tmp, synced and renamed over
// the target. The temporary name is fixed, so a file left by a write that
// died is replaced by the next write, refer to
// https://github.com/projectcalico/calico/blob/master/cni-plugin/pkg/install/install.go
// and
// https://github.com/cilium/cilium/blob/main/plugins/cilium-cni/install-plugin.sh.
func (f *file) write() (err error) {
	if err := os.MkdirAll(filepath.Dir(f.target), 0o755); err != nil {
		return fmt.Errorf("create dir of %s: %w", f.target, err)
	}

	src, err := f.open()
	if err != nil {
		return err
	}
	defer src.Close()

	// Remove a leftover temporary file rather than write into it, so a
	// symlink planted under that name is never followed.
	tmp := f.target + temporarySuffix
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", tmp, err)
	}

	dst, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, f.perm)
	if err != nil {
		return fmt.Errorf("write %s: %w", f.target, err)
	}

	// A temporary file left behind would keep a full disk full.
	defer func() {
		if err != nil {
			_ = dst.Close()
			_ = os.Remove(tmp)
			err = fmt.Errorf("write %s: %w", f.target, err)
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

	return os.Rename(tmp, f.target)
}

// syncConfig copies the config files onto the host without restarting the
// snapshotter. A changed config.yaml marks the service pending a restart.
// The next install, run by the rollout the ConfigMap checksum triggers, finds
// the host config already in place and restarts the service from that mark,
// so keys the snapshotter cannot reload still apply.
func (i *Installer) syncConfig(ctx context.Context) error {
	files, err := i.configFiles()
	if err != nil {
		return err
	}

	return i.installFiles(ctx, files)
}

// configFiles returns the config files of the payload, validated before
// anything touches the host so a broken ConfigMap leaves the running
// snapshotter alone: config.yaml and certs.d when present.
func (i *Installer) configFiles() ([]file, error) {
	cfg, data, err := i.payloadConfig()
	if err != nil {
		return nil, err
	}

	files := []file{{path: config.DefaultPath, perm: 0o644, data: data}}

	certs, err := i.certsFiles()
	if err != nil {
		return nil, err
	}

	// certs.d goes to its default directory, which the config must read.
	if len(certs) > 0 && !slices.Contains(filepath.SplitList(cfg.Registry.ConfigPath), config.DefaultRegistryConfigPath) {
		return nil, fmt.Errorf("payload config: registry.config_path must hold %s, where certs.d is installed, got %q", config.DefaultRegistryConfigPath, cfg.Registry.ConfigPath)
	}

	return append(files, certs...), nil
}

// certsFiles returns the certs.d files of the payload, none without a
// certs.d. A hosts.toml is checked as a daemon start reads it. Files dropped
// from certs.d stay on the host, so hosts.toml baked into the node image
// survive.
func (i *Installer) certsFiles() ([]file, error) {
	certsDir := i.cfg.certsDir()
	if _, err := os.Stat(certsDir); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}

	// A file vanishing during the walk fails it, so a certs.d read in part is
	// never installed.
	var files []file
	fsys := os.DirFS(certsDir)
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

		files = append(files, file{path: filepath.Join(config.DefaultRegistryConfigPath, path), perm: 0o644, data: data})
		return nil
	}); err != nil {
		return nil, fmt.Errorf("walk payload certs.d: %w", err)
	}

	return files, nil
}

// payloadConfig returns the validated config.yaml of the payload and its
// content.
func (i *Installer) payloadConfig() (*config.Config, []byte, error) {
	data, err := os.ReadFile(i.cfg.Path)
	if err != nil {
		return nil, nil, fmt.Errorf("read payload config: %w", err)
	}

	cfg, err := config.Parse(data)
	if err != nil {
		return nil, nil, fmt.Errorf("parse payload config: %w", err)
	}

	// The installer writes to fixed host paths and installs the socket unit
	// that listens on one, so a config naming others would reach the node
	// and never work.
	paths := []struct{ name, path, want string }{
		{name: "grpc.addr", path: cfg.GRPC.Addr, want: config.DefaultGRPCAddr},
		{name: "nydusd.binary", path: cfg.Nydusd.Binary, want: config.DefaultNydusdBinary},
	}
	if cfg.Auth.KubeSecret.Enable {
		paths = append(paths, struct{ name, path, want string }{name: "auth.kube_secret.kubeconfig", path: cfg.Auth.KubeSecret.Kubeconfig, want: config.DefaultAuthKubeconfig})
	}

	for _, p := range paths {
		if p.path != p.want {
			return nil, nil, fmt.Errorf("payload config: %s must be %s, where the installer writes, got %q", p.name, p.want, p.path)
		}
	}

	return cfg, data, nil
}

// installFiles puts files on the host, skipping those already there. The
// units a changed file needs restarted are marked pending before anything is
// written, so a run that dies before restarting them is finished by the next
// one.
func (i *Installer) installFiles(ctx context.Context, files []file) error {
	var changed []file
	for _, f := range files {
		target, err := i.cfg.host(f.path)
		if err != nil {
			return err
		}
		f.target = target

		installed, err := f.installed()
		if err != nil {
			return err
		}

		if !installed {
			changed = append(changed, f)
		}
	}

	if err := i.markRestarts(i.unitsToRestart(changed)); err != nil {
		return err
	}

	for _, f := range changed {
		if err := f.write(); err != nil {
			return err
		}

		log.G(ctx).WithField("path", f.path).Info("installed file")
	}

	return nil
}

// unitsToRestart returns the units changed files need restarted: the socket
// for its unit file, the service for what it reads only at start. certs.d
// and nydus binaries are read per daemon start and need none.
func (i *Installer) unitsToRestart(changed []file) []string {
	var units []string
	for _, f := range changed {
		switch f.path {
		case filepath.Join(unitDir, socketUnit):
			units = append(units, socketUnit)
		case filepath.Join(unitDir, serviceUnit), snapshotterBinary, config.DefaultPath:
			units = append(units, serviceUnit)
		}
	}

	return units
}

// pendingRestarts returns the units marked pending a restart.
func (i *Installer) pendingRestarts() ([]string, error) {
	path, err := i.cfg.host(restartPending)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	return strings.Fields(string(data)), nil
}

// markRestarts adds units to those pending a restart.
func (i *Installer) markRestarts(units []string) error {
	if len(units) == 0 {
		return nil
	}

	pending, err := i.pendingRestarts()
	if err != nil {
		return err
	}

	units = append(pending, units...)
	slices.Sort(units)
	units = slices.Compact(units)
	path, err := i.cfg.host(restartPending)
	if err != nil {
		return err
	}

	// The marker lives in the snapshotter's runtime directory, which holds
	// daemon sockets and credentials: create it private to root, as the
	// socket unit does, when the installer is the first to need it.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create dir of %s: %w", path, err)
	}

	marker := &file{path: restartPending, target: path, perm: 0o644, data: []byte(strings.Join(units, "\n") + "\n")}
	return marker.write()
}

// clearRestarts forgets the units pending a restart.
func (i *Installer) clearRestarts() error {
	path, err := i.cfg.host(restartPending)
	if err != nil {
		return err
	}

	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", path, err)
	}

	return nil
}
