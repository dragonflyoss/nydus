/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package installer

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/containerd/log"
	utilversion "k8s.io/apimachinery/pkg/util/version"
)

// nydusBinaryVersion returns the version the image's nydus binary prints, 3.0.0
// in "nydus 3.0.0 (1a2b3c4d5, 2026-01-02)".
func (i *Installer) nydusBinaryVersion(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, nydusBinary, "--version").Output()
	if err != nil {
		return "", fmt.Errorf("run %s --version: %w", nydusBinary, err)
	}

	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return "", fmt.Errorf("unexpected %s --version output %q", nydusBinary, out)
	}

	// A semantic version holds no path separator, so it names the directory
	// of the version.
	version, err := utilversion.ParseSemantic(fields[1])
	if err != nil {
		return "", fmt.Errorf("unexpected %s --version output %q: %w", nydusBinary, out, err)
	}

	return version.String(), nil
}

// switchNydusBinaryVersion atomically links nydusd.binary to a version whose
// binary is in place and removes the versions no daemon start can resolve
// anymore.
//
//	nydusd.binary ──▶ /opt/nydus-snapshotter/versions/<version>/nydus
func (i *Installer) switchNydusBinaryVersion(ctx context.Context, version string) error {
	containerLink, err := i.containerPath(i.cfg.Nydusd.Binary)
	if err != nil {
		return err
	}

	// A path that is no link, such as a binary put there by hand or nothing
	// yet, has no previous version and is replaced.
	hostTarget := filepath.Join(nydusBinaryVersionsDir, version, filepath.Base(nydusBinary))
	previous, _ := os.Readlink(containerLink)
	if previous == hostTarget {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(containerLink), 0o755); err != nil {
		return fmt.Errorf("create dir of %s: %w", containerLink, err)
	}

	// Rename a new link over the old one, which a daemon start resolves
	// either before or after.
	tmp := containerLink + temporarySuffix
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", tmp, err)
	}

	if err := os.Symlink(hostTarget, tmp); err != nil {
		return fmt.Errorf("create symlink %s: %w", tmp, err)
	}

	if err := os.Rename(tmp, containerLink); err != nil {
		return fmt.Errorf("rename %s: %w", tmp, err)
	}

	log.G(ctx).WithFields(log.Fields{"version": version, "previous": previous}).Info("switched nydus version")
	containerVersionsDir, err := i.containerPath(nydusBinaryVersionsDir)
	if err != nil {
		return err
	}

	if err := i.pruneNydusBinaryVersions(ctx, containerVersionsDir, version, filepath.Base(filepath.Dir(previous))); err != nil {
		log.G(ctx).WithError(err).Warn("prune nydus versions")
	}

	return nil
}

// pruneNydusBinaryVersions removes the nydus version dirs of containerVersionsDir
// other than keep. Running daemons keep the inode of the binary they started
// with, and nothing restarts them; the version nydusd.binary linked to before
// is kept for a daemon start that resolved it just before the switch.
func (i *Installer) pruneNydusBinaryVersions(ctx context.Context, containerVersionsDir string, keep ...string) error {
	entries, err := os.ReadDir(containerVersionsDir)
	if err != nil {
		return fmt.Errorf("read %s: %w", containerVersionsDir, err)
	}

	for _, entry := range entries {
		// What is no version dir is not the installer's to remove.
		if _, err := utilversion.ParseSemantic(entry.Name()); err != nil || !entry.IsDir() || slices.Contains(keep, entry.Name()) {
			continue
		}

		path := filepath.Join(containerVersionsDir, entry.Name())
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove %s: %w", path, err)
		}

		log.G(ctx).WithField("version", entry.Name()).Info("removed nydus version")
	}

	return nil
}
