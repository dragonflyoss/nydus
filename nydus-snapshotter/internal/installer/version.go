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
	"regexp"
	"slices"
	"strings"

	"github.com/containerd/log"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
)

// versionRegexp matches a nydus version usable as a directory name.
var versionRegexp = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]*$`)

// nydusVersion returns the version the payload's nydus binary prints, 3.0.0
// in "nydus 3.0.0 (1a2b3c4d5, 2026-01-02)".
func (i *Installer) nydusVersion(ctx context.Context) (string, error) {
	binary := i.payload(payloadNydusBinary)
	out, err := exec.CommandContext(ctx, binary, "--version").Output()
	if err != nil {
		return "", fmt.Errorf("run %s --version: %w", binary, err)
	}

	fields := strings.Fields(string(out))
	if len(fields) < 2 || !versionRegexp.MatchString(fields[1]) {
		return "", fmt.Errorf("unexpected %s --version output %q", binary, out)
	}

	return fields[1], nil
}

// nydusBinary returns the host path of the nydus binary of a version.
// config.DefaultNydusdBinary is <bin dir>/current/nydus; each version gets its
// own dir so running daemons keep the binary they started with.
func (i *Installer) nydusBinary(version string) string {
	binDir := filepath.Dir(filepath.Dir(config.DefaultNydusdBinary))
	return filepath.Join(binDir, version, filepath.Base(config.DefaultNydusdBinary))
}

// switchVersion atomically points the current link at a version whose binary
// is in place and removes the versions no daemon start can resolve anymore.
func (i *Installer) switchVersion(ctx context.Context, version string) error {
	link, err := i.host(filepath.Dir(config.DefaultNydusdBinary))
	if err != nil {
		return err
	}

	previous, err := os.Readlink(link)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read %s: %w", link, err)
	}

	if previous == version {
		return nil
	}

	// Rename a new link over the old one, which a daemon start resolves
	// either before or after.
	tmp := link + temporarySuffix
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", tmp, err)
	}

	if err := os.Symlink(version, tmp); err != nil {
		return fmt.Errorf("create symlink %s: %w", tmp, err)
	}

	if err := os.Rename(tmp, link); err != nil {
		return fmt.Errorf("rename %s: %w", tmp, err)
	}

	log.G(ctx).WithFields(log.Fields{"version": version, "previous": previous}).Info("switched nydus version")
	if err := i.pruneVersions(ctx, filepath.Dir(link), version, previous); err != nil {
		log.G(ctx).WithError(err).Warn("prune nydus versions")
	}

	return nil
}

// pruneVersions removes the nydus version dirs of binDir other than keep.
// Running daemons keep the inode of the binary they started with, and
// nothing restarts them; the version current pointed at before is kept for
// a daemon start that resolved it just before the switch.
func (i *Installer) pruneVersions(ctx context.Context, binDir string, keep ...string) error {
	entries, err := os.ReadDir(binDir)
	if err != nil {
		return fmt.Errorf("read %s: %w", binDir, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() || !versionRegexp.MatchString(entry.Name()) || slices.Contains(keep, entry.Name()) {
			continue
		}

		path := filepath.Join(binDir, entry.Name())
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove %s: %w", path, err)
		}

		log.G(ctx).WithField("version", entry.Name()).Info("removed nydus version")
	}

	return nil
}
