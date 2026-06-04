/*
 * Copyright (c) 2026. Lepton Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/log"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// filesystemRule mounts both the source and target images and compares their
// root filesystems for consistency. It is skipped unless both images are
// present.
type filesystemRule struct {
	cs      content.Store
	builder string
	workDir string
	source  *Image
	target  *Image
}

func (r *filesystemRule) Name() string { return "filesystem" }

// ensurePrivileged verifies the process has the privileges required by the
// filesystem rule. Both mounting a lepton image through FUSE and applying OCI
// layers while preserving their original uid/gid require root; without it the
// rule would either fail with an obscure FUSE timeout or silently compare
// ownership against the wrong (current-user) values.
func ensurePrivileged() error {
	if os.Geteuid() != 0 {
		return errors.New("filesystem rule requires root privileges: mounting the lepton image via FUSE and applying OCI layer ownership both need root; re-run with sudo, or provide only one of --source/--target to skip the filesystem comparison")
	}
	return nil
}

func (r *filesystemRule) Validate(ctx context.Context) error {
	if r.source == nil || r.target == nil {
		log.G(ctx).Info("skipping filesystem rule: source or target image is not provided")
		return nil
	}

	if err := ensurePrivileged(); err != nil {
		return err
	}

	sourceRoot, cleanupSource, err := r.mount(ctx, "source", r.source)
	if err != nil {
		return errors.Wrap(err, "mount source image")
	}
	defer cleanupSource()

	targetRoot, cleanupTarget, err := r.mount(ctx, "target", r.target)
	if err != nil {
		return errors.Wrap(err, "mount target image")
	}
	defer cleanupTarget()

	sourceNodes, err := walkRootfs(sourceRoot)
	if err != nil {
		return errors.Wrap(err, "walk source rootfs")
	}
	targetNodes, err := walkRootfs(targetRoot)
	if err != nil {
		return errors.Wrap(err, "walk target rootfs")
	}

	if err := verifyRootfs(sourceNodes, targetNodes); err != nil {
		return errors.Wrap(err, "filesystem mismatch")
	}
	log.G(ctx).Infof("filesystem check passed (%d entries)", len(sourceNodes))
	return nil
}

// mount materializes img's root filesystem and returns the path together with a
// cleanup function. OCI images are extracted to a directory; lepton images are
// mounted through `lepton fuse`.
func (r *filesystemRule) mount(ctx context.Context, label string, img *Image) (string, func(), error) {
	dir, err := os.MkdirTemp(r.workDir, "fs-"+label+"-")
	if err != nil {
		return "", nil, errors.Wrap(err, "create scratch dir")
	}
	cleanupDir := func() { _ = os.RemoveAll(dir) }

	if img.Kind == KindOCI {
		rootfs := filepath.Join(dir, "rootfs")
		if err := applyOCIImage(ctx, r.cs, img, rootfs); err != nil {
			cleanupDir()
			return "", nil, errors.Wrap(err, "apply oci image")
		}
		return rootfs, cleanupDir, nil
	}

	rootfs, unmount, err := r.fuseMount(ctx, dir, img)
	if err != nil {
		cleanupDir()
		return "", nil, err
	}
	return rootfs, func() {
		unmount()
		cleanupDir()
	}, nil
}

// fuseMount materializes the lepton bootstrap and blobs under dir, starts a
// `lepton fuse` daemon mounting them, waits for the mount to become ready, and
// returns the mountpoint with an unmount function.
func (r *filesystemRule) fuseMount(ctx context.Context, dir string, img *Image) (string, func(), error) {
	if img.Bootstrap == nil {
		return "", nil, errors.New("lepton image is missing its bootstrap layer")
	}

	blobDir := filepath.Join(dir, "blobs")
	cacheDir := filepath.Join(dir, "cache")
	mountpoint := filepath.Join(dir, "mnt")
	for _, d := range []string{blobDir, cacheDir, mountpoint} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return "", nil, errors.Wrapf(err, "create dir %q", d)
		}
	}

	if err := materializeBlobs(ctx, r.cs, img.Blobs, blobDir); err != nil {
		return "", nil, errors.Wrap(err, "materialize blobs")
	}
	bootstrapPath := filepath.Join(dir, "image.boot")
	if err := extractBootstrap(ctx, r.cs, *img.Bootstrap, bootstrapPath); err != nil {
		return "", nil, errors.Wrap(err, "extract bootstrap")
	}

	args := []string{
		"fuse",
		"--bootstrap", bootstrapPath,
		"--blob-dir", blobDir,
		"--cache-dir", cacheDir,
		"--mountpoint", mountpoint,
		"--log-level", "warn",
		"--log-dir", filepath.Join(dir, "log"),
		"--console",
	}
	// lepton fuse runs in the foreground; start it detached and wait for the
	// mountpoint to become active.
	cmd := exec.Command(builderBinary(r.builder), args...)
	var fuseLog bytes.Buffer
	cmd.Stdout = &fuseLog
	cmd.Stderr = &fuseLog
	if err := cmd.Start(); err != nil {
		return "", nil, errors.Wrap(err, "start lepton fuse")
	}

	unmount := func() {
		_ = unmountFuse(mountpoint)
		if cmd.Process != nil {
			_ = cmd.Process.Signal(unix.SIGTERM)
			_, _ = cmd.Process.Wait()
		}
	}

	if err := waitForMount(ctx, mountpoint, 30*time.Second); err != nil {
		// Surface whatever the daemon printed (e.g. a permission error opening
		// /dev/fuse) instead of letting it look like a bare timeout.
		output := strings.TrimSpace(fuseLog.String())
		unmount()
		if output == "" {
			output = "<no output; the FUSE mount may require root or access to /dev/fuse>"
		}
		return "", nil, errors.Wrapf(err, "lepton fuse did not mount %q (lepton output: %s)", mountpoint, output)
	}
	return mountpoint, unmount, nil
}

// waitForMount polls until mountpoint is backed by a different device than its
// parent (i.e. a filesystem has been mounted) or the timeout elapses.
func waitForMount(ctx context.Context, mountpoint string, timeout time.Duration) error {
	parent := filepath.Dir(mountpoint)
	deadline := time.Now().Add(timeout)
	for {
		mounted, err := isMounted(mountpoint, parent)
		if err != nil {
			return err
		}
		if mounted {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.Errorf("mountpoint %q did not become ready within %s", mountpoint, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func isMounted(mountpoint, parent string) (bool, error) {
	var mp, pp unix.Stat_t
	if err := unix.Stat(mountpoint, &mp); err != nil {
		return false, errors.Wrapf(err, "stat %q", mountpoint)
	}
	if err := unix.Stat(parent, &pp); err != nil {
		return false, errors.Wrapf(err, "stat %q", parent)
	}
	return mp.Dev != pp.Dev, nil
}

// unmountFuse unmounts a FUSE mountpoint, trying the userspace helpers before
// falling back to umount.
func unmountFuse(mountpoint string) error {
	candidates := [][]string{
		{"fusermount3", "-u", mountpoint},
		{"fusermount", "-u", mountpoint},
		{"umount", mountpoint},
	}
	var lastErr error
	for _, c := range candidates {
		bin, err := exec.LookPath(c[0])
		if err != nil {
			lastErr = err
			continue
		}
		if err := exec.Command(bin, c[1:]...).Run(); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr == nil {
		return nil
	}
	return errors.Wrapf(lastErr, "unmount %q", mountpoint)
}
