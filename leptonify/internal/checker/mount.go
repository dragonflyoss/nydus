/*
 * Copyright (c) 2026. Lepton Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/log"
	"github.com/containerd/platforms"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/dragonflyoss/lepton/leptonify/internal/remote"
)

// MountOpt configures a Mounter.
type MountOpt struct {
	// Target is the image reference to mount (OCI or lepton). Required.
	Target string
	// Mountpoint is the directory the image is mounted at. Required, and must
	// already exist.
	Mountpoint string
	// Builder is the lepton binary path (PATH-resolvable). Defaults to "lepton".
	Builder string
	// WorkDir is the scratch directory backing the content store and the
	// extracted bootstrap/cache. It must already exist.
	WorkDir string
	// TargetInsecure skips TLS certificate verification for the target registry.
	TargetInsecure bool
	// TargetPlainHTTP uses plain HTTP to talk to the target registry.
	TargetPlainHTTP bool
	// Prefetch enables background blob prefetch after mounting. Off by
	// default so a traced mount records the pure on-demand access pattern.
	Prefetch bool
	// LogLevel is the log level forwarded to the `lepton` subprocess. Defaults
	// to "info" when empty.
	LogLevel string
	// PlatformMC selects which platform to mount. Defaults to the host platform.
	PlatformMC platforms.MatchComparer
}

// Mounter materializes a single image at a local mountpoint. Lepton images are
// mounted live through `lepton fuse` (blobs fetched on demand from the source
// registry); OCI images are extracted to the mountpoint.
type Mounter struct {
	opt MountOpt
}

// NewMounter creates a Mounter.
func NewMounter(opt MountOpt) (*Mounter, error) {
	if opt.Target == "" {
		return nil, errors.New("target must be provided")
	}
	if opt.Mountpoint == "" {
		return nil, errors.New("mountpoint must be provided")
	}
	if opt.PlatformMC == nil {
		opt.PlatformMC = platforms.Default()
	}
	if opt.LogLevel == "" {
		opt.LogLevel = "info"
	}
	return &Mounter{opt: opt}, nil
}

// Mount pulls the target image and mounts it at the configured mountpoint. For a
// lepton image it runs `lepton fuse` in the foreground and blocks until the
// mount is torn down (by ctx cancellation or SIGINT/SIGTERM), unmounting on
// exit. For an OCI image it extracts the root filesystem to the mountpoint and
// returns immediately.
func (m *Mounter) Mount(ctx context.Context) error {
	contentDir := filepath.Join(m.opt.WorkDir, "content")
	scratchDir := filepath.Join(m.opt.WorkDir, "scratch")
	for _, d := range []string{contentDir, scratchDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return errors.Wrapf(err, "create dir %q", d)
		}
	}

	provider, err := remote.NewProvider(remote.Options{
		WorkDir:         contentDir,
		TargetInsecure:  m.opt.TargetInsecure,
		TargetPlainHTTP: m.opt.TargetPlainHTTP,
		PlatformMC:      m.opt.PlatformMC,
	})
	if err != nil {
		return errors.Wrap(err, "create provider")
	}

	img, err := loadImage(ctx, provider, m.opt.Target, m.opt.PlatformMC, remote.PullAll, remote.Target)
	if err != nil {
		return errors.Wrapf(err, "load target %q", m.opt.Target)
	}

	if img.Kind == KindOCI {
		return m.mountOCI(ctx, provider.ContentStore(), img)
	}
	return m.mountLepton(ctx, provider, provider.ContentStore(), img, scratchDir)
}

// mountOCI extracts img's merged root filesystem into the mountpoint. Layer
// ownership is preserved, which requires root.
func (m *Mounter) mountOCI(ctx context.Context, cs content.Store, img *Image) error {
	log.G(ctx).Infof("extracting OCI image %s to %s", img.Ref, m.opt.Mountpoint)
	if err := applyOCIImage(ctx, cs, img, m.opt.Mountpoint); err != nil {
		return errors.Wrap(err, "apply oci image")
	}
	log.G(ctx).Infof("extracted OCI image %s at %s (static rootfs, not a live mount)", img.Ref, m.opt.Mountpoint)
	return nil
}

// mountLepton materializes the lepton bootstrap, generates a registry-backed
// storage config, and runs `lepton fuse` in the foreground mounting the image at
// the mountpoint. Blob data is fetched on demand from the source registry. It
// blocks until the daemon exits, forwarding termination signals so the mount is
// unmounted cleanly.
func (m *Mounter) mountLepton(ctx context.Context, provider *remote.Provider, cs content.Store, img *Image, scratchDir string) error {
	if img.Bootstrap == nil {
		return errors.New("lepton image is missing its bootstrap layer")
	}

	cacheDir := filepath.Join(scratchDir, "cache")
	bootDir := filepath.Join(scratchDir, "bootstrap")
	logDir := filepath.Join(scratchDir, "log")
	for _, d := range []string{cacheDir, bootDir, logDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return errors.Wrapf(err, "create dir %q", d)
		}
	}

	// Extract the bootstrap layer (image.boot plus the per-layer blob meta
	// artifacts) and hardlink the blob metas into the cache dir so the registry
	// backend loads metadata from disk instead of fetching each blob footer.
	bootstrapPath, blobMetaPaths, err := extractBootstrapLayer(ctx, cs, *img.Bootstrap, bootDir)
	if err != nil {
		return errors.Wrap(err, "extract bootstrap")
	}
	if err := linkBlobMetaFiles(ctx, blobMetaPaths, cacheDir); err != nil {
		return errors.Wrap(err, "link blob meta to cache")
	}

	configPath := filepath.Join(scratchDir, "config.yaml")
	configYAML, err := writeRegistryConfig(provider, remote.Target, img, cacheDir, configPath, m.opt.Prefetch)
	if err != nil {
		return errors.Wrap(err, "generate storage config")
	}
	log.G(ctx).Debugf("generated lepton storage config %s:\n%s", configPath, configYAML)

	// Expose Prometheus metrics over a Unix socket under the work dir so the
	// running mount can be scraped (e.g. curl --unix-socket).
	apiSocket := filepath.Join(m.opt.WorkDir, "apiserver.sock")

	args := []string{
		"fuse",
		"--bootstrap", bootstrapPath,
		"--config", configPath,
		"--mountpoint", m.opt.Mountpoint,
		"--apiserver", "unix://" + apiSocket,
		"--log-level", leptonLogLevel(m.opt.LogLevel),
		"--log-dir", logDir,
		"--console",
	}
	cmd := exec.Command(builderBinary(m.opt.Builder), args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return errors.Wrap(err, "start lepton fuse")
	}
	log.G(ctx).Infof("mounting lepton image %s at %s (metrics at unix://%s, press Ctrl+C to unmount)", img.Ref, m.opt.Mountpoint, apiSocket)

	// `lepton fuse` runs in the foreground and performs its own unmount on
	// SIGTERM/SIGINT. Forward termination signals (and ctx cancellation) to it
	// and wait for it to exit so this command's cleanup can run afterwards.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, unix.SIGINT, unix.SIGTERM)
	defer signal.Stop(sigCh)

	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()

	select {
	case <-ctx.Done():
		_ = cmd.Process.Signal(unix.SIGTERM)
		<-waitErr
	case <-sigCh:
		_ = cmd.Process.Signal(unix.SIGTERM)
		<-waitErr
	case err := <-waitErr:
		if err != nil {
			return errors.Wrap(err, "lepton fuse exited")
		}
	}
	log.G(ctx).Infof("unmounted lepton image at %s", m.opt.Mountpoint)
	return nil
}
