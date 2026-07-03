/*
 * Copyright (c) 2026. Lepton Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/log"
	"github.com/distribution/reference"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"

	"github.com/dragonflyoss/lepton/leptonify/internal/remote"
)

// filesystemRule mounts both the source and target images and compares their
// root filesystems for consistency. It is skipped unless both images are
// present.
type filesystemRule struct {
	cs       content.Store
	provider *remote.Provider
	builder  string
	logLevel string
	workDir  string
	source   *Image
	target   *Image
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

	sourceRoot, cleanupSource, err := r.mount(ctx, "source", remote.Source, r.source)
	if err != nil {
		return errors.Wrap(err, "mount source image")
	}
	defer cleanupSource()

	targetRoot, cleanupTarget, err := r.mount(ctx, "target", remote.Target, r.target)
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
// mounted through `lepton fuse`. reg selects which registry side's TLS/HTTP
// settings back the lepton FUSE mount.
func (r *filesystemRule) mount(ctx context.Context, label string, reg remote.Registry, img *Image) (string, func(), error) {
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

	rootfs, unmount, err := r.fuseMount(ctx, dir, reg, img)
	if err != nil {
		cleanupDir()
		return "", nil, err
	}
	return rootfs, func() {
		unmount()
		cleanupDir()
	}, nil
}

// fuseMount materializes the lepton bootstrap under dir, generates a storage
// config pointing the registry backend at the image's source registry, starts a
// `lepton fuse` daemon mounting them, waits for the mount to become ready, and
// returns the mountpoint with an unmount function. Blob data is fetched on
// demand from the registry rather than materialized locally.
func (r *filesystemRule) fuseMount(ctx context.Context, dir string, reg remote.Registry, img *Image) (string, func(), error) {
	if img.Bootstrap == nil {
		return "", nil, errors.New("lepton image is missing its bootstrap layer")
	}

	cacheDir := filepath.Join(dir, "cache")
	mountpoint := filepath.Join(dir, "mnt")
	for _, d := range []string{cacheDir, mountpoint} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return "", nil, errors.Wrapf(err, "create dir %q", d)
		}
	}

	// Extract the bootstrap layer (image.boot plus the per-layer blob meta
	// artifacts) and hardlink the blob metas into the cache dir so the registry
	// backend loads metadata from disk instead of fetching each blob footer.
	bootDir := filepath.Join(dir, "bootstrap")
	bootstrapPath, blobMetaPaths, err := extractBootstrapLayer(ctx, r.cs, *img.Bootstrap, bootDir)
	if err != nil {
		return "", nil, errors.Wrap(err, "extract bootstrap")
	}
	if err := linkBlobMetaFiles(ctx, blobMetaPaths, cacheDir); err != nil {
		return "", nil, errors.Wrap(err, "link blob meta to cache")
	}

	configPath := filepath.Join(dir, "config.yaml")
	_, err = writeRegistryConfig(r.provider, reg, img, cacheDir, configPath, false)
	if err != nil {
		return "", nil, errors.Wrap(err, "generate storage config")
	}

	args := []string{
		"fuse",
		"--bootstrap", bootstrapPath,
		"--config", configPath,
		"--mountpoint", mountpoint,
		"--log-level", "warn",
		"--log-dir", filepath.Join(dir, "log"),
	}
	// lepton fuse runs in the foreground; start it detached and wait for the
	// mountpoint to become active. Keep its output buffered for startup errors;
	// the check command itself owns the user-facing progress logs.
	cmd := exec.Command(builderBinary(r.builder), args...)
	var fuseLog bytes.Buffer
	cmd.Stdout = &fuseLog
	cmd.Stderr = &fuseLog
	if err := cmd.Start(); err != nil {
		return "", nil, errors.Wrap(err, "start lepton fuse")
	}

	unmount := func() {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(unix.SIGTERM)
			done := make(chan struct{})
			go func() {
				_, _ = cmd.Process.Wait()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				_ = unmountFuse(mountpoint)
				_ = cmd.Process.Kill()
				<-done
			}
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

// registryBackendConfig is the `backend.config` section for the registry
// backend understood by `lepton fuse --config`.
type registryBackendConfig struct {
	Host       string `yaml:"host"`
	Repo       string `yaml:"repo"`
	Insecure   bool   `yaml:"insecure"`
	SkipVerify bool   `yaml:"skip_verify"`
	Auth       string `yaml:"auth,omitempty"`
}

type backendSection struct {
	Type   string                `yaml:"type"`
	Config registryBackendConfig `yaml:"config"`
}

type localDirSection struct {
	Dir string `yaml:"dir"`
}

type cacheSection struct {
	Type   string          `yaml:"type"`
	Config localDirSection `yaml:"config"`
}

type prefetchSection struct {
	Enable  bool `yaml:"enable"`
	Threads int  `yaml:"threads"`
}

type storageConfig struct {
	Backend  backendSection  `yaml:"backend"`
	Cache    cacheSection    `yaml:"cache"`
	Prefetch prefetchSection `yaml:"prefetch"`
}

// prefetchThreads returns the worker thread count for the prefetch section:
// the lepton default when prefetch is enabled, zero otherwise.
func prefetchThreads(enable bool) int {
	if enable {
		return 10
	}
	return 0
}

// writeRegistryConfig derives a registry-backed storage config for img, writes
// it to configPath, and returns the rendered YAML. The registry host and
// repository are parsed from the image reference; credentials, TLS and HTTP
// settings come from the provider's reg side (source or target) used to pull
// the image. Blob prefetch runs only when prefetchEnable is set (a live mount
// wants production-like warmup, while check and optimize want fully on-demand
// reads).
func writeRegistryConfig(provider *remote.Provider, reg remote.Registry, img *Image, cacheDir, configPath string, prefetchEnable bool) (string, error) {
	named, err := reference.ParseNormalizedNamed(img.Ref)
	if err != nil {
		return "", errors.Wrapf(err, "parse image reference %q", img.Ref)
	}
	host := reference.Domain(named)
	repo := reference.Path(named)
	// The normalized Docker Hub domain is not the actual registry endpoint.
	if host == "docker.io" {
		host = "registry-1.docker.io"
	}

	var auth string
	if username, password, err := provider.Credentials(host); err == nil && username != "" {
		auth = basicAuthConfig(username, password)
	}

	cfg := storageConfig{
		Backend: backendSection{
			Type: "registry",
			Config: registryBackendConfig{
				Host:       host,
				Repo:       repo,
				Insecure:   provider.PlainHTTP(reg),
				SkipVerify: provider.Insecure(reg),
				Auth:       auth,
			},
		},
		Cache: cacheSection{
			Type:   "local",
			Config: localDirSection{Dir: cacheDir},
		},
		Prefetch: prefetchSection{Enable: prefetchEnable, Threads: prefetchThreads(prefetchEnable)},
	}

	out, err := yaml.Marshal(cfg)
	if err != nil {
		return "", errors.Wrap(err, "marshal storage config")
	}
	if err := os.WriteFile(configPath, out, 0o600); err != nil {
		return "", errors.Wrapf(err, "write storage config %q", configPath)
	}
	return string(out), nil
}

func basicAuthConfig(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
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
