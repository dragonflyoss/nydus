/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package installer installs the snapshotter onto the host from the
// DaemonSet Pod and keeps its config and Kubernetes credentials in sync,
// refer to
// https://github.com/containerd/nydus-snapshotter/blob/main/misc/snapshotter/snapshotter.sh.
package installer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/containerd/continuity"
	continuityfs "github.com/containerd/continuity/fs"
	"github.com/containerd/log"
	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd"
)

const (
	// DefaultHostRoot is where the DaemonSet mounts the host root.
	DefaultHostRoot = "/host"

	// DefaultPayloadDir holds what is installed: bin/ and systemd/ from the
	// image, config/ from the ConfigMap.
	DefaultPayloadDir = "/opt/nydus-snapshotter/payload"

	// DefaultTokenDir is the Pod's projected service account token directory.
	DefaultTokenDir = "/var/run/secrets/kubernetes.io/serviceaccount"

	// DefaultSyncInterval is how often the token is copied to the host, well
	// within the hour a projected token lives.
	DefaultSyncInterval = time.Minute

	// DefaultJobTimeout bounds a unit restart: systemd's default 90s stop
	// timeout plus a start.
	DefaultJobTimeout = 2 * time.Minute

	// serviceUnit is the snapshotter service.
	serviceUnit = "nydus-snapshotter.service"

	// socketUnit is the snapshotter's gRPC socket.
	socketUnit = "nydus-snapshotter.socket"

	// snapshotterBinary is the host path of the snapshotter binary.
	snapshotterBinary = "/usr/local/bin/nydus-snapshotter"

	// unitDir is the host directory of the unit files.
	unitDir = "/etc/systemd/system"

	// restartPending holds the units due a restart until they restart. It
	// lives on tmpfs because a reboot starts the units from the new files
	// anyway.
	restartPending = "/run/nydus-v3/restart-pending"

	// payloadNydusBinary is the nydus binary in the payload.
	payloadNydusBinary = "bin/nydus"

	// payloadSnapshotterBinary is the snapshotter binary in the payload.
	payloadSnapshotterBinary = "bin/nydus-snapshotter"

	// payloadConfigFile is the snapshotter config in the payload.
	payloadConfigFile = "config/config.yaml"

	// payloadTemplateFile is the nydusd config template in the payload.
	payloadTemplateFile = "config/nydusd.template.yaml"

	// payloadCertsDir is the certs.d directory in the payload.
	payloadCertsDir = "config/certs.d"

	// hostsFile is the registry host config in a certs.d host directory.
	hostsFile = "hosts.toml"
)

// versionRegexp matches a nydus version usable as a directory name.
var versionRegexp = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]*$`)

// Config is the installer config.
type Config struct {
	// HostRoot is where the host root is mounted, / when run on the host.
	HostRoot string

	// PayloadDir holds what is installed.
	PayloadDir string

	// TokenDir is the Pod's service account token directory.
	TokenDir string

	// SyncInterval is how often the token is copied to the host.
	SyncInterval time.Duration
}

// Validate checks the config.
func (c *Config) Validate() error {
	if c.SyncInterval <= 0 {
		return fmt.Errorf("invalid sync interval %s", c.SyncInterval)
	}

	return nil
}

// host returns where a host path is in the Pod. Symlinks in its parent
// directories resolve within the host root, as an absolute link on the host
// must, refer to https://github.com/containerd/continuity/blob/main/fs/path.go.
// The last element is kept, so a link itself can be replaced.
func (c *Config) host(path string) (string, error) {
	dir, err := continuityfs.RootPath(c.HostRoot, filepath.Dir(path))
	if err != nil {
		return "", fmt.Errorf("resolve host path %s: %w", path, err)
	}

	return filepath.Join(dir, filepath.Base(path)), nil
}

// payload returns where a payload file is.
func (c *Config) payload(path string) string {
	return filepath.Join(c.PayloadDir, path)
}

// payloadFile is a payload file and where it goes on the host.
type payloadFile struct {
	// src is the path under the payload dir.
	src string

	// dst is the host path.
	dst string

	// perm is the mode of dst.
	perm os.FileMode

	// data is the content validated before install, nil to read src then.
	// A ConfigMap can change between two reads, so a validated file is
	// installed from the bytes that were validated.
	data []byte
}

// change is a payload file whose host copy differs.
type change struct {
	// file is the payload file.
	file payloadFile

	// path is where the host path is in the Pod.
	path string

	// data is the payload file's content.
	data []byte
}

// Installer installs the snapshotter onto the host from the DaemonSet Pod.
type Installer struct {
	// cfg is the installer config.
	cfg *Config

	// systemd manages the host's snapshotter units.
	systemd systemd.Manager
}

// New installer.
func New(cfg *Config, manager systemd.Manager) *Installer {
	return &Installer{cfg: cfg, systemd: manager}
}

// Run syncs the Kubernetes credentials, installs the payload and restarts the
// snapshotter when anything it reads at start changed, then keeps the
// credentials and the config in sync until ctx is done. A synced config is
// not followed by a restart: the snapshotter reloads cgroup and
// nydusd.dragonfly itself and reads the template and certs.d per daemon
// start; other keys apply on its next restart. It never stops daemons, edits
// containerd's config or uninstalls.
func (i *Installer) Run(ctx context.Context) error {
	// Sync the credentials first, so a restarted snapshotter finds a valid token.
	if err := i.syncKubeconfig(); err != nil {
		return err
	}

	if err := i.install(ctx); err != nil {
		return err
	}

	tick := time.NewTicker(i.cfg.SyncInterval)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			if err := i.syncKubeconfig(); err != nil {
				log.G(ctx).WithError(err).Error("sync kubernetes credentials")
			}

			if _, err := i.syncConfig(ctx); err != nil {
				log.G(ctx).WithError(err).Error("sync config")
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// install copies the payload onto the host, enables the units, restarts the
// units whose files changed and starts whichever unit is inactive.
func (i *Installer) install(ctx context.Context) error {
	version, err := i.nydusVersion(ctx)
	if err != nil {
		return err
	}

	// config.DefaultNydusdBinary is <bin dir>/current/nydus; each version gets
	// its own dir so running daemons keep the binary they started with.
	currentLink := filepath.Dir(config.DefaultNydusdBinary)
	nydusBinary := filepath.Join(filepath.Dir(currentLink), version, filepath.Base(config.DefaultNydusdBinary))
	files := []payloadFile{
		{src: payloadNydusBinary, dst: nydusBinary, perm: 0o755},
		{src: payloadSnapshotterBinary, dst: snapshotterBinary, perm: 0o755},
		{src: "systemd/" + socketUnit, dst: filepath.Join(unitDir, socketUnit), perm: 0o644},
		{src: "systemd/" + serviceUnit, dst: filepath.Join(unitDir, serviceUnit), perm: 0o644},
	}

	configFiles, err := i.configFiles()
	if err != nil {
		return err
	}
	files = append(files, configFiles...)

	if _, err := i.installFiles(ctx, files); err != nil {
		return err
	}

	// Point current at the version only once its binary is in place.
	link, err := i.cfg.host(currentLink)
	if err != nil {
		return err
	}

	previous, err := os.Readlink(link)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read %s: %w", link, err)
	}

	switched, err := i.switchLink(link, version)
	if err != nil {
		return err
	}

	if switched {
		log.G(ctx).WithFields(log.Fields{"version": version, "previous": previous}).Info("switched nydus version")
		if err := i.pruneVersions(ctx, filepath.Dir(link), version, previous); err != nil {
			log.G(ctx).WithError(err).Warn("prune nydus versions")
		}
	}

	if err := i.systemd.EnableUnitFiles(ctx, []string{socketUnit, serviceUnit}); err != nil {
		return err
	}

	pending, err := i.pendingRestarts()
	if err != nil {
		return err
	}

	// Restart a pending unit and start an inactive one.
	for _, unit := range []string{socketUnit, serviceUnit} {
		if !slices.Contains(pending, unit) {
			state, err := i.systemd.ActiveState(ctx, unit)
			if err != nil {
				return err
			}

			if state == systemd.ActiveStateActive {
				continue
			}
		}

		log.G(ctx).WithField("unit", unit).Info("restarting unit")
		if err := i.systemd.RestartUnit(ctx, unit); err != nil {
			return err
		}
	}

	path, err := i.cfg.host(restartPending)
	if err != nil {
		return err
	}

	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", path, err)
	}

	return nil
}

// syncConfig copies the config files onto the host without restarting the
// snapshotter and reports the files it changed. A changed config.yaml leaves
// the service pending a restart, so keys the snapshotter cannot reload apply
// on the next install, the rollout the ConfigMap checksum triggers, even
// though the new Pod then finds the host config already in place.
func (i *Installer) syncConfig(ctx context.Context) ([]string, error) {
	files, err := i.configFiles()
	if err != nil {
		return nil, err
	}

	return i.installFiles(ctx, files)
}

// configFiles returns the config files of the payload, validated before
// anything touches the host so a broken ConfigMap leaves the running
// snapshotter alone: config.yaml, the nydusd template and certs.d when
// present.
func (i *Installer) configFiles() ([]payloadFile, error) {
	_, data, err := i.payloadConfig()
	if err != nil {
		return nil, err
	}

	template, err := os.ReadFile(i.cfg.payload(payloadTemplateFile))
	if err != nil {
		return nil, fmt.Errorf("read payload nydusd template: %w", err)
	}

	if err := yaml.Unmarshal(template, &map[string]any{}); err != nil {
		return nil, fmt.Errorf("decode payload nydusd template: %w", err)
	}

	files := []payloadFile{
		{src: payloadConfigFile, dst: config.DefaultPath, perm: 0o644, data: data},
		{src: payloadTemplateFile, dst: config.DefaultNydusdTemplate, perm: 0o644, data: template},
	}

	// Files dropped from certs.d stay on the host, so hosts.toml baked into
	// the node image survive.
	certsDir := i.cfg.payload(payloadCertsDir)
	if err := fs.WalkDir(os.DirFS(certsDir), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		data, err := os.ReadFile(filepath.Join(certsDir, path))
		if err != nil {
			return err
		}

		if d.Name() == hostsFile {
			if err := toml.Unmarshal(data, &map[string]any{}); err != nil {
				return fmt.Errorf("decode %s: %w", path, err)
			}
		}

		files = append(files, payloadFile{src: filepath.Join(payloadCertsDir, path), dst: filepath.Join(config.DefaultRegistryConfigPath, path), perm: 0o644, data: data})
		return nil
	}); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("walk payload certs.d: %w", err)
	}

	return files, nil
}

// payloadConfig returns the validated config.yaml of the payload and its
// content.
func (i *Installer) payloadConfig() (*config.Config, []byte, error) {
	data, err := os.ReadFile(i.cfg.payload(payloadConfigFile))
	if err != nil {
		return nil, nil, fmt.Errorf("read payload config: %w", err)
	}

	cfg, err := config.Parse(data)
	if err != nil {
		return nil, nil, fmt.Errorf("parse payload config: %w", err)
	}

	return cfg, data, nil
}

// installFiles copies payload files onto the host and returns the host paths
// it changed. The units a changed file needs restarted are marked pending
// before anything is written, so a run that dies before restarting them is
// finished by the next one.
func (i *Installer) installFiles(ctx context.Context, files []payloadFile) ([]string, error) {
	var changes []change
	for _, file := range files {
		data := file.data
		if data == nil {
			var err error
			data, err = os.ReadFile(i.cfg.payload(file.src))
			if err != nil {
				return nil, fmt.Errorf("read payload: %w", err)
			}
		}

		path, err := i.cfg.host(file.dst)
		if err != nil {
			return nil, err
		}

		if !i.holds(path, data, file.perm) {
			changes = append(changes, change{file: file, path: path, data: data})
		}
	}

	if err := i.markRestarts(i.restartUnits(changes)); err != nil {
		return nil, err
	}

	changed := make([]string, 0, len(changes))
	for _, c := range changes {
		if err := i.write(c.path, c.data, c.file.perm); err != nil {
			return nil, err
		}

		log.G(ctx).WithField("path", c.file.dst).Info("installed file")
		changed = append(changed, c.file.dst)
	}

	return changed, nil
}

// restartUnits returns the units changed files need restarted: the socket and
// its service for the socket unit, the service for what it reads only at
// start. The nydusd template, certs.d and nydus binaries are read per daemon
// start and need none.
func (i *Installer) restartUnits(changes []change) []string {
	var units []string
	for _, c := range changes {
		switch c.file.dst {
		case filepath.Join(unitDir, socketUnit):
			units = append(units, socketUnit, serviceUnit)
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

	return i.writeFile(path, []byte(strings.Join(units, "\n")+"\n"), 0o644)
}

// syncKubeconfig copies the Pod's service account token and CA to the host
// and writes a kubeconfig reading them, for the snapshotter's secret
// informer; without kubesecret it does nothing, and no token is mounted.
// client-go re-reads a rotated token file, refer to
// https://github.com/kubernetes/client-go/blob/master/transport/token_source.go.
func (i *Installer) syncKubeconfig() error {
	cfg, _, err := i.payloadConfig()
	if err != nil {
		return err
	}

	if !cfg.Auth.KubeSecret.Enable {
		return nil
	}

	// Reach the API server as in-cluster clients do, refer to
	// https://github.com/kubernetes/client-go/blob/master/rest/config.go.
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return errors.New("KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set")
	}

	dir := filepath.Dir(config.DefaultKubeconfig)
	tokenPath, caPath := filepath.Join(dir, "token"), filepath.Join(dir, "ca.crt")
	kubeconfig, err := clientcmd.Write(clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{
			"default": {
				Server:               "https://" + net.JoinHostPort(host, port),
				CertificateAuthority: caPath,
			},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"nydus-snapshotter": {
				TokenFile: tokenPath,
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			"default": {
				Cluster:  "default",
				AuthInfo: "nydus-snapshotter",
			},
		},
		CurrentContext: "default",
	})
	if err != nil {
		return fmt.Errorf("encode kubeconfig: %w", err)
	}

	token, err := os.ReadFile(filepath.Join(i.cfg.TokenDir, "token"))
	if err != nil {
		return fmt.Errorf("read service account token: %w", err)
	}

	ca, err := os.ReadFile(filepath.Join(i.cfg.TokenDir, "ca.crt"))
	if err != nil {
		return fmt.Errorf("read service account ca: %w", err)
	}

	// The token is a credential: keep it on tmpfs, in a dir only root reads.
	hostDir, err := i.cfg.host(dir)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(hostDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", hostDir, err)
	}

	// Write the token and CA before the kubeconfig naming them.
	for _, file := range []struct {
		path string
		data []byte
		perm os.FileMode
	}{
		{path: tokenPath, data: token, perm: 0o600},
		{path: caPath, data: ca, perm: 0o644},
		{path: config.DefaultKubeconfig, data: kubeconfig, perm: 0o600},
	} {
		path, err := i.cfg.host(file.path)
		if err != nil {
			return err
		}

		if err := i.writeFile(path, file.data, file.perm); err != nil {
			return err
		}
	}

	return nil
}

// nydusVersion returns the version the payload's nydus binary prints, 3.0.0
// in "nydus 3.0.0 (1a2b3c4d5, 2026-01-02)".
func (i *Installer) nydusVersion(ctx context.Context) (string, error) {
	binary := i.cfg.payload(payloadNydusBinary)
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

// writeFile atomically writes data to path with perm unless the file already
// holds it.
func (i *Installer) writeFile(path string, data []byte, perm os.FileMode) error {
	if i.holds(path, data, perm) {
		return nil
	}

	return i.write(path, data, perm)
}

// write atomically writes data to path with perm, creating its directory.
func (i *Installer) write(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create dir of %s: %w", path, err)
	}

	// Write a temporary file in the same dir, fsync and rename it.
	if err := continuity.AtomicWriteFile(path, data, perm); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	return nil
}

// holds reports whether the regular file at path holds data with perm.
func (i *Installer) holds(path string, data []byte, perm os.FileMode) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || info.Mode() != perm || info.Size() != int64(len(data)) {
		return false
	}

	current, err := io.ReadAll(f)
	return err == nil && bytes.Equal(current, data)
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

// switchLink atomically points link at target and reports whether it changed.
func (i *Installer) switchLink(link, target string) (bool, error) {
	if current, err := os.Readlink(link); err == nil && current == target {
		return false, nil
	}

	tmp := link + ".tmp"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("remove %s: %w", tmp, err)
	}

	if err := os.Symlink(target, tmp); err != nil {
		return false, fmt.Errorf("create symlink %s: %w", tmp, err)
	}

	if err := os.Rename(tmp, link); err != nil {
		return false, fmt.Errorf("rename %s: %w", tmp, err)
	}

	return true, nil
}
