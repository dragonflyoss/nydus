package snapshotter

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/leases"
	ctrmount "github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/opencontainers/image-spec/identity"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

const (
	plugin        = "nydus"
	labelPrefetch = "containerd.io/snapshot/nydus-prefetch"
	startTimeout  = 30 * time.Second
	gcTimeout     = 30 * time.Second
)

var containerdVersion = regexp.MustCompile(`\sv(\d+)\.\d+\.\d+`)

type node struct {
	client              *containerd.Client
	ctx                 context.Context
	runc                string
	snapshotter, config string
	daemon              *mount.Daemon
	dir, root, runDir   string
	slice, parentSlice  string
	dockerConfig        string
	user, password      string
}

func newNode(t *testing.T) *node {
	t.Helper()
	containerdBin, runcBin := hostBinaries(t)
	id := fmt.Sprintf("%08x", rand.Uint32())
	n := &node{
		runc:        runcBin,
		snapshotter: env.Snapshotter(t),
		dir:         t.TempDir(),
		runDir:      "/run/nydus-e2e-" + id,
		slice:       "system-nyduse2e" + id + "-v3.slice",
		parentSlice: "system-nyduse2e" + id + ".slice",
	}
	n.root = filepath.Join(n.dir, "snapshotter")
	n.config = filepath.Join(n.dir, "config.yaml")
	n.dockerConfig = filepath.Join(n.dir, "docker", "config.json")
	namespace := "nydus-e2e-" + id
	t.Cleanup(func() { n.teardown(t, namespace) })

	n.writeConfig(t)
	n.startSnapshotter(t, "snapshotter")
	address := n.startContainerd(t, containerdBin)

	client, err := containerd.New(address, containerd.WithDefaultNamespace(namespace))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	n.client = client
	n.ctx = namespaces.WithNamespace(context.Background(), namespace)
	t.Cleanup(func() {
		n.removeContainers(t)
		_ = client.Close()
	})

	ctx, cancel := context.WithTimeout(n.ctx, startTimeout)
	defer cancel()
	if !assert.Eventually(t, func() bool {
		serving, _ := client.IsServing(ctx)
		return serving
	}, startTimeout, 100*time.Millisecond) {
		t.FailNow()
	}

	return n
}

func hostBinaries(t *testing.T) (string, string) {
	t.Helper()
	env.MustHaveRoot(t)
	mount.FUSE{}.Require(t)
	env.MustHaveFilesystem(t, "overlay")
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		env.Skipf(t, "systemd is not PID 1: the snapshotter starts daemons as transient units")
	}

	env.LookPath(t, "systemctl")
	env.LookPath(t, "systemd-run")
	containerdBin := os.Getenv("NYDUS_E2E_CONTAINERD")
	if containerdBin == "" {
		env.Skipf(t, "NYDUS_E2E_CONTAINERD is not set")
	}

	runcBin := os.Getenv("NYDUS_E2E_RUNC")
	if runcBin == "" {
		runcBin = env.LookPath(t, "runc")
	}

	return containerdBin, runcBin
}

func (n *node) writeConfig(t *testing.T) {
	t.Helper()
	repo, err := env.RepoRoot()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	nydus, err := filepath.Abs(env.Nydus(t))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	config := fmt.Sprintf(`version: 1
root: %q
address: %q
run_dir: %q
log:
  level: debug
metrics:
  address: ''
registry:
  config_path: %q
auth:
  docker_config:
    path: %q
nydusd:
  binary: %q
  template: %q
  log_dir: %q
cgroup:
  slice: %q
`, n.root, n.snapshotterAddress(), n.runDir, filepath.Join(n.dir, "certs.d"), n.dockerConfig, nydus,
		filepath.Join(repo, "nydus-snapshotter", "deploy", "nydus-snapshotter", "nydusd.template.yaml"),
		n.daemonLogDir(), n.slice)
	assert.NoError(t, os.WriteFile(n.config, []byte(config), 0o600))
}

func (n *node) snapshotterAddress() string {
	return filepath.Join(n.runDir, "snapshotter.sock")
}

func (n *node) daemonLogDir() string {
	return filepath.Join(n.dir, "nydusd-logs")
}

func (n *node) startSnapshotter(t *testing.T, name string) {
	t.Helper()
	n.daemon = mount.StartDaemon(t, n.dir, name, n.snapshotter, "--config", n.config)
	n.daemon.WaitFor(t, startTimeout, "snapshotter socket", func() bool {
		conn, err := net.Dial("unix", n.snapshotterAddress())
		if err == nil {
			_ = conn.Close()
		}

		return err == nil
	})
}

func (n *node) startContainerd(t *testing.T, bin string) string {
	t.Helper()
	out := []byte(env.Run(t, bin, "--version"))
	match := containerdVersion.FindSubmatch(out)
	if !assert.NotNil(t, match) {
		t.FailNow()
	}

	version, snippet := 3, "config-v2.toml"
	if string(match[1]) == "1" {
		version, snippet = 2, "config-v1.6.toml"
	}

	t.Logf("%s", bytes.TrimSpace(out))
	repo, err := env.RepoRoot()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	shipped, err := os.ReadFile(filepath.Join(repo, "nydus-snapshotter", "deploy", "containerd", snippet))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	address := filepath.Join(n.runDir, "containerd", "containerd.sock")
	config := fmt.Sprintf(`version = %d
root = %q
state = %q
disabled_plugins = ["io.containerd.grpc.v1.cri", "io.containerd.nri.v1.nri"]

[grpc]
  address = %q

`, version, filepath.Join(n.dir, "containerd"), filepath.Join(n.runDir, "containerd", "state"), address)
	config += strings.NewReplacer(
		"/run/containerd-nydus-v3/containerd-nydus-grpc.sock", n.snapshotterAddress(),
		"/var/lib/containerd-nydus-v3", n.root,
	).Replace(string(shipped))
	path := filepath.Join(n.dir, "containerd.toml")
	if !assert.NoError(t, os.WriteFile(path, []byte(config), 0o600)) {
		t.FailNow()
	}

	pathEnv := "PATH=" + filepath.Dir(bin) + ":" + os.Getenv("PATH")
	d := mount.StartDaemon(t, n.dir, "containerd", env.LookPath(t, "env"), pathEnv, bin, "--config", path)
	d.WaitFor(t, startTimeout, "containerd socket", func() bool {
		_, err := os.Stat(address)
		return err == nil
	})

	return address
}

func (n *node) teardown(t *testing.T, namespace string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if t.Failed() {
		entries, _ := os.ReadDir(n.daemonLogDir())
		for _, entry := range entries {
			files, _ := os.ReadDir(filepath.Join(n.daemonLogDir(), entry.Name()))
			for _, file := range files {
				data, _ := os.ReadFile(filepath.Join(n.daemonLogDir(), entry.Name(), file.Name()))
				t.Logf("nydusd %s %s:\n%s", entry.Name(), file.Name(), data)
			}
		}

		out, _ := exec.CommandContext(ctx, "journalctl", "--no-pager", "-o", "short-precise", "_SYSTEMD_SLICE="+n.slice).CombinedOutput()
		t.Logf("journal of %s:\n%s", n.slice, out)
	}

	if out, err := exec.CommandContext(ctx, "systemctl", "stop", n.parentSlice).CombinedOutput(); err != nil {
		t.Logf("stop %s: %v: %s", n.parentSlice, err, out)
	}

	for _, dir := range []string{n.runDir, n.dir} {
		assert.NoError(t, ctrmount.UnmountRecursive(dir, unix.MNT_DETACH))
	}

	assert.NoError(t, os.RemoveAll(n.runDir))
	_ = os.Remove(filepath.Join("/sys/fs/cgroup", namespace))
}

func (n *node) restartSnapshotter(t *testing.T, name string, down func()) {
	t.Helper()
	if !assert.True(t, n.daemon.Stop()) {
		t.FailNow()
	}

	down()
	n.startSnapshotter(t, name)
}

func (n *node) login(t *testing.T, host, user, password string) {
	t.Helper()
	n.user, n.password = user, password
	data, err := json.Marshal(map[string]any{"auths": map[string]any{
		host: map[string]string{"auth": base64.StdEncoding.EncodeToString([]byte(user + ":" + password))},
	}})
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.NoError(t, os.MkdirAll(filepath.Dir(n.dockerConfig), 0o700))
	assert.NoError(t, os.WriteFile(n.dockerConfig, data, 0o600))
}

func (n *node) pull(t *testing.T, ref string, opts ...containerd.RemoteOpt) containerd.Image {
	t.Helper()
	opts = append([]containerd.RemoteOpt{containerd.WithImageHandlerWrapper(snapshotters.AppendInfoHandlerWrapper(ref))}, opts...)
	img, err := n.tryPull(ref, opts...)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return img
}

func (n *node) tryPull(ref string, opts ...containerd.RemoteOpt) (containerd.Image, error) {
	ctx, cancel := context.WithTimeout(n.ctx, 2*time.Minute)
	defer cancel()
	hosts := docker.ConfigureDefaultRegistries(
		docker.WithPlainHTTP(docker.MatchLocalhost),
		docker.WithAuthorizer(docker.NewDockerAuthorizer(docker.WithAuthCreds(func(string) (string, string, error) {
			return n.user, n.password, nil
		}))),
	)

	return n.client.Pull(ctx, ref, append([]containerd.RemoteOpt{
		containerd.WithPullUnpack,
		containerd.WithPullSnapshotter(plugin),
		containerd.WithResolver(docker.NewResolver(docker.ResolverOptions{Hosts: hosts})),
	}, opts...)...)
}

func (n *node) gc(t *testing.T) {
	t.Helper()
	l, err := n.client.LeasesService().Create(n.ctx, leases.WithRandomID())
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.NoError(t, n.client.LeasesService().Delete(n.ctx, l, leases.SynchronousDelete))
}

func (n *node) chainID(t *testing.T, img containerd.Image) string {
	t.Helper()
	diffIDs, err := img.RootFS(n.ctx)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return identity.ChainID(diffIDs).Encoded()
}

func (n *node) unit(t *testing.T, img containerd.Image) string {
	t.Helper()
	return "nydusd-" + n.chainID(t, img) + ".service"
}

type daemonConfig struct {
	Prefetch struct {
		Scope string `yaml:"scope"`
	} `yaml:"prefetch"`
	Backend struct {
		Config struct {
			Addr string `yaml:"addr"`
			Auth string `yaml:"auth"`
		} `yaml:"config"`
	} `yaml:"backend"`
}

func (n *node) renderedConfig(t *testing.T, img containerd.Image) daemonConfig {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(n.runDir, "nydusd", n.chainID(t, img), "config.yaml"))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	var config daemonConfig
	assert.NoError(t, yaml.Unmarshal(data, &config))
	return config
}

func (n *node) units(t *testing.T) []string {
	t.Helper()
	out := env.Run(t, "systemctl", "list-units", "--all", "--plain", "--no-legend", "--full", "nydusd-*.service")
	var units []string
	for line := range strings.Lines(out) {
		if fields := strings.Fields(line); len(fields) > 0 && show(t, fields[0], "Slice")["Slice"] == n.slice {
			units = append(units, fields[0])
		}
	}

	return units
}

func show(t *testing.T, unit string, props ...string) map[string]string {
	t.Helper()
	out := env.Run(t, "systemctl", "show", unit, "--property="+strings.Join(props, ","))
	values := make(map[string]string, len(props))
	for line := range strings.Lines(out) {
		if key, value, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			values[key] = value
		}
	}

	return values
}

func (n *node) runningDaemon(t *testing.T, unit string) string {
	t.Helper()
	props := show(t, unit, "ActiveState", "Slice", "InvocationID")
	assert.Equal(t, "active", props["ActiveState"])
	assert.Equal(t, n.slice, props["Slice"])
	if !assert.NotEmpty(t, props["InvocationID"]) {
		t.FailNow()
	}

	return props["InvocationID"]
}

func waitStopped(t *testing.T, unit string, timeout time.Duration) {
	t.Helper()
	loaded := func() bool {
		out, err := exec.Command("systemctl", "show", unit, "--property=LoadState").Output()
		return err != nil || strings.TrimSpace(string(out)) != "LoadState=not-found"
	}
	if !assert.Eventually(t, func() bool { return !loaded() }, timeout, 200*time.Millisecond) {
		t.FailNow()
	}
}
