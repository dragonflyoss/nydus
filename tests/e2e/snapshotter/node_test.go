package snapshotter

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
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
	dockerconfig "github.com/containerd/containerd/v2/core/remotes/docker/config"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/containerd/errdefs"
	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/opencontainers/image-spec/identity"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"gopkg.in/yaml.v3"
)

const (
	plugin         = "nydus"
	labelNydusBlob = "containerd.io/snapshot/nydus-blob"
	labelPrefetch  = "containerd.io/snapshot/nydus-prefetch"
	unitDir        = "/run/systemd/system"
	startTimeout   = 30 * time.Second
	gcTimeout      = 30 * time.Second
	reloadTimeout  = 30 * time.Second
)

var containerdVersion = regexp.MustCompile(`\sv(\d+)\.\d+\.\d+`)

type node struct {
	client         *containerd.Client
	ctx            context.Context
	namespace      string
	address        string
	runcBin        string
	snapshotterBin string
	snapshotter    *mount.Daemon
	config         string
	dir            string
	root           string
	runDir         string
	containerdDir  string
	slice          string
	dockerConfig   string
	metricsAddress string
	user           string
	password       string
	pause          string
	service        string
	kubeconfig     string
	selector       string
	memoryHigh     string
}

type nodeOption func(*node)

func withCRI(pause string) nodeOption {
	return func(n *node) { n.pause = pause }
}

func withSocketActivation() nodeOption {
	return func(n *node) { n.service = n.namespace }
}

func withKubeSecret(kubeconfig, selector string) nodeOption {
	return func(n *node) { n.kubeconfig, n.selector = kubeconfig, selector }
}

func newNode(t *testing.T, opts ...nodeOption) *node {
	t.Helper()
	containerdBin, runcBin := requireHost(t)
	id := fmt.Sprintf("%08x", rand.Uint32())
	n := &node{
		namespace:      "nydus-e2e-" + id,
		runcBin:        runcBin,
		snapshotterBin: env.Snapshotter(t),
		dir:            t.TempDir(),
		runDir:         "/run/nydus-e2e-" + id,
		containerdDir:  "/run/nydus-e2e-containerd-" + id,
		slice:          "system-nyduse2e" + id + ".slice",
	}
	for _, opt := range opts {
		opt(n)
	}

	n.root = filepath.Join(n.dir, "snapshotter")
	n.metricsAddress = freeAddress(t)
	n.config = filepath.Join(n.dir, "config.yaml")
	n.dockerConfig = filepath.Join(n.dir, "docker", "config.json")
	t.Cleanup(func() { n.teardown(t) })

	n.writeConfig(t)
	n.startSnapshotter(t, "snapshotter")
	n.address = n.startContainerd(t, containerdBin)

	client, err := containerd.New(n.address, containerd.WithDefaultNamespace(n.namespace))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	n.client = client
	n.ctx = namespaces.WithNamespace(context.Background(), n.namespace)
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

func (n *node) in(namespace string) *node {
	other := *n
	other.namespace = namespace
	other.ctx = namespaces.WithNamespace(context.Background(), namespace)
	return &other
}

func requireHost(t *testing.T) (string, string) {
	t.Helper()
	env.MustHaveRoot(t)
	mount.FUSE{}.Require(t)
	env.MustHaveFilesystem(t, "overlay")
	if _, err := os.Stat(unitDir); err != nil {
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
	nydus, err := filepath.Abs(env.Nydus(t))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	auth := map[string]any{"docker_config": map[string]any{"path": n.dockerConfig}}
	if n.kubeconfig != "" {
		auth["kube_secret"] = map[string]any{"enable": true, "kubeconfig": n.kubeconfig, "label_selector": n.selector}
	}

	cgroup := map[string]any{"slice": n.slice}
	if n.memoryHigh != "" {
		cgroup["daemon"] = map[string]any{"memory_high": n.memoryHigh}
	}

	config, err := yaml.Marshal(map[string]any{
		"root_dir":    n.root,
		"runtime_dir": n.runDir,
		"grpc":        map[string]any{"addr": n.snapshotterAddress()},
		"log":         map[string]any{"level": "debug"},
		"metrics":     map[string]any{"addr": n.metricsAddress},
		"registry":    map[string]any{"config_path": n.certsDir()},
		"auth":        auth,
		"nydusd": map[string]any{
			"binary":  nydus,
			"log_dir": n.daemonLogDir(),
		},
		"cgroup": cgroup,
	})
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.NoError(t, os.WriteFile(n.config, config, 0o600))
}

func deployPath(t *testing.T, elem ...string) string {
	t.Helper()
	repo, err := env.RepoRoot()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return filepath.Join(append([]string{repo, "nydus-snapshotter", "deploy"}, elem...)...)
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	address := listener.Addr().String()
	assert.NoError(t, listener.Close())
	return address
}

func (n *node) metrics(t *testing.T) string {
	t.Helper()
	status, body, err := n.get("/metrics")
	if !assert.NoError(t, err) || !assert.Equal(t, http.StatusOK, status) {
		t.FailNow()
	}

	return body
}

func (n *node) get(path string) (int, string, error) {
	req, err := http.NewRequestWithContext(n.ctx, http.MethodGet, "http://"+n.metricsAddress+path, nil)
	if err != nil {
		return 0, "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), err
}

func (n *node) serving() bool {
	conn, err := grpc.NewClient("unix://"+n.snapshotterAddress(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
	defer cancel()
	resp, err := grpc_health_v1.NewHealthClient(conn).Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	return err == nil && resp.GetStatus() == grpc_health_v1.HealthCheckResponse_SERVING
}

func (n *node) snapshotterAddress() string {
	return filepath.Join(n.runDir, "snapshotter.sock")
}

func (n *node) certsDir() string {
	return filepath.Join(n.dir, "certs.d")
}

func (n *node) writeHosts(t *testing.T, host, hosts string) {
	t.Helper()
	dir := filepath.Join(n.certsDir(), host)
	assert.NoError(t, os.MkdirAll(dir, 0o755))
	assert.NoError(t, os.WriteFile(filepath.Join(dir, "hosts.toml"), []byte(hosts), 0o644))
}

func (n *node) withHosts() containerd.RemoteOpt {
	return containerd.WithResolver(docker.NewResolver(docker.ResolverOptions{
		Hosts: dockerconfig.ConfigureHosts(n.ctx, dockerconfig.HostOptions{HostDir: dockerconfig.HostDirFromRoot(n.certsDir())}),
	}))
}

func (n *node) daemonLogDir() string {
	return filepath.Join(n.dir, "nydusd-logs")
}

func (n *node) startSnapshotter(t *testing.T, name string) {
	t.Helper()
	if n.service != "" {
		n.startUnits(t)
		return
	}

	n.snapshotter = mount.StartDaemon(t, n.dir, name, n.snapshotterBin, "--config", n.config)
	n.snapshotter.WaitFor(t, startTimeout, "snapshotter socket", func() bool {
		conn, err := net.Dial("unix", n.snapshotterAddress())
		if err == nil {
			_ = conn.Close()
		}

		return err == nil
	})
}

func (n *node) startUnits(t *testing.T) {
	t.Helper()
	bin, err := filepath.Abs(n.snapshotterBin)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	replacer := strings.NewReplacer(
		"nydus-snapshotter.socket", n.service+".socket",
		"/usr/local/bin/nydus-snapshotter", bin,
		"/etc/nydus-snapshotter/config.yaml", n.config,
		"/run/nydus-snapshotter/nydus-snapshotter.sock", n.snapshotterAddress(),
	)
	for _, suffix := range []string{".socket", ".service"} {
		shipped, err := os.ReadFile(deployPath(t, "systemd", "nydus-snapshotter"+suffix))
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		unit := replacer.Replace(string(shipped))
		if dir := os.Getenv("GOCOVERDIR"); dir != "" && suffix == ".service" {
			unit += "\n[Service]\nEnvironment=GOCOVERDIR=" + dir + "\n"
		}

		if !assert.NoError(t, os.WriteFile(filepath.Join(unitDir, n.service+suffix), []byte(unit), 0o644)) {
			t.FailNow()
		}
	}

	env.Run(t, "systemctl", "daemon-reload")
	env.Run(t, "systemctl", "start", n.service+".socket")
	assert.Equal(t, "inactive", unitProperty(n.service+".service", "ActiveState"))
}

func (n *node) startContainerd(t *testing.T, bin string) string {
	t.Helper()
	path, address := n.containerdConfig(t, bin)
	pathEnv := "PATH=" + filepath.Dir(bin) + ":" + os.Getenv("PATH")
	d := mount.StartDaemon(t, n.dir, "containerd", env.LookPath(t, "env"), pathEnv, bin, "--config", path)
	d.WaitFor(t, startTimeout, "containerd socket", func() bool {
		_, err := os.Stat(address)
		return err == nil
	})

	return address
}

func (n *node) containerdConfig(t *testing.T, bin string) (path, address string) {
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
	shipped, err := os.ReadFile(deployPath(t, "containerd", snippet))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	if !assert.NoError(t, os.MkdirAll(n.containerdDir, 0o711)) {
		t.FailNow()
	}

	address = filepath.Join(n.containerdDir, "containerd.sock")
	disabled := `"io.containerd.grpc.v1.cri", "io.containerd.nri.v1.nri"`
	if n.pause != "" {
		disabled = `"io.containerd.nri.v1.nri"`
	}

	config := fmt.Sprintf(`version = %d
root = %q
state = %q
disabled_plugins = [%s]

[grpc]
  address = %q

`, version, filepath.Join(n.dir, "containerd"), filepath.Join(n.containerdDir, "state"), disabled, address)
	config += strings.NewReplacer(
		"/run/nydus-snapshotter/nydus-snapshotter.sock", n.snapshotterAddress(),
		"/var/lib/nydus-snapshotter", n.root,
	).Replace(string(shipped))
	if n.pause != "" {
		images, runtime, sandbox := `"io.containerd.cri.v1.images".pinned_images`, `"io.containerd.cri.v1.runtime"`, "sandbox"
		if version == 2 {
			images, runtime, sandbox = `"io.containerd.grpc.v1.cri"`, `"io.containerd.grpc.v1.cri"`, "sandbox_image"
		}

		config += fmt.Sprintf(`
[plugins.%s]
  %s = %q

[plugins.%s.containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"
  [plugins.%s.containerd.runtimes.runc.options]
    BinaryName = %q
`, images, sandbox, n.pause, runtime, runtime, n.runcBin)
	}

	path = filepath.Join(n.dir, "containerd.toml")
	if !assert.NoError(t, os.WriteFile(path, []byte(config), 0o600)) {
		t.FailNow()
	}

	return path, address
}

func (n *node) teardown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if n.service != "" {
		service, socket := n.service+".service", n.service+".socket"
		if t.Failed() {
			out, _ := exec.CommandContext(ctx, "journalctl", "--no-pager", "-o", "short-precise", "--unit", service).CombinedOutput()
			t.Logf("journal of %s:\n%s", service, out)
		}

		_ = exec.CommandContext(ctx, "systemctl", "stop", service, socket).Run()
		for _, unit := range []string{service, socket} {
			_ = os.Remove(filepath.Join(unitDir, unit))
		}

		_ = exec.CommandContext(ctx, "systemctl", "daemon-reload").Run()
	}

	if t.Failed() {
		logs, _ := filepath.Glob(filepath.Join(n.daemonLogDir(), "*", "*"))
		for _, path := range logs {
			data, _ := os.ReadFile(path)
			t.Logf("%s:\n%s", path, data)
		}

		out, _ := exec.CommandContext(ctx, "journalctl", "--no-pager", "-o", "short-precise", "_SYSTEMD_SLICE="+n.slice).CombinedOutput()
		t.Logf("journal of %s:\n%s", n.slice, out)
	}

	if out, err := exec.CommandContext(ctx, "systemctl", "stop", n.slice).CombinedOutput(); err != nil {
		t.Logf("stop %s: %v: %s", n.slice, err, out)
	}

	for _, dir := range []string{n.runDir, n.containerdDir, n.dir} {
		assert.NoError(t, ctrmount.UnmountRecursive(dir, unix.MNT_DETACH))
	}

	assert.NoError(t, os.RemoveAll(n.runDir))
	assert.NoError(t, os.RemoveAll(n.containerdDir))
	_ = os.Remove(filepath.Join("/sys/fs/cgroup", n.namespace))
}

func (n *node) restartSnapshotter(t *testing.T, name string, down func()) {
	t.Helper()
	if !assert.True(t, n.snapshotter.Stop()) {
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

func (n *node) retryUnavailable(t *testing.T, try func() error) {
	t.Helper()
	var err error
	if !assert.Eventually(t, func() bool {
		err = try()
		return !errdefs.IsUnavailable(err)
	}, startTimeout, 200*time.Millisecond) || !assert.NoError(t, err) {
		t.FailNow()
	}
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

type daemonInfo struct {
	Version      string   `json:"version"`
	PID          int      `json:"pid"`
	Capabilities []string `json:"capabilities"`
}

func (n *node) daemonInfo(t *testing.T, img containerd.Image) daemonInfo {
	t.Helper()
	body, err := mount.NewAPI(filepath.Join(n.runDir, "nydusd", n.chainID(t, img)+".sock")).Get("/api/v1/daemon")
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	var info daemonInfo
	if !assert.NoError(t, json.Unmarshal(body, &info)) {
		t.FailNow()
	}

	return info
}
