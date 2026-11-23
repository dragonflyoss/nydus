package snapshotter

import (
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/stretchr/testify/assert"
)

const (
	payloadDir        = "/opt/nydus-snapshotter/payload"
	payloadConfig     = payloadDir + "/config/config.yaml"
	tokenDir          = "/opt/nydus-snapshotter/token"
	installerConfig   = "\ninstaller:\n  rootfs_dir: /\n  payload_dir: " + payloadDir + "\n  token_dir: " + tokenDir + "\n  sync_interval: 1s\n"
	nodeLabelConfig   = "  node_label:\n    enable: true\n"
	snapshotterBinary = "/usr/local/bin/nydus-snapshotter"
	nydusCurrent      = "/opt/nydus-snapshotter/bin/current"
	hostConfig        = "/etc/nydus-snapshotter/config.yaml"
	kubernetesDir     = "/run/nydus-snapshotter/kubernetes"
	restartPending    = "/run/nydus-snapshotter/restart-pending"
	serviceUnit       = "nydus-snapshotter.service"
	socketUnit        = "nydus-snapshotter.socket"
	metricsURL        = "http://127.0.0.1:4010/metrics"
	nodeLabel         = "d7y.io/nydus-snapshotter"
	containerdConfig  = "/etc/containerd/config.toml"
	proxyPlugin       = "\n[proxy_plugins.nydus]\n  type = \"snapshot\"\n  address = \"/run/nydus-snapshotter/nydus-snapshotter.sock\"\n"
	installed         = "installed, keeping the config and the credentials in sync"
	bootTimeout       = time.Minute
	installTimeout    = time.Minute
	syncTimeout       = 30 * time.Second
)

type installNode struct {
	docker     string
	name       string
	dir        string
	installer  string
	config     string
	installers int
}

func newInstallNode(t *testing.T) *installNode {
	t.Helper()
	image := os.Getenv("NYDUS_E2E_NODE_IMAGE")
	if image == "" {
		env.Skipf(t, "NYDUS_E2E_NODE_IMAGE is not set")
	}

	n := &installNode{
		docker:    env.LookPath(t, "docker"),
		name:      fmt.Sprintf("nydus-e2e-install-%08x", rand.Uint32()),
		dir:       t.TempDir(),
		installer: installerConfig,
	}
	env.Run(t, n.docker, "run", "--detach", "--name", n.name, "--privileged",
		"--security-opt", "seccomp=unconfined", "--security-opt", "apparmor=unconfined",
		"--tmpfs", "/tmp", "--tmpfs", "/run", "--volume", "/var", "--volume", "/lib/modules:/lib/modules:ro",
		"--cgroupns=private", "--tty", image)
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command(n.docker, "exec", n.name, "journalctl", "--no-pager", "--output", "short-precise",
				"--unit", serviceUnit, "--unit", socketUnit, "--unit", "nydus-installer-*").CombinedOutput()
			t.Logf("journal of %s:\n%s", n.name, out)
		}

		_ = exec.Command(n.docker, "rm", "--force", "--volumes", n.name).Run()
	})

	n.waitBooted(t)
	snapshotter, err := os.ReadFile(env.Snapshotter(t))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	n.exec(t, "mkdir", "-p", payloadDir+"/bin", payloadDir+"/systemd", payloadDir+"/config", tokenDir)
	n.write(t, payloadDir+"/bin/nydus-snapshotter", string(snapshotter), 0o755)
	n.write(t, payloadDir+"/bin/nydus", nydusStub("3.0.0-e2e"), 0o755)
	for _, unit := range []string{socketUnit, serviceUnit} {
		n.write(t, payloadDir+"/systemd/"+unit, shipped(t, "systemd", unit), 0o644)
	}

	n.writeShippedConfig(t)

	return n
}

func nydusStub(version string) string {
	return "#!/bin/sh\necho 'nydus " + version + " (1a2b3c4d5, 2026-01-02)'\n"
}

func shipped(t *testing.T, elem ...string) string {
	t.Helper()
	data, err := os.ReadFile(deployPath(t, elem...))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return string(data)
}

func (n *installNode) waitBooted(t *testing.T) {
	t.Helper()
	if !assert.Eventually(t, func() bool {
		state, _ := n.tryExec("systemctl", "is-system-running")
		return state == "running" || state == "degraded"
	}, bootTimeout, 200*time.Millisecond) {
		t.FailNow()
	}
}

func (n *installNode) exec(t *testing.T, args ...string) string {
	t.Helper()
	return strings.TrimSpace(env.Run(t, n.docker, append([]string{"exec", n.name}, args...)...))
}

func (n *installNode) tryExec(args ...string) (string, error) {
	out, err := exec.Command(n.docker, append([]string{"exec", n.name}, args...)...).Output()
	return strings.TrimSpace(string(out)), err
}

func (n *installNode) write(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()
	local := filepath.Join(n.dir, filepath.Base(path))
	if !assert.NoError(t, os.WriteFile(local, []byte(data), mode)) || !assert.NoError(t, os.Chmod(local, mode)) {
		t.FailNow()
	}

	env.Run(t, n.docker, "cp", local, n.name+":"+path)
}

func (n *installNode) writeConfig(t *testing.T, config string) {
	t.Helper()
	n.config = config + n.installer
	n.write(t, payloadConfig, n.config, 0o644)
}

func (n *installNode) writeShippedConfig(t *testing.T) {
	t.Helper()
	config, _, found := strings.Cut(shipped(t, "nydus-snapshotter", "config.yaml"), "\ninstaller:\n")
	if !assert.True(t, found) {
		t.FailNow()
	}

	n.writeConfig(t, config+"\n")
}

func (n *installNode) start(t *testing.T, environment ...string) string {
	t.Helper()
	n.installers++
	unit := fmt.Sprintf("nydus-installer-%d.service", n.installers)
	args := []string{"systemd-run", "--unit", unit, "--collect"}
	for _, variable := range environment {
		args = append(args, "--setenv", variable)
	}

	n.exec(t, append(args, payloadDir+"/bin/nydus-snapshotter", "install", "--config", payloadConfig)...)

	return unit
}

func (n *installNode) install(t *testing.T, environment ...string) string {
	t.Helper()
	unit := n.start(t, environment...)
	if !assert.Eventually(t, func() bool {
		return strings.Contains(n.journal(unit), installed)
	}, installTimeout, 200*time.Millisecond) {
		t.FailNow()
	}

	return unit
}

func (n *installNode) stop(t *testing.T, unit string) {
	t.Helper()
	n.exec(t, "systemctl", "stop", unit)
}

func (n *installNode) journal(unit string) string {
	out, _ := n.tryExec("journalctl", "--no-pager", "--output", "cat", "--unit", unit)
	return out
}

func (n *installNode) property(t *testing.T, unit, name string) string {
	t.Helper()
	return n.exec(t, "systemctl", "show", unit, "--property="+name, "--value")
}

func (n *installNode) assertServing(t *testing.T) {
	t.Helper()
	for _, unit := range []string{socketUnit, serviceUnit} {
		assert.Equal(t, "active", n.property(t, unit, "ActiveState"))
		assert.Equal(t, "enabled", n.property(t, unit, "UnitFileState"))
	}

	assert.Contains(t, n.exec(t, "curl", "--fail", "--silent", metricsURL), "nydus_snapshotter_running_daemons")
}

func (n *installNode) starts() int {
	return strings.Count(n.journal(serviceUnit), "starting nydus-snapshotter")
}

func TestInstall(t *testing.T) {
	t.Parallel()
	n := newInstallNode(t)
	installer := n.install(t)

	n.assertServing(t)
	assert.Equal(t, strings.Fields(n.exec(t, "sha256sum", payloadDir+"/bin/nydus-snapshotter"))[0], strings.Fields(n.exec(t, "sha256sum", snapshotterBinary))[0])
	assert.Equal(t, n.config, n.exec(t, "cat", hostConfig)+"\n")
	assert.Equal(t, "3.0.0-e2e", n.exec(t, "readlink", nydusCurrent))
	assert.Contains(t, n.exec(t, nydusCurrent+"/nydus", "--version"), "3.0.0-e2e")
	assert.Equal(t, "700", n.exec(t, "stat", "--format", "%a", filepath.Dir(restartPending)))

	service := n.property(t, serviceUnit, "InvocationID")
	n.stop(t, installer)
	n.stop(t, n.install(t))
	assert.Equal(t, service, n.property(t, serviceUnit, "InvocationID"))

	env.Run(t, n.docker, "restart", n.name)
	n.waitBooted(t)
	if !assert.Eventually(t, func() bool {
		state, _ := n.tryExec("systemctl", "is-active", serviceUnit)
		return state == "active"
	}, bootTimeout, 200*time.Millisecond) {
		t.FailNow()
	}

	n.assertServing(t)
	assert.NotEqual(t, service, n.property(t, serviceUnit, "InvocationID"))
}

func TestInstallUpgrade(t *testing.T) {
	t.Parallel()
	n := newInstallNode(t)
	installer := n.install(t)
	service, socket := n.property(t, serviceUnit, "InvocationID"), n.property(t, socketUnit, "InvocationID")

	n.writeConfig(t, "log:\n  level: debug\n")
	assert.Eventually(t, func() bool {
		synced, _ := n.tryExec("cat", hostConfig)
		return synced+"\n" == n.config
	}, syncTimeout, 200*time.Millisecond)
	assert.Equal(t, serviceUnit, n.exec(t, "cat", restartPending))
	assert.Equal(t, service, n.property(t, serviceUnit, "InvocationID"))

	n.stop(t, installer)
	installer = n.install(t)
	restarted := n.property(t, serviceUnit, "InvocationID")
	assert.NotEqual(t, service, restarted)
	assert.Equal(t, socket, n.property(t, socketUnit, "InvocationID"))
	_, err := n.tryExec("test", "-e", restartPending)
	assert.Error(t, err)
	n.assertServing(t)

	n.stop(t, installer)
	starts := n.starts()
	n.write(t, payloadDir+"/systemd/"+socketUnit, shipped(t, "systemd", socketUnit)+"\n# changed\n", 0o644)
	installer = n.install(t)
	assert.NotEqual(t, socket, n.property(t, socketUnit, "InvocationID"))
	assert.NotEqual(t, restarted, n.property(t, serviceUnit, "InvocationID"))
	assert.Equal(t, starts+1, n.starts())
	n.assertServing(t)

	n.stop(t, installer)
	service = n.property(t, serviceUnit, "InvocationID")
	n.write(t, payloadDir+"/bin/nydus", nydusStub("3.0.1-e2e"), 0o755)
	installer = n.install(t)
	assert.Equal(t, "3.0.1-e2e", n.exec(t, "readlink", nydusCurrent))
	assert.Contains(t, n.exec(t, filepath.Dir(nydusCurrent)+"/3.0.0-e2e/nydus", "--version"), "3.0.0-e2e")
	assert.Equal(t, service, n.property(t, serviceUnit, "InvocationID"))

	n.stop(t, installer)
	n.stop(t, serviceUnit)
	n.install(t)
	n.assertServing(t)
}

func TestInstallKubeSecret(t *testing.T) {
	t.Parallel()
	n := newInstallNode(t)
	n.writeConfig(t, "auth:\n  kube_secret:\n    enable: true\n")
	n.write(t, tokenDir+"/token", "issued", 0o600)
	n.write(t, tokenDir+"/ca.crt", "ca", 0o644)
	installer := n.install(t, "KUBERNETES_SERVICE_HOST=10.96.0.1", "KUBERNETES_SERVICE_PORT=443")

	assert.Equal(t, "700", n.exec(t, "stat", "--format", "%a", kubernetesDir))
	assert.Equal(t, "600 644 600", strings.Join(strings.Fields(n.exec(t, "stat", "--format", "%a",
		kubernetesDir+"/token", kubernetesDir+"/ca.crt", kubernetesDir+"/kubeconfig")), " "))
	assert.Equal(t, "issued", n.exec(t, "cat", kubernetesDir+"/token"))
	kubeconfig := n.exec(t, "cat", kubernetesDir+"/kubeconfig")
	assert.Contains(t, kubeconfig, "server: https://10.96.0.1:443")
	assert.Contains(t, kubeconfig, "tokenFile: "+kubernetesDir+"/token")
	assert.Equal(t, "active", n.property(t, serviceUnit, "ActiveState"))

	n.write(t, tokenDir+"/token", "rotated", 0o600)
	assert.Eventually(t, func() bool {
		token, _ := n.tryExec("cat", kubernetesDir+"/token")
		return token == "rotated"
	}, syncTimeout, 200*time.Millisecond)

	n.stop(t, installer)
	n.exec(t, "ln", "--symbolic", "/", "/host")
	installedConfig := n.exec(t, "cat", hostConfig)
	n.writeConfig(t, "log:\n  level: loud\n")
	n.write(t, tokenDir+"/token", "rotated by a broken config", 0o600)
	installer = n.start(t, "KUBERNETES_SERVICE_HOST=10.96.0.1", "KUBERNETES_SERVICE_PORT=443")
	assert.Eventually(t, func() bool {
		return strings.Contains(n.journal(installer), "nydus-snapshotter failed")
	}, installTimeout, 200*time.Millisecond)
	assert.Contains(t, n.journal(installer), "invalid log.level")
	assert.Equal(t, "rotated by a broken config", n.exec(t, "cat", kubernetesDir+"/token"))
	assert.Equal(t, installedConfig, n.exec(t, "cat", hostConfig))
	assert.Equal(t, "active", n.property(t, serviceUnit, "ActiveState"))
}

func TestInstallNodeLabel(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	n := newInstallNode(t)
	node := c.kubectl(t, "get", "nodes", "--output", "jsonpath={.items[0].metadata.name}")
	if err := exec.Command(n.docker, "inspect", "--type", "container", node).Run(); err != nil {
		env.Skipf(t, "node %s is not a container the install node can join the network of", node)
	}

	network := strings.TrimSpace(env.Run(t, n.docker, "inspect", "--format", "{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{end}}", node))
	address := strings.TrimSpace(env.Run(t, n.docker, "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", node))
	env.Run(t, n.docker, "network", "connect", network, n.name)

	role := c.namespace + "-nodes"
	t.Cleanup(func() {
		for _, args := range [][]string{
			{"delete", "clusterrolebinding", role, "--ignore-not-found", "--wait=false"},
			{"delete", "clusterrole", role, "--ignore-not-found", "--wait=false"},
			{"label", "node", node, nodeLabel + "-"},
		} {
			_ = exec.Command("kubectl", append([]string{"--kubeconfig", c.admin}, args...)...).Run()
		}
	})
	c.kubectl(t, "create", "clusterrole", role, "--verb=get,list,patch", "--resource=nodes")
	c.kubectl(t, "create", "clusterrolebinding", role, "--clusterrole="+role, "--serviceaccount="+c.namespace+":nydus-snapshotter")
	token := strings.TrimSpace(c.kubectl(t, "--namespace", c.namespace, "create", "token", "nydus-snapshotter", "--duration=1h"))
	ca, err := base64.StdEncoding.DecodeString(c.kubectl(t, "config", "view", "--raw", "--minify", "--output", "jsonpath={.clusters[0].cluster.certificate-authority-data}"))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	n.write(t, tokenDir+"/token", token, 0o600)
	n.write(t, tokenDir+"/ca.crt", string(ca), 0o644)
	n.installer += nodeLabelConfig
	n.writeShippedConfig(t)
	labeled := func() bool {
		value, err := exec.Command("kubectl", "--kubeconfig", c.admin, "get", "node", node,
			"--output", `jsonpath={.metadata.labels.d7y\.io/nydus-snapshotter}`).Output()
		return err == nil && string(value) == "true"
	}

	unlabeled := func() bool { return !labeled() }
	loadSnapshotter := func(config string) {
		n.write(t, containerdConfig, config, 0o644)
		n.exec(t, "systemctl", "restart", "containerd")
	}

	installer := n.install(t, "NODE_NAME="+node, "KUBERNETES_SERVICE_HOST="+address, "KUBERNETES_SERVICE_PORT=6443")
	n.assertServing(t)
	assert.Never(t, labeled, 3*time.Second, 200*time.Millisecond)

	config := n.exec(t, "cat", containerdConfig)
	loadSnapshotter(config + "\n" + proxyPlugin)
	assert.Eventually(t, labeled, syncTimeout, 200*time.Millisecond)

	c.kubectl(t, "label", "node", node, nodeLabel+"-")
	assert.Eventually(t, labeled, syncTimeout, 200*time.Millisecond)

	loadSnapshotter(config + "\n")
	assert.Eventually(t, unlabeled, syncTimeout, 200*time.Millisecond)

	loadSnapshotter(config + "\n" + proxyPlugin)
	assert.Eventually(t, labeled, syncTimeout, 200*time.Millisecond)

	n.stop(t, installer)
	assert.Never(t, unlabeled, 3*time.Second, 200*time.Millisecond)
	assert.Equal(t, "active", n.property(t, serviceUnit, "ActiveState"))

	n.exec(t, "env", "KUBERNETES_SERVICE_HOST="+address, "KUBERNETES_SERVICE_PORT=6443",
		payloadDir+"/bin/nydus-snapshotter", "uninstall", "--config", payloadConfig)
	assert.False(t, labeled())
}
