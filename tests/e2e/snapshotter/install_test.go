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
	installerRoot               = "/opt/nydus-installer"
	tokenDir                    = installerRoot + "/var/run/secrets/kubernetes.io/serviceaccount"
	installerConfig             = "\ninstaller:\n  sync_interval: 1s\n"
	nodeLabelConfig             = "  node_label:\n    enable: true\n"
	nydusSnapshotterBinary      = "/usr/local/bin/nydus-snapshotter"
	nydusBinary                 = "/usr/local/bin/nydus"
	hostUnitDir                 = "/etc/systemd/system"
	nydusLink                   = "/opt/nydus-snapshotter/bin/current/nydus"
	nydusBinaryVersionsDir      = "/opt/nydus-snapshotter/versions"
	hostConfig                  = "/etc/nydus-snapshotter/config.yaml"
	kubernetesDir               = "/run/nydus-snapshotter/kubernetes"
	restartRequiredFile         = "/run/nydus-snapshotter/restart-required"
	nydusSnapshotterServiceUnit = "nydus-snapshotter-v3.service"
	metricsURL                  = "http://127.0.0.1:4010/metrics"
	nodeLabel                   = "d7y.io/nydus-snapshotter"
	containerdConfig            = "/etc/containerd/config.toml"
	proxyPlugin                 = "\n[proxy_plugins.nydus]\n  type = \"snapshot\"\n  address = \"/run/nydus-snapshotter/nydus-snapshotter.sock\"\n"
	installed                   = "installed, keeping the config and the credentials in sync"
	bootTimeout                 = time.Minute
	installTimeout              = time.Minute
	syncTimeout                 = 30 * time.Second
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
				"--unit", nydusSnapshotterServiceUnit, "--unit", "nydus-installer-*").CombinedOutput()
			t.Logf("journal of %s:\n%s", n.name, out)
		}

		_ = exec.Command(n.docker, "rm", "--force", "--volumes", n.name).Run()
	})

	n.waitBooted(t)
	snapshotter, err := os.ReadFile(env.Snapshotter(t))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	// The installer runs in a root of its own laid out as its image, with
	// the node's root at /host as in the DaemonSet. The stub of nydus is a
	// shell script, so the root borrows the node's shell and libraries.
	n.exec(t, "mkdir", "-p", installerRoot+filepath.Dir(nydusSnapshotterBinary), installerRoot+hostUnitDir,
		installerRoot+filepath.Dir(hostConfig), tokenDir, installerRoot+"/host",
		installerRoot+"/usr/bin", installerRoot+"/usr/lib", installerRoot+"/usr/lib64")
	for _, dir := range []string{"bin", "lib", "lib64"} {
		n.exec(t, "ln", "-s", "usr/"+dir, installerRoot+"/"+dir)
	}

	n.write(t, installerRoot+nydusSnapshotterBinary, string(snapshotter), 0o755)
	n.write(t, installerRoot+nydusBinary, nydusStub("3.0.0-e2e"), 0o755)
	n.write(t, installerRoot+hostUnitDir+"/"+nydusSnapshotterServiceUnit, shipped(t, "systemd", nydusSnapshotterServiceUnit), 0o644)

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
	n.write(t, installerRoot+hostConfig, n.config, 0o644)
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
	args := []string{
		"systemd-run", "--unit", unit, "--collect",
		"--property", "RootDirectory=" + installerRoot,
		"--property", "MountAPIVFS=yes",
		"--property", "BindPaths=/:/host /run/systemd -/run/dbus",
		"--property", "BindReadOnlyPaths=/usr/bin /usr/lib -/usr/lib64",
	}
	for _, variable := range environment {
		args = append(args, "--setenv", variable)
	}

	n.exec(t, append(args, nydusSnapshotterBinary, "install")...)

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
	assert.Equal(t, "active", n.property(t, nydusSnapshotterServiceUnit, "ActiveState"))
	assert.Equal(t, "enabled", n.property(t, nydusSnapshotterServiceUnit, "UnitFileState"))

	assert.Contains(t, n.exec(t, "curl", "--fail", "--silent", metricsURL), "nydus_snapshotter_running_daemons")
}

func TestInstall(t *testing.T) {
	t.Parallel()
	n := newInstallNode(t)
	installer := n.install(t)

	n.assertServing(t)
	assert.Equal(t, strings.Fields(n.exec(t, "sha256sum", installerRoot+nydusSnapshotterBinary))[0], strings.Fields(n.exec(t, "sha256sum", nydusSnapshotterBinary))[0])
	assert.Equal(t, n.config, n.exec(t, "cat", hostConfig)+"\n")
	assert.Equal(t, nydusBinaryVersionsDir+"/3.0.0-e2e/nydus", n.exec(t, "readlink", nydusLink))
	assert.Contains(t, n.exec(t, nydusLink, "--version"), "3.0.0-e2e")
	assert.Equal(t, "700", n.exec(t, "stat", "--format", "%a", filepath.Dir(restartRequiredFile)))

	service := n.property(t, nydusSnapshotterServiceUnit, "InvocationID")
	n.stop(t, installer)
	n.stop(t, n.install(t))
	assert.Equal(t, service, n.property(t, nydusSnapshotterServiceUnit, "InvocationID"))

	env.Run(t, n.docker, "restart", n.name)
	n.waitBooted(t)
	if !assert.Eventually(t, func() bool {
		state, _ := n.tryExec("systemctl", "is-active", nydusSnapshotterServiceUnit)
		return state == "active"
	}, bootTimeout, 200*time.Millisecond) {
		t.FailNow()
	}

	n.assertServing(t)
	assert.NotEqual(t, service, n.property(t, nydusSnapshotterServiceUnit, "InvocationID"))
}

func TestInstallUpgrade(t *testing.T) {
	t.Parallel()
	n := newInstallNode(t)
	installer := n.install(t)
	service := n.property(t, nydusSnapshotterServiceUnit, "InvocationID")

	n.writeConfig(t, "log:\n  level: debug\n")
	assert.Eventually(t, func() bool {
		synced, _ := n.tryExec("cat", hostConfig)
		return synced+"\n" == n.config
	}, syncTimeout, 200*time.Millisecond)
	n.exec(t, "test", "-e", restartRequiredFile)
	assert.Equal(t, service, n.property(t, nydusSnapshotterServiceUnit, "InvocationID"))

	n.stop(t, installer)
	installer = n.install(t)
	assert.NotEqual(t, service, n.property(t, nydusSnapshotterServiceUnit, "InvocationID"))
	_, err := n.tryExec("test", "-e", restartRequiredFile)
	assert.Error(t, err)
	n.assertServing(t)

	n.stop(t, installer)
	service = n.property(t, nydusSnapshotterServiceUnit, "InvocationID")
	n.write(t, installerRoot+nydusBinary, nydusStub("3.0.1-e2e"), 0o755)
	installer = n.install(t)
	assert.Equal(t, nydusBinaryVersionsDir+"/3.0.1-e2e/nydus", n.exec(t, "readlink", nydusLink))
	assert.Contains(t, n.exec(t, nydusBinaryVersionsDir+"/3.0.0-e2e/nydus", "--version"), "3.0.0-e2e")
	assert.Equal(t, service, n.property(t, nydusSnapshotterServiceUnit, "InvocationID"))

	n.stop(t, installer)
	n.stop(t, nydusSnapshotterServiceUnit)
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
	assert.Equal(t, "active", n.property(t, nydusSnapshotterServiceUnit, "ActiveState"))

	n.write(t, tokenDir+"/token", "rotated", 0o600)
	assert.Eventually(t, func() bool {
		token, _ := n.tryExec("cat", kubernetesDir+"/token")
		return token == "rotated"
	}, syncTimeout, 200*time.Millisecond)

	n.stop(t, installer)
	installedConfig := n.exec(t, "cat", hostConfig)
	n.writeConfig(t, "log:\n  level: loud\n")
	n.write(t, tokenDir+"/token", "issued after a broken config", 0o600)
	installer = n.start(t, "KUBERNETES_SERVICE_HOST=10.96.0.1", "KUBERNETES_SERVICE_PORT=443")
	assert.Eventually(t, func() bool {
		return strings.Contains(n.journal(installer), "nydus-snapshotter failed")
	}, installTimeout, 200*time.Millisecond)
	assert.Contains(t, n.journal(installer), "invalid log.level")
	assert.Equal(t, "rotated", n.exec(t, "cat", kubernetesDir+"/token"))
	assert.Equal(t, installedConfig, n.exec(t, "cat", hostConfig))
	assert.Equal(t, "active", n.property(t, nydusSnapshotterServiceUnit, "ActiveState"))
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
	assert.Equal(t, "active", n.property(t, nydusSnapshotterServiceUnit, "ActiveState"))

	n.exec(t, "env", "KUBERNETES_SERVICE_HOST="+address, "KUBERNETES_SERVICE_PORT=6443",
		"chroot", installerRoot, nydusSnapshotterBinary, "uninstall")
	assert.False(t, labeled())
}
