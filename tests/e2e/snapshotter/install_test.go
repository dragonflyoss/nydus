package snapshotter

import (
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
	tokenDir          = "/opt/nydus-snapshotter/token"
	snapshotterBinary = "/usr/local/bin/nydus-snapshotter"
	nydusCurrent      = "/opt/nydus-snapshotter/bin/current"
	hostConfig        = "/etc/nydus-snapshotter/config.yaml"
	kubernetesDir     = "/run/nydus-snapshotter/kubernetes"
	restartPending    = "/run/nydus-snapshotter/restart-pending"
	serviceUnit       = "nydus-snapshotter.service"
	socketUnit        = "nydus-snapshotter.socket"
	metricsURL        = "http://127.0.0.1:4010/metrics"
	installed         = "installed, keeping the config and the credentials in sync"
	bootTimeout       = time.Minute
	installTimeout    = time.Minute
	syncTimeout       = 30 * time.Second
)

type installNode struct {
	docker     string
	name       string
	dir        string
	installers int
}

func newInstallNode(t *testing.T) *installNode {
	t.Helper()
	image := os.Getenv("NYDUS_E2E_NODE_IMAGE")
	if image == "" {
		env.Skipf(t, "NYDUS_E2E_NODE_IMAGE is not set")
	}

	n := &installNode{
		docker: env.LookPath(t, "docker"),
		name:   fmt.Sprintf("nydus-e2e-install-%08x", rand.Uint32()),
		dir:    t.TempDir(),
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

	n.write(t, payloadDir+"/config/config.yaml", shipped(t, "nydus-snapshotter", "config.yaml"), 0o644)

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

func (n *installNode) install(t *testing.T, environment ...string) string {
	t.Helper()
	n.installers++
	unit := fmt.Sprintf("nydus-installer-%d.service", n.installers)
	args := []string{"systemd-run", "--unit", unit, "--collect"}
	for _, variable := range environment {
		args = append(args, "--setenv", variable)
	}

	n.exec(t, append(args, payloadDir+"/bin/nydus-snapshotter", "install",
		"--host-root", "/", "--payload-dir", payloadDir, "--token-dir", tokenDir, "--sync-interval", "1s")...)
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
	assert.Equal(t, shipped(t, "nydus-snapshotter", "config.yaml"), n.exec(t, "cat", hostConfig)+"\n")
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

	config := "log:\n  level: debug\n"
	n.write(t, payloadDir+"/config/config.yaml", config, 0o644)
	assert.Eventually(t, func() bool {
		synced, _ := n.tryExec("cat", hostConfig)
		return synced+"\n" == config
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
	n.write(t, payloadDir+"/config/config.yaml", "auth:\n  kube_secret:\n    enable: true\n", 0o644)
	n.write(t, tokenDir+"/token", "issued", 0o600)
	n.write(t, tokenDir+"/ca.crt", "ca", 0o644)
	n.install(t, "KUBERNETES_SERVICE_HOST=10.96.0.1", "KUBERNETES_SERVICE_PORT=443")

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
}
