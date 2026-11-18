package snapshotter

import (
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/stretchr/testify/assert"
)

func TestKubeSecretRotation(t *testing.T) {
	t.Parallel()
	c := newCluster(t)
	origin := registry.Start(t)
	auth := startBasicAuth(t, origin, "nydus", "first")
	img := newImage(t, origin, "snapshotter/kube-secret").on(auth.host)
	c.applySecret(t, auth.host, "nydus", "first")
	n := newNode(t, withKubeSecret(c.kubeconfig, c.selector))
	n.user, n.password = "nydus", "first"
	if !assert.Eventually(t, func() bool {
		status, _, err := n.get("/readyz")
		return err == nil && status == http.StatusOK
	}, startTimeout, 100*time.Millisecond) {
		t.FailNow()
	}

	pulled := n.pull(t, img.nydus, withPrefetch("none"))
	started := n.start(t, pulled)
	assert.Equal(t, img.files["/id"], started.sha256sum(t, "/id")["/id"])
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("nydus:first")), n.renderedConfig(t, pulled).Backend.Config.Auth)

	gets := origin.Faults.BlobGets()
	auth.rotate("nydus", "second")
	c.applySecret(t, auth.host, "nydus", "second")
	if !assert.Eventually(t, func() bool {
		_, metrics, err := n.get("/metrics")
		return err == nil && strings.Contains(metrics, `nydus_snapshotter_auth_updates_total{result="success"} 1`)
	}, startTimeout, 200*time.Millisecond) {
		t.FailNow()
	}

	assertFiles(t, started, img)
	assert.Greater(t, origin.Faults.BlobGets(), gets)
}

type cluster struct {
	admin, kubeconfig   string
	namespace, selector string
}

func newCluster(t *testing.T) *cluster {
	t.Helper()
	admin := os.Getenv("NYDUS_E2E_KUBECONFIG")
	if admin == "" {
		env.Skipf(t, "NYDUS_E2E_KUBECONFIG is not set")
	}

	env.LookPath(t, "kubectl")
	id := fmt.Sprintf("nydus-e2e-%08x", rand.Uint32())
	c := &cluster{admin: admin, kubeconfig: filepath.Join(t.TempDir(), "kubeconfig"), namespace: id, selector: "nydus-e2e=" + id}
	t.Cleanup(func() {
		for _, resource := range []string{"namespace", "clusterrolebinding", "clusterrole"} {
			_ = exec.Command("kubectl", "--kubeconfig", admin, "delete", resource, id, "--ignore-not-found", "--wait=false").Run()
		}
	})

	account := "nydus-snapshotter"
	c.kubectl(t, "create", "namespace", id)
	c.kubectl(t, "--namespace", id, "create", "serviceaccount", account)
	c.kubectl(t, "create", "clusterrole", id, "--verb=list,watch", "--resource=secrets")
	c.kubectl(t, "create", "clusterrolebinding", id, "--clusterrole="+id, "--serviceaccount="+id+":"+account)
	token := strings.TrimSpace(c.kubectl(t, "--namespace", id, "create", "token", account, "--duration=1h"))
	server := c.kubectl(t, "config", "view", "--raw", "--minify", "--output", "jsonpath={.clusters[0].cluster.server}")
	ca := c.kubectl(t, "config", "view", "--raw", "--minify", "--output", "jsonpath={.clusters[0].cluster.certificate-authority-data}")
	kubeconfig := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: e2e
  cluster:
    server: %s
    certificate-authority-data: %s
users:
- name: %s
  user:
    token: %s
contexts:
- name: e2e
  context:
    cluster: e2e
    user: %s
current-context: e2e
`, server, ca, account, token, account)
	if !assert.NoError(t, os.WriteFile(c.kubeconfig, []byte(kubeconfig), 0o600)) {
		t.FailNow()
	}

	return c
}

func (c *cluster) kubectl(t *testing.T, args ...string) string {
	t.Helper()
	return env.Run(t, "kubectl", append([]string{"--kubeconfig", c.admin}, args...)...)
}

func (c *cluster) applySecret(t *testing.T, host, user, password string) {
	t.Helper()
	auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: registry
  namespace: %s
  labels:
    nydus-e2e: %s
type: kubernetes.io/dockerconfigjson
stringData:
  .dockerconfigjson: '{"auths":{%q:{"auth":%q}}}'
`, c.namespace, c.namespace, host, auth)
	cmd := env.Command(t, "kubectl", "--kubeconfig", c.admin, "apply", "--filename", "-")
	cmd.Stdin = strings.NewReader(manifest)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("kubectl apply: %v\n%s", err, out)
	}
}
