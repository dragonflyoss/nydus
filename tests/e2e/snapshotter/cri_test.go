package snapshotter

import (
	"context"
	"maps"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const criNamespace = "k8s.io"

func TestCRI(t *testing.T) {
	t.Parallel()
	reg := registry.Start(t)
	n := newNode(t, withCRI(pushPause(t, reg)))
	img := newImage(t, reg, "snapshotter/cri")
	cri := n.cri(t)
	pod, sandbox := cri.runPod(t, n)
	cri.pull(t, img.nydus, sandbox)
	k8s := n.in(criNamespace)
	pulled, err := k8s.client.GetImage(k8s.ctx, img.nydus)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	manifest, err := images.Manifest(k8s.ctx, k8s.client.ContentStore(), pulled.Target(), pulled.Platform())
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	blobs := 0
	for _, layer := range manifest.Layers {
		if layer.Annotations[labelNydusBlob] != "true" {
			continue
		}

		blobs++
		assert.Zero(t, reg.Faults.Count(func(r registry.Request) bool {
			return r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/blobs/"+layer.Digest.String())
		}))
	}

	assert.Equal(t, 3, blobs)
	id := cri.start(t, pod, sandbox, img.nydus)
	assert.Equal(t, img.files, cri.sha256sum(t, id, slices.Collect(maps.Keys(img.files))...))
	unit := k8s.unit(t, pulled)
	n.assertRunning(t, unit)
	assert.Equal(t, []string{unit}, n.units(t))
	fs, err := cri.images.ImageFsInfo(cri.ctx, &runtimeapi.ImageFsInfoRequest{})
	if assert.NoError(t, err) && assert.NotEmpty(t, fs.GetImageFilesystems()) {
		assert.Equal(t, n.root, fs.GetImageFilesystems()[0].GetFsId().GetMountpoint())
	}

	cri.removePod(t, pod)
	waitStopped(t, unit, gcTimeout)
	assert.Empty(t, n.units(t))
}

type criClient struct {
	runtime runtimeapi.RuntimeServiceClient
	images  runtimeapi.ImageServiceClient
	ctx     context.Context
}

func (n *node) cri(t *testing.T) *criClient {
	t.Helper()
	conn, err := grpc.NewClient("unix://"+n.address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(func() {
		cancel()
		_ = conn.Close()
	})

	return &criClient{
		runtime: runtimeapi.NewRuntimeServiceClient(conn),
		images:  runtimeapi.NewImageServiceClient(conn),
		ctx:     ctx,
	}
}

func (c *criClient) runPod(t *testing.T, n *node) (string, *runtimeapi.PodSandboxConfig) {
	t.Helper()
	sandbox := &runtimeapi.PodSandboxConfig{
		Metadata:     &runtimeapi.PodSandboxMetadata{Name: "nydus-e2e", Namespace: "default", Uid: n.namespace},
		LogDirectory: filepath.Join(n.dir, "pods"),
		Linux: &runtimeapi.LinuxPodSandboxConfig{
			CgroupParent: "/" + n.namespace,
			SecurityContext: &runtimeapi.LinuxSandboxSecurityContext{
				NamespaceOptions: &runtimeapi.NamespaceOption{Network: runtimeapi.NamespaceMode_NODE},
			},
		},
	}
	resp, err := c.runtime.RunPodSandbox(c.ctx, &runtimeapi.RunPodSandboxRequest{Config: sandbox})
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	t.Cleanup(func() { c.removePod(t, resp.GetPodSandboxId()) })
	return resp.GetPodSandboxId(), sandbox
}

func (c *criClient) removePod(t *testing.T, pod string) {
	t.Helper()
	_, err := c.runtime.StopPodSandbox(c.ctx, &runtimeapi.StopPodSandboxRequest{PodSandboxId: pod})
	assert.NoError(t, err)
	_, err = c.runtime.RemovePodSandbox(c.ctx, &runtimeapi.RemovePodSandboxRequest{PodSandboxId: pod})
	assert.NoError(t, err)
}

func (c *criClient) pull(t *testing.T, ref string, sandbox *runtimeapi.PodSandboxConfig) {
	t.Helper()
	_, err := c.images.PullImage(c.ctx, &runtimeapi.PullImageRequest{
		Image:         &runtimeapi.ImageSpec{Image: ref},
		SandboxConfig: sandbox,
	})
	if !assert.NoError(t, err) {
		t.FailNow()
	}
}

func (c *criClient) start(t *testing.T, pod string, sandbox *runtimeapi.PodSandboxConfig, ref string) string {
	t.Helper()
	created, err := c.runtime.CreateContainer(c.ctx, &runtimeapi.CreateContainerRequest{
		PodSandboxId: pod,
		Config: &runtimeapi.ContainerConfig{
			Metadata: &runtimeapi.ContainerMetadata{Name: "nydus"},
			Image:    &runtimeapi.ImageSpec{Image: ref},
			Command:  []string{busybox, "sleep", "3600"},
			LogPath:  "nydus.log",
			Linux: &runtimeapi.LinuxContainerConfig{
				SecurityContext: &runtimeapi.LinuxContainerSecurityContext{
					Apparmor: &runtimeapi.SecurityProfile{ProfileType: runtimeapi.SecurityProfile_Unconfined},
				},
			},
		},
		SandboxConfig: sandbox,
	})
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	_, err = c.runtime.StartContainer(c.ctx, &runtimeapi.StartContainerRequest{ContainerId: created.GetContainerId()})
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return created.GetContainerId()
}

func (c *criClient) sha256sum(t *testing.T, id string, paths ...string) map[string]string {
	t.Helper()
	resp, err := c.runtime.ExecSync(c.ctx, &runtimeapi.ExecSyncRequest{
		ContainerId: id,
		Cmd:         append([]string{busybox, "sha256sum"}, paths...),
		Timeout:     60,
	})
	if !assert.NoError(t, err) || !assert.Zero(t, resp.GetExitCode()) {
		t.FailNow()
	}

	return sha256sums(t, string(resp.GetStdout()))
}

func pushPause(t *testing.T, reg *registry.Registry) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "busybox")
	copyFile(t, staticBusybox(t), filepath.Join(bin, "bin", "busybox"), 0o755)
	ref := reg.Ref("snapshotter/pause", "latest")
	img, err := mutate.Config(reg.PushDirs(t, ref, bin), v1.Config{Entrypoint: []string{busybox, "sleep", "86400"}})
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	parsed, err := name.ParseReference(ref, name.Insecure)
	if !assert.NoError(t, err) || !assert.NoError(t, remote.Write(parsed, img)) {
		t.FailNow()
	}

	return ref
}
