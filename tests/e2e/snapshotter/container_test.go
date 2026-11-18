package snapshotter

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/containerd/containerd/api/types/runc/options"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/containerd/v2/plugins"
	"github.com/containerd/errdefs"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
)

const busybox = "/bin/busybox"

type container struct {
	containerd.Container
	task containerd.Task
	ctx  context.Context
}

func (n *node) start(t *testing.T, img containerd.Image) *container {
	t.Helper()
	c, err := n.tryStart(img)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return c
}

func (n *node) startInUserNamespace(t *testing.T, img containerd.Image, root specs.LinuxIDMapping) *container {
	t.Helper()
	c, err := n.tryStart(img, root)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return c
}

func (n *node) tryStart(img containerd.Image, userNamespace ...specs.LinuxIDMapping) (*container, error) {
	ctx, cancel := context.WithTimeout(n.ctx, startTimeout)
	defer cancel()
	var snapshotOpts []snapshots.Opt
	specOpts := []oci.SpecOpts{oci.WithImageConfig(img), oci.WithProcessArgs(busybox, "sleep", "3600")}
	for _, root := range userNamespace {
		snapshotOpts = append(snapshotOpts, containerd.WithRemapperLabels(root.ContainerID, root.HostID, root.ContainerID, root.HostID, root.Size))
		specOpts = append(specOpts, oci.WithUserNamespace(userNamespace, userNamespace))
	}

	id := fmt.Sprintf("c%08x", rand.Uint32())
	ctr, err := n.client.NewContainer(ctx, id,
		containerd.WithImage(img),
		containerd.WithSnapshotter(plugin),
		containerd.WithNewSnapshot(id, img, snapshotOpts...),
		containerd.WithRuntime(plugins.RuntimeRuncV2, &options.Options{BinaryName: n.runcBin}),
		containerd.WithNewSpec(specOpts...),
	)
	if err != nil {
		return nil, err
	}

	c := &container{Container: ctr, ctx: n.ctx}
	if c.task, err = ctr.NewTask(ctx, cio.NullIO); err != nil {
		return nil, err
	}

	return c, c.task.Start(ctx)
}

func TestUserNamespace(t *testing.T) {
	t.Parallel()
	n := newNode(t)
	img := newImage(t, registry.Start(t), "snapshotter/user-namespace")
	pulled := n.pull(t, img.nydus)
	c := n.startInUserNamespace(t, pulled, specs.LinuxIDMapping{ContainerID: 0, HostID: 100000, Size: 100000})

	assertFiles(t, c, img)
	n.assertRunning(t, n.unit(t, pulled))
	mapping, err := c.exec(busybox, "cat", "/proc/self/uid_map")
	assert.NoError(t, err)
	assert.Equal(t, []string{"0", "100000", "100000"}, strings.Fields(mapping))
	owners, err := c.exec(busybox, "stat", "-c", "%u:%g", "/", busybox, "/id")
	assert.NoError(t, err)
	assert.Equal(t, []string{"0:0", "0:0", "0:0"}, strings.Fields(owners))
	_, err = c.exec(busybox, "touch", "/written")
	assert.NoError(t, err)
}

func (n *node) removeContainers(t *testing.T) {
	ctx, cancel := context.WithTimeout(n.ctx, time.Minute)
	defer cancel()
	containers, err := n.client.Containers(ctx)
	if !assert.NoError(t, err) {
		return
	}

	for _, c := range containers {
		assert.NoError(t, removeContainer(ctx, c))
	}
}

func removeContainer(ctx context.Context, c containerd.Container) error {
	if task, err := c.Task(ctx, nil); err == nil {
		if _, err := task.Delete(ctx, containerd.WithProcessKill); err != nil && !errdefs.IsNotFound(err) {
			return err
		}
	}

	if err := c.Delete(ctx, containerd.WithSnapshotCleanup); err != nil && !errdefs.IsNotFound(err) {
		return err
	}

	return nil
}

func (c *container) remove(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(c.ctx, time.Minute)
	defer cancel()
	assert.NoError(t, removeContainer(ctx, c.Container))
}

func (c *container) sha256sum(t *testing.T, paths ...string) map[string]string {
	t.Helper()
	out, err := c.exec(append([]string{busybox, "sha256sum"}, paths...)...)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return sha256sums(t, out)
}

func sha256sums(t *testing.T, out string) map[string]string {
	t.Helper()
	sums := map[string]string{}
	for line := range strings.Lines(strings.TrimSpace(out)) {
		sum, path, ok := strings.Cut(strings.TrimSpace(line), "  ")
		if !assert.True(t, ok) {
			t.FailNow()
		}

		sums[path] = sum
	}

	return sums
}

func (c *container) exec(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(c.ctx, time.Minute)
	defer cancel()
	spec, err := c.Spec(ctx)
	if err != nil {
		return "", err
	}

	process := *spec.Process
	process.Args = args
	var stdout, stderr bytes.Buffer
	p, err := c.task.Exec(ctx, fmt.Sprintf("exec%08x", rand.Uint32()), &process, cio.NewCreator(cio.WithStreams(nil, &stdout, &stderr)))
	if err != nil {
		return "", err
	}

	exited, err := p.Wait(ctx)
	if err == nil {
		err = p.Start(ctx)
	}

	if err != nil {
		_, _ = p.Delete(ctx)
		return "", err
	}

	var status containerd.ExitStatus
	select {
	case status = <-exited:
	case <-ctx.Done():
		_ = p.Kill(context.WithoutCancel(ctx), syscall.SIGKILL)
		return "", fmt.Errorf("%v: %w", args, ctx.Err())
	}

	if _, err := p.Delete(ctx); err != nil {
		return "", err
	}

	if code := status.ExitCode(); code != 0 {
		return stdout.String(), fmt.Errorf("%v exited with %d: %s", args, code, stderr.String())
	}

	return stdout.String(), nil
}
