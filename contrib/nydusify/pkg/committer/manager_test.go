package committer

import (
	"context"
	"encoding/json"
	"errors"
	"syscall"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	typesapi "github.com/containerd/containerd/api/types"
	containerdclient "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/cio"
	containerdoci "github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/platforms"
	typeurl "github.com/containerd/typeurl/v2"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
)

type mockImage struct {
	name string
}

func (m *mockImage) Name() string                                                        { return m.name }
func (m *mockImage) Target() ocispec.Descriptor                                          { return ocispec.Descriptor{} }
func (m *mockImage) Labels() map[string]string                                           { return nil }
func (m *mockImage) Unpack(context.Context, string, ...containerdclient.UnpackOpt) error { return nil }
func (m *mockImage) RootFS(context.Context) ([]digest.Digest, error)                     { return nil, nil }
func (m *mockImage) Size(context.Context) (int64, error)                                 { return 0, nil }
func (m *mockImage) Usage(context.Context, ...containerdclient.UsageOpt) (int64, error) {
	return 0, nil
}
func (m *mockImage) Config(context.Context) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{}, nil
}
func (m *mockImage) IsUnpacked(context.Context, string) (bool, error) { return false, nil }
func (m *mockImage) ContentStore() content.Store                      { return nil }
func (m *mockImage) Metadata() images.Image                           { return images.Image{} }
func (m *mockImage) Platform() platforms.MatchComparer                { return nil }
func (m *mockImage) Spec(context.Context) (ocispec.Image, error)      { return ocispec.Image{}, nil }

type mockTask struct {
	pid       uint32
	pauseErr  error
	resumeErr error
}

func (m *mockTask) ID() string                  { return "task" }
func (m *mockTask) Pid() uint32                 { return m.pid }
func (m *mockTask) Start(context.Context) error { return nil }
func (m *mockTask) Delete(context.Context, ...containerdclient.ProcessDeleteOpts) (*containerdclient.ExitStatus, error) {
	return nil, nil
}
func (m *mockTask) Kill(context.Context, syscall.Signal, ...containerdclient.KillOpts) error {
	return nil
}
func (m *mockTask) Wait(context.Context) (<-chan containerdclient.ExitStatus, error) { return nil, nil }
func (m *mockTask) CloseIO(context.Context, ...containerdclient.IOCloserOpts) error  { return nil }
func (m *mockTask) Resize(context.Context, uint32, uint32) error                     { return nil }
func (m *mockTask) IO() cio.IO                                                       { return nil }
func (m *mockTask) Status(context.Context) (containerdclient.Status, error) {
	var status containerdclient.Status
	return status, nil
}
func (m *mockTask) Pause(context.Context) error  { return m.pauseErr }
func (m *mockTask) Resume(context.Context) error { return m.resumeErr }
func (m *mockTask) Exec(context.Context, string, *runtimespec.Process, cio.Creator) (containerdclient.Process, error) {
	return nil, nil
}
func (m *mockTask) Pids(context.Context) ([]containerdclient.ProcessInfo, error) { return nil, nil }
func (m *mockTask) Checkpoint(context.Context, ...containerdclient.CheckpointTaskOpts) (containerdclient.Image, error) {
	return nil, nil
}
func (m *mockTask) Update(context.Context, ...containerdclient.UpdateTaskOpts) error { return nil }
func (m *mockTask) LoadProcess(context.Context, string, cio.Attach) (containerdclient.Process, error) {
	return nil, nil
}
func (m *mockTask) Metrics(context.Context) (*typesapi.Metric, error) { return nil, nil }
func (m *mockTask) Spec(context.Context) (*containerdoci.Spec, error) { return nil, nil }

type mockContainer struct {
	id      string
	task    containerdclient.Task
	taskErr error
	image   containerdclient.Image
	imgErr  error
	info    containers.Container
	infoErr error
}

func (m *mockContainer) ID() string { return m.id }
func (m *mockContainer) Info(context.Context, ...containerdclient.InfoOpts) (containers.Container, error) {
	return m.info, m.infoErr
}
func (m *mockContainer) Delete(context.Context, ...containerdclient.DeleteOpts) error { return nil }
func (m *mockContainer) NewTask(context.Context, cio.Creator, ...containerdclient.NewTaskOpts) (containerdclient.Task, error) {
	return m.task, m.taskErr
}
func (m *mockContainer) Spec(context.Context) (*runtimespec.Spec, error) { return nil, nil }
func (m *mockContainer) Task(context.Context, cio.Attach) (containerdclient.Task, error) {
	return m.task, m.taskErr
}
func (m *mockContainer) Image(context.Context) (containerdclient.Image, error) {
	return m.image, m.imgErr
}
func (m *mockContainer) Labels(context.Context) (map[string]string, error) { return nil, nil }
func (m *mockContainer) SetLabels(context.Context, map[string]string) (map[string]string, error) {
	return nil, nil
}
func (m *mockContainer) Extensions(context.Context) (map[string]typeurl.Any, error) { return nil, nil }
func (m *mockContainer) Update(context.Context, ...containerdclient.UpdateContainerOpts) error {
	return nil
}
func (m *mockContainer) Checkpoint(context.Context, string, ...containerdclient.CheckpointOpts) (containerdclient.Image, error) {
	return nil, nil
}
func (m *mockContainer) Restore(context.Context, cio.Creator, string) (int, error) { return 0, nil }

type mockSnapshotter struct {
	mounts []mount.Mount
	err    error
}

func (m *mockSnapshotter) Stat(context.Context, string) (snapshots.Info, error) {
	return snapshots.Info{}, nil
}
func (m *mockSnapshotter) Update(context.Context, snapshots.Info, ...string) (snapshots.Info, error) {
	return snapshots.Info{}, nil
}
func (m *mockSnapshotter) Usage(context.Context, string) (snapshots.Usage, error) {
	return snapshots.Usage{}, nil
}
func (m *mockSnapshotter) Mounts(context.Context, string) ([]mount.Mount, error) {
	return m.mounts, m.err
}
func (m *mockSnapshotter) Prepare(context.Context, string, string, ...snapshots.Opt) ([]mount.Mount, error) {
	return nil, nil
}
func (m *mockSnapshotter) View(context.Context, string, string, ...snapshots.Opt) ([]mount.Mount, error) {
	return nil, nil
}
func (m *mockSnapshotter) Commit(context.Context, string, string, ...snapshots.Opt) error { return nil }
func (m *mockSnapshotter) Remove(context.Context, string) error                           { return nil }
func (m *mockSnapshotter) Walk(context.Context, snapshots.WalkFunc, ...string) error      { return nil }
func (m *mockSnapshotter) Close() error                                                   { return nil }

func patchClientNewSeq(outputs []gomonkey.OutputCell) *gomonkey.Patches {
	return gomonkey.ApplyFuncSeq(containerdclient.New, outputs)
}

func patchLoadContainerSeq(client *containerdclient.Client, outputs []gomonkey.OutputCell) *gomonkey.Patches {
	return gomonkey.ApplyMethodSeq(client, "LoadContainer", outputs)
}

func patchSnapshotService(client *containerdclient.Client, snapshotter snapshots.Snapshotter) *gomonkey.Patches {
	return gomonkey.ApplyMethod(
		client,
		"SnapshotService",
		func(*containerdclient.Client, string) snapshots.Snapshotter {
			return snapshotter
		},
	)
}

func TestNewManager(t *testing.T) {
	mgr, err := NewManager("/run/containerd/containerd.sock")
	require.NoError(t, err)
	require.Equal(t, "/run/containerd/containerd.sock", mgr.address)
}

func TestManagerErrorPaths(t *testing.T) {
	specBytes, err := json.Marshal(runtimespec.Spec{Mounts: []runtimespec.Mount{{Destination: "/dst", Source: "/src"}}})
	require.NoError(t, err)

	client := &containerdclient.Client{}
	patches := patchClientNewSeq([]gomonkey.OutputCell{
		{Values: []interface{}{(*containerdclient.Client)(nil), errors.New("new client failed")}, Times: 1},
		{Values: []interface{}{client, nil}, Times: 3},
		{Values: []interface{}{(*containerdclient.Client)(nil), errors.New("new client failed")}, Times: 1},
		{Values: []interface{}{client, nil}, Times: 3},
		{Values: []interface{}{(*containerdclient.Client)(nil), errors.New("new client failed")}, Times: 1},
		{Values: []interface{}{client, nil}, Times: 6},
	})
	defer patches.Reset()

	loadPatches := patchLoadContainerSeq(client, []gomonkey.OutputCell{
		{Values: []interface{}{containerdclient.Container(nil), errors.New("load failed")}, Times: 1},
		{Values: []interface{}{&mockContainer{taskErr: errors.New("task failed")}, nil}, Times: 1},
		{Values: []interface{}{&mockContainer{task: &mockTask{pauseErr: errors.New("pause failed")}}, nil}, Times: 1},
		{Values: []interface{}{containerdclient.Container(nil), errors.New("load failed")}, Times: 1},
		{Values: []interface{}{&mockContainer{taskErr: errors.New("task failed")}, nil}, Times: 1},
		{Values: []interface{}{&mockContainer{task: &mockTask{resumeErr: errors.New("resume failed")}}, nil}, Times: 1},
		{Values: []interface{}{containerdclient.Container(nil), errors.New("load failed")}, Times: 1},
		{Values: []interface{}{&mockContainer{imgErr: errors.New("image failed")}, nil}, Times: 1},
		{Values: []interface{}{&mockContainer{image: &mockImage{name: "test-image"}, taskErr: errors.New("task failed")}, nil}, Times: 1},
		{Values: []interface{}{&mockContainer{image: &mockImage{name: "test-image"}, task: &mockTask{pid: 100}, infoErr: errors.New("info failed")}, nil}, Times: 1},
		{Values: []interface{}{&mockContainer{image: &mockImage{name: "test-image"}, task: &mockTask{pid: 100}, info: containers.Container{Spec: &anypb.Any{TypeUrl: "test", Value: []byte("not-json")}, SnapshotKey: "snap-key"}}, nil}, Times: 1},
		{Values: []interface{}{&mockContainer{image: &mockImage{name: "test-image"}, task: &mockTask{pid: 100}, info: containers.Container{Spec: &anypb.Any{TypeUrl: "test", Value: specBytes}, SnapshotKey: "snap-key"}}, nil}, Times: 1},
	})
	defer loadPatches.Reset()

	snapshotPatches := patchSnapshotService(client, &mockSnapshotter{err: errors.New("mount failed")})
	defer snapshotPatches.Reset()

	err = (&Manager{address: "test"}).Pause(context.Background(), "id")
	require.ErrorContains(t, err, "create client")

	err = (&Manager{address: "test"}).Pause(context.Background(), "id")
	require.ErrorContains(t, err, "load container")

	err = (&Manager{address: "test"}).Pause(context.Background(), "id")
	require.ErrorContains(t, err, "obtain container task")

	err = (&Manager{address: "test"}).Pause(context.Background(), "id")
	require.EqualError(t, err, "pause failed")

	err = (&Manager{address: "test"}).UnPause(context.Background(), "id")
	require.ErrorContains(t, err, "create client")

	err = (&Manager{address: "test"}).UnPause(context.Background(), "id")
	require.ErrorContains(t, err, "load container")

	err = (&Manager{address: "test"}).UnPause(context.Background(), "id")
	require.ErrorContains(t, err, "obtain container task")

	err = (&Manager{address: "test"}).UnPause(context.Background(), "id")
	require.EqualError(t, err, "resume failed")

	_, err = (&Manager{address: "test"}).Inspect(context.Background(), "id")
	require.ErrorContains(t, err, "create client")

	_, err = (&Manager{address: "test"}).Inspect(context.Background(), "id")
	require.ErrorContains(t, err, "load container")

	_, err = (&Manager{address: "test"}).Inspect(context.Background(), "id")
	require.ErrorContains(t, err, "obtain container image")

	_, err = (&Manager{address: "test"}).Inspect(context.Background(), "id")
	require.ErrorContains(t, err, "obtain container task")

	_, err = (&Manager{address: "test"}).Inspect(context.Background(), "id")
	require.ErrorContains(t, err, "obtain container info")

	_, err = (&Manager{address: "test"}).Inspect(context.Background(), "id")
	require.ErrorContains(t, err, "unmarshal json")

	_, err = (&Manager{address: "test"}).Inspect(context.Background(), "id")
	require.ErrorContains(t, err, "get snapshot mount")
}

func TestInspectParseMountOptionsPaths(t *testing.T) {
	specBytes, err := json.Marshal(runtimespec.Spec{Mounts: []runtimespec.Mount{{Destination: "/dst", Source: "/src"}}})
	require.NoError(t, err)

	client := &containerdclient.Client{}
	goodContainer := &mockContainer{
		image: &mockImage{name: "test-image"},
		task:  &mockTask{pid: 100},
		info: containers.Container{
			Spec:        &anypb.Any{TypeUrl: "test", Value: specBytes},
			SnapshotKey: "snap-key",
		},
	}

	patches := patchClientNewSeq([]gomonkey.OutputCell{
		{Values: []interface{}{client, nil}, Times: 2},
	})
	defer patches.Reset()

	loadPatches := patchLoadContainerSeq(client, []gomonkey.OutputCell{
		{Values: []interface{}{goodContainer, nil}, Times: 2},
	})
	defer loadPatches.Reset()

	snapshotPatches := gomonkey.ApplyMethodSeq(client, "SnapshotService",
		[]gomonkey.OutputCell{
			// First cell leads to an error from Inspect() due to missing mount options
			{Values: []interface{}{snapshots.Snapshotter(&mockSnapshotter{
				mounts: []mount.Mount{{Options: []string{"workdir=/work"}}},
			})}, Times: 1},
			// Inspect() will succeed: all necessary mount options present
			{Values: []interface{}{snapshots.Snapshotter(&mockSnapshotter{
				mounts: []mount.Mount{{Options: []string{"workdir=/work", "upperdir=/upper", "lowerdir=/lower"}}},
			})}, Times: 1},
		},
	)
	defer snapshotPatches.Reset()

	_, err = (&Manager{address: "test"}).Inspect(context.Background(), "id")
	require.ErrorContains(t, err, "parse snapshot mount options")

	result, err := (&Manager{address: "test"}).Inspect(context.Background(), "id")
	require.NoError(t, err)
	require.Equal(t, "/lower", result.LowerDirs)
	require.Equal(t, "/upper", result.UpperDir)
	require.Equal(t, "test-image", result.Image)
	require.Equal(t, 100, result.Pid)
}

func TestParseMountOptions(t *testing.T) {
	tests := []struct {
		Name         string
		Options      []string
		WantLower    string
		WantUpper    string
		WantErr      bool
		ErrSubstring string
	}{
		{
			Name: "StandardOrder",
			Options: []string{
				"workdir=/var/lib/containerd/snapshots/123/work",
				"upperdir=/var/lib/containerd/snapshots/123/fs",
				"lowerdir=/var/lib/containerd/snapshots/100/mnt",
			},
			WantLower: "/var/lib/containerd/snapshots/100/mnt",
			WantUpper: "/var/lib/containerd/snapshots/123/fs",
		},
		{
			Name: "WithVolatilePrefix",
			Options: []string{
				"volatile",
				"workdir=/var/lib/containerd/io.containerd.snapshotter.v1.nydus/snapshots/1443/work",
				"upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.nydus/snapshots/1443/fs",
				"lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.nydus/snapshots/282/mnt",
			},
			WantLower: "/var/lib/containerd/io.containerd.snapshotter.v1.nydus/snapshots/282/mnt",
			WantUpper: "/var/lib/containerd/io.containerd.snapshotter.v1.nydus/snapshots/1443/fs",
		},
		{
			Name: "ReversedOrder",
			Options: []string{
				"lowerdir=/lower",
				"upperdir=/upper",
				"workdir=/work",
			},
			WantLower: "/lower",
			WantUpper: "/upper",
		},
		{
			Name: "MultipleLowerDirs",
			Options: []string{
				"workdir=/work",
				"upperdir=/upper",
				"lowerdir=/lower1:/lower2:/lower3",
			},
			WantLower: "/lower1:/lower2:/lower3",
			WantUpper: "/upper",
		},
		{
			Name: "WithIndexOff",
			Options: []string{
				"volatile",
				"index=off",
				"workdir=/work",
				"upperdir=/upper",
				"lowerdir=/lower",
			},
			WantLower: "/lower",
			WantUpper: "/upper",
		},
		{
			Name:         "MissingLowerDir",
			Options:      []string{"workdir=/work", "upperdir=/upper"},
			WantErr:      true,
			ErrSubstring: "missing lowerdir or upperdir",
		},
		{
			Name:         "MissingUpperDir",
			Options:      []string{"workdir=/work", "lowerdir=/lower"},
			WantErr:      true,
			ErrSubstring: "missing lowerdir or upperdir",
		},
		{
			Name:         "EmptyOptions",
			Options:      []string{},
			WantErr:      true,
			ErrSubstring: "missing lowerdir or upperdir",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			lowerDirs, upperDir, err := parseMountOptions(tt.Options)
			if tt.WantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.ErrSubstring)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.WantLower, lowerDirs)
			assert.Equal(t, tt.WantUpper, upperDir)
		})
	}
}
