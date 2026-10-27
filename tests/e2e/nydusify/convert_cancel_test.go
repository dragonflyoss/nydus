package nydusify

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/proc"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/require"
)

func TestConvertCancel(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
	reg := registry.Start(t)
	src := inputTree(t, map[string]string{"payload": "cancel and resume\n"})
	source, target := reg.Ref("cancel", "source"), reg.Ref("cancel", "target")
	reg.PushDirs(t, source, src)
	reg.Faults.Set(registry.Fault{Delay: time.Minute, Match: func(r *http.Request) bool {
		return registry.IsBlobGet(r)
	}})
	work := t.TempDir()
	dir := env.WorkDir(t)
	args := []string{"convert", "--source", source, "--target", target, "--work-dir", work}
	d := mount.StartDaemon(t, dir, "nydusify-convert", env.Nydusify(t),
		append(args, "--builder", env.Nydus(t), "--source-plain-http", "--target-plain-http")...)
	d.WaitFor(t, 10*time.Second, "blocked registry read", func() bool { return reg.Faults.Hits() > 0 })
	children := proc.Children(d.Pid())
	d.Signal(syscall.SIGTERM)
	select {
	case <-d.Exited():
	case <-time.After(10 * time.Second):
		t.Fatal("conversion did not stop after SIGTERM")
	}
	require.NotZero(t, d.ExitCode(), "canceled conversion must not report success")
	for _, pid := range children {
		_, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid)))
		require.True(t, os.IsNotExist(err), "child %d survived cancellation: %v", pid, err)
	}
	ref, err := name.ParseReference(target, name.Insecure)
	require.NoError(t, err)
	_, err = remote.Head(ref)
	require.Error(t, err, "canceled conversion published a manifest")
	reg.Faults.Clear()
	nydusify(t, args...)
	img := pullNydus(t, target, oracle.ScanSource(t, src))
	m := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
	oracle.VerifyMount(t, m.Root, img.Want, img.Compare())
}
