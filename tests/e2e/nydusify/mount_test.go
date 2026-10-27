package nydusify

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/proc"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func testMountLifecycle(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
	reg := registry.Start(t)
	src := inputTree(t, map[string]string{"payload": "mount lifecycle\n"})
	source, target := reg.Ref("mount-lifecycle", "oci"), reg.Ref("mount-lifecycle", "nydus")
	reg.PushDirs(t, source, src)
	nydusify(t, "convert", "--source", source, "--target", target)
	for _, mode := range []string{"graceful", "child_failure", "stuck_child"} {
		t.Run(mode, func(t *testing.T) {
			d, mnt, _ := startMount(t, target, false)
			data, err := os.ReadFile(filepath.Join(mnt, "payload"))
			require.NoError(t, err)
			require.Equal(t, "mount lifecycle\n", string(data))
			children := proc.Children(d.Pid())
			require.Len(t, children, 1, "one foreground nydus fuse child")
			if mode == "child_failure" {
				require.NoError(t, syscall.Kill(children[0], syscall.SIGKILL))
			} else {
				if mode == "stuck_child" {
					require.NoError(t, syscall.Kill(children[0], syscall.SIGSTOP))
				}
				d.Signal(syscall.SIGTERM)
			}
			select {
			case <-d.Exited():
			case <-time.After(20 * time.Second):
				t.Fatal("mount did not terminate and reap its child within 20s")
			}
			if mode == "graceful" {
				require.Zero(t, d.ExitCode(), d.Log())
			} else {
				require.NotZero(t, d.ExitCode(), "unexpected or forced child exit must remain an error")
				require.Contains(t, d.Log(), "nydus fuse exited")
			}
			for _, pid := range children {
				_, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid)))
				require.True(t, os.IsNotExist(err), "child %d survived: %v", pid, err)
			}
			require.False(t, mount.IsMountpoint(mnt), "dead FUSE mount survived child exit")
			mounts, err := proc.MountsUnder(mnt)
			require.NoError(t, err)
			require.Empty(t, mounts, "mount leaks must be checked before harness cleanup")
		})
	}
	for _, mode := range []string{"preexisting_live", "preexisting_dead", "replaced_while_starting"} {
		t.Run(mode, func(t *testing.T) {
			foreign, foreignMount, _ := startMount(t, target, false)
			if mode != "preexisting_live" {
				children := proc.Children(foreign.Pid())
				require.Len(t, children, 1)
				foreign.Signal(syscall.SIGSTOP)
				t.Cleanup(func() { foreign.Signal(syscall.SIGCONT) })
				require.NoError(t, syscall.Kill(children[0], syscall.SIGKILL))
				require.Eventually(t, func() bool {
					var stat unix.Statfs_t
					return unix.Statfs(foreignMount, &stat) == unix.ENOTCONN
				}, 10*time.Second, 10*time.Millisecond, "foreign mount must be disconnected")
			}
			work := t.TempDir()
			mnt := foreignMount
			if mode == "replaced_while_starting" {
				mnt = filepath.Join(work, "mnt")
				require.NoError(t, os.Mkdir(mnt, 0o700))
			}
			builder, pidPath, release := filepath.Join(work, "builder"), filepath.Join(work, "pid"), filepath.Join(work, "release")
			script := fmt.Sprintf("#!/bin/sh\necho $$ > %q\nwhile [ ! -f %q ]; do sleep 0.01; done\nexit 7\n", pidPath, release)
			require.NoError(t, os.WriteFile(builder, []byte(script), 0o700))
			if mode != "replaced_while_starting" {
				require.NoError(t, os.WriteFile(release, nil, 0o600))
			}
			failed := mount.StartDaemon(t, work, "failed-mount", env.Nydusify(t),
				"mount", "--target", target, "--target-plain-http", "--mountpoint", mnt,
				"--work-dir", filepath.Join(work, "work"), "--builder", builder)
			var child int
			if mode == "replaced_while_starting" {
				failed.WaitFor(t, 10*time.Second, "child startup", func() bool {
					data, _ := os.ReadFile(pidPath)
					child, _ = strconv.Atoi(strings.TrimSpace(string(data)))
					return child != 0
				})
				require.NoError(t, os.Remove(mnt))
				require.NoError(t, os.Symlink(foreignMount, mnt))
				require.NoError(t, os.WriteFile(release, nil, 0o600))
			}
			select {
			case <-failed.Exited():
			case <-time.After(20 * time.Second):
				t.Fatal("mount startup failure did not return")
			}
			require.NotZero(t, failed.ExitCode(), failed.Log())
			if mode == "replaced_while_starting" {
				require.Contains(t, failed.Log(), "mount ownership changed")
				require.ErrorIs(t, unix.Kill(child, 0), unix.ESRCH, "failed child must be reaped")
			} else {
				_, err := os.Stat(pidPath)
				require.True(t, os.IsNotExist(err), "pre-existing mounts must be rejected before starting the child")
			}
			// mountpoint(1) may fail to stat a disconnected FUSE mount.
			mounts, err := proc.MountsUnder(foreignMount)
			require.NoError(t, err)
			require.Equal(t, []string{foreignMount}, mounts, "failure cleanup unmounted a foreign mount")
			if mode == "preexisting_live" {
				data, err := os.ReadFile(filepath.Join(foreignMount, "payload"))
				require.NoError(t, err)
				require.Equal(t, "mount lifecycle\n", string(data))
			}
		})
	}
}

// TestMount runs `nydusify mount`: a nydus image is served by FUSE on
// demand from the registry, with metrics on the apiserver under the work
// directory; an OCI image is extracted into the mountpoint instead. Both
// reproduce the source tree.
func TestMount(t *testing.T) {
	t.Parallel()
	t.Run("lifecycle", testMountLifecycle)
	reg := registry.Start(t)
	for _, src := range corpusSources(t) {
		t.Run(src.name, func(t *testing.T) {
			t.Parallel()
			srcRef := reg.Ref("mount-"+src.name, "oci")
			nydusRef := reg.Ref("mount-"+src.name, "nydus")
			reg.PushDirs(t, srcRef, src.dirs...)
			nydusify(t, "convert", "--source", srcRef, "--target", nydusRef)

			manifest, err := remoteImage(t, nydusRef).Manifest()
			require.NoError(t, err)
			dataBlobs := map[string]bool{}
			for _, layer := range manifest.Layers {
				if _, ok := layer.Annotations[nydusBlobAnnotation]; ok {
					dataBlobs[layer.Digest.String()] = true
				}
			}
			require.NotEmpty(t, dataBlobs)
			before := len(reg.Faults.Requests())
			_, mnt, api := startMount(t, nydusRef, false)
			for _, request := range reg.Faults.Requests()[before:] {
				_, digest, _ := strings.Cut(request.Path, "/blobs/")
				require.False(t, request.Method == http.MethodGet && strings.HasPrefix(request.Path, "/v2/mount-"+src.name+"/blobs/") && dataBlobs[digest],
					"mount downloaded data before the first read: %+v", request)
			}
			oracle.VerifyMount(t, mnt, src.want, src.compare())
			metrics := api.Metrics(t)
			require.Positive(t, metrics.Sum("nydus_backend_read_total", `type="ondemand"`), "reads must be served on demand from the registry")
			require.Zero(t, metrics.Sum("nydus_backend_read_total", `type="prefetch"`), "prefetch is off by default")

			oracle.VerifyMount(t, extractOCI(t, srcRef), src.want, src.compare())
		})
	}
}
