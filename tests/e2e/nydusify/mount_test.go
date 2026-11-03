package nydusify

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/util/proc"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestMount(t *testing.T) {
	t.Parallel()
	reg := registry.Start(t)

	for _, src := range corpusSources(t) {
		t.Run(src.name, func(t *testing.T) {
			t.Parallel()
			srcRef := reg.Ref("mount-"+src.name, "oci")
			nydusRef := reg.Ref("mount-"+src.name, "nydus")
			reg.PushDirs(t, srcRef, src.dirs...)
			nydusify(t, "convert", "--source", srcRef, "--target", nydusRef)

			manifest, err := ref(nydusRef).image(t).Manifest()
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			dataBlobs := map[string]bool{}

			for _, layer := range manifest.Layers {
				if _, ok := layer.Annotations[nydusBlobAnnotation]; ok {
					dataBlobs[layer.Digest.String()] = true
				}
			}

			if !assert.NotEmpty(t, dataBlobs) {
				t.FailNow()
			}

			dataBlobGet := func(r registry.Request) bool {
				digest, ok := strings.CutPrefix(r.Path, "/v2/mount-"+src.name+"/blobs/")
				return ok && r.Method == http.MethodGet && dataBlobs[digest]
			}

			before := reg.Faults.Count(dataBlobGet)
			_, mnt, api := ref(nydusRef).mount(t, false)
			assert.Equal(t, before, reg.Faults.Count(dataBlobGet))

			fstest.VerifyMount(t, mnt, src.want, src.compare())
			metrics := api.Metrics(t)
			if !assert.Positive(t, metrics.Sum("nydus_backend_read_total", `type="ondemand"`)) {
				t.FailNow()
			}

			assert.Zero(t, metrics.Sum("nydus_backend_read_total", `type="prefetch"`))

			fstest.VerifyMount(t, ref(srcRef).extract(t), src.want, src.compare())
		})
	}
}

func TestMountLifecycle(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
	reg := registry.Start(t)
	src := inputTree(t, map[string]string{"payload": "mount lifecycle\n"})
	source, target := reg.Ref("mount-lifecycle", "oci"), reg.Ref("mount-lifecycle", "nydus")
	reg.PushDirs(t, source, src)
	nydusify(t, "convert", "--source", source, "--target", target)

	for _, mode := range []string{"Graceful", "ChildFailure", "StuckChild"} {
		t.Run(mode, func(t *testing.T) {
			d, mnt, _ := ref(target).mount(t, false)
			data, err := os.ReadFile(filepath.Join(mnt, "payload"))
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			assert.Equal(t, "mount lifecycle\n", string(data))
			children := proc.Children(d.Pid())
			if !assert.Len(t, children, 1) {
				t.FailNow()
			}

			if mode == "ChildFailure" {
				assert.NoError(t, unix.Kill(children[0], unix.SIGKILL))
			} else {
				if mode == "StuckChild" {
					assert.NoError(t, unix.Kill(children[0], unix.SIGSTOP))
				}

				d.Signal(unix.SIGTERM)
			}

			if !assert.True(t, d.WaitExit(20*time.Second)) {
				t.FailNow()
			}

			if mode == "Graceful" {
				assert.Zero(t, d.ExitCode())
			} else {
				if !assert.NotZero(t, d.ExitCode()) {
					t.FailNow()
				}

				assert.Contains(t, d.Log(), "nydus fuse exited")
			}

			proc.ExpectGone(t, children, time.Second)

			if !assert.False(t, mount.IsMountpoint(mnt)) {
				t.FailNow()
			}

			mounts, err := mount.PointsUnder(mnt)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			assert.Empty(t, mounts)
		})
	}

	for _, mode := range []string{"PreexistingLive", "PreexistingDead", "ReplacedWhileStarting"} {
		t.Run(mode, func(t *testing.T) {
			foreign, foreignMount, _ := ref(target).mount(t, false)

			if mode != "PreexistingLive" {
				children := proc.Children(foreign.Pid())
				if !assert.Len(t, children, 1) {
					t.FailNow()
				}

				foreign.Signal(unix.SIGSTOP)
				t.Cleanup(func() { foreign.Signal(unix.SIGCONT) })
				assert.NoError(t, unix.Kill(children[0], unix.SIGKILL))

				if !assert.Eventually(t, func() bool {
					var stat unix.Statfs_t
					return errors.Is(unix.Statfs(foreignMount, &stat), unix.ENOTCONN)
				}, 10*time.Second, 10*time.Millisecond) {
					t.FailNow()
				}
			}

			work := t.TempDir()

			mnt := foreignMount
			if mode == "ReplacedWhileStarting" {
				mnt = filepath.Join(work, "mnt")
				if !assert.NoError(t, os.Mkdir(mnt, 0o700)) {
					t.FailNow()
				}
			}

			builder, pidPath, release := filepath.Join(work, "builder"), filepath.Join(work, "pid"), filepath.Join(work, "release")
			script := fmt.Sprintf("#!/bin/sh\necho $$ > %q\nwhile [ ! -f %q ]; do sleep 0.01; done\nexit 7\n", pidPath, release)
			if !assert.NoError(t, os.WriteFile(builder, []byte(script), 0o700)) {
				t.FailNow()
			}

			if mode != "ReplacedWhileStarting" {
				if !assert.NoError(t, os.WriteFile(release, nil, 0o600)) {
					t.FailNow()
				}
			}

			failed := mount.StartDaemon(t, work, "failed-mount", env.Nydusify(t),
				"mount", "--target", target, "--target-plain-http", "--mountpoint", mnt,
				"--work-dir", filepath.Join(work, "work"), "--builder", builder)

			var child int
			if mode == "ReplacedWhileStarting" {
				failed.WaitFor(t, 10*time.Second, "child startup", func() bool {
					data, _ := os.ReadFile(pidPath)
					child, _ = strconv.Atoi(strings.TrimSpace(string(data)))

					return child != 0
				})

				if !assert.NoError(t, os.Remove(mnt)) {
					t.FailNow()
				}
				if !assert.NoError(t, os.Symlink(foreignMount, mnt)) {
					t.FailNow()
				}
				if !assert.NoError(t, os.WriteFile(release, nil, 0o600)) {
					t.FailNow()
				}
			}

			if !assert.True(t, failed.WaitExit(20*time.Second)) {
				t.FailNow()
			}
			if !assert.NotZero(t, failed.ExitCode()) {
				t.FailNow()
			}

			if mode == "ReplacedWhileStarting" {
				assert.Contains(t, failed.Log(), "mount ownership changed")
				assert.ErrorIs(t, unix.Kill(child, 0), unix.ESRCH)
			} else {
				assert.NoFileExists(t, pidPath)
			}

			mounts, err := mount.PointsUnder(foreignMount)
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			if !assert.Equal(t, []string{foreignMount}, mounts) {
				t.FailNow()
			}

			if mode == "PreexistingLive" {
				data, err := os.ReadFile(filepath.Join(foreignMount, "payload"))
				if !assert.NoError(t, err) {
					t.FailNow()
				}

				assert.Equal(t, "mount lifecycle\n", string(data))
			}
		})
	}
}
