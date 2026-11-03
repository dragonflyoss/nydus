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
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestCheck(t *testing.T) {
	t.Parallel()
	reg := registry.Start(t)
	srcs := corpusSources(t)

	refs := map[string]string{}

	for _, src := range srcs {
		refs[src.name] = reg.Ref("check-"+src.name, "oci")
		reg.PushDirs(t, refs[src.name], src.dirs...)
	}

	for _, src := range srcs {
		for _, compressor := range []string{"zstd", "erofs-lz4"} {
			t.Run(src.name+"/"+compressor, func(t *testing.T) {
				t.Parallel()
				target := reg.Ref("check-"+src.name, compressor)
				nydusify(t, "convert", "--source", refs[src.name], "--target", target, "--compressor", compressor)
				nydusify(t, "check", "--source", refs[src.name], "--target", target)

				work := t.TempDir()
				nydusify(t, "check", "--target", target, "--work-dir", work)
				exported, err := os.ReadFile(filepath.Join(work, "target", "manifest.json"))
				if !assert.NoError(t, err) {
					t.FailNow()
				}

				remoteImg := ref(target).image(t)
				raw, err := remoteImg.RawManifest()
				if !assert.NoError(t, err) {
					t.FailNow()
				}
				if !assert.Equal(t, string(raw), string(exported)) {
					t.FailNow()
				}

				exported, err = os.ReadFile(filepath.Join(work, "target", "config.json"))
				if !assert.NoError(t, err) {
					t.FailNow()
				}

				raw, err = remoteImg.RawConfigFile()
				if !assert.NoError(t, err) {
					t.FailNow()
				}

				assert.Equal(t, string(raw), string(exported))
				pulled := ref(target).pull(t, src.want)

				assert.Equal(t, fstest.FileSHA256(t, pulled.Bootstrap),
					fstest.FileSHA256(t, filepath.Join(work, "target", "bootstrap", bootstrapInLayer)))
			})
		}
	}

	t.Run("Mismatch", func(t *testing.T) {
		t.Parallel()
		target := reg.Ref("check-single", "mismatch")
		nydusify(t, "convert", "--source", refs["single"], "--target", target)
		work := t.TempDir()
		out, err := tryNydusify(t, "check", "--source", refs["multi"], "--target", target, "--work-dir", work)
		if !assert.Error(t, err) {
			t.FailNow()
		}

		assert.Contains(t, out, "filesystem mismatch")
		expectCheckScratchClean(t, work)
	})

	for _, failure := range []string{"TargetMountFailure", "WalkFailure", "ForcedUnmount"} {
		t.Run(failure, func(t *testing.T) {
			t.Parallel()
			repo := "check-" + strings.ToLower(failure)
			target := reg.Ref(repo, "target")
			nydusify(t, "convert", "--source", refs["single"], "--target", target)
			work, state := t.TempDir(), t.TempDir()
			builder, pidFile := filepath.Join(state, "builder"), filepath.Join(state, "pids")
			ready := filepath.Join(state, "both-started")

			script := fmt.Sprintf(`#!/bin/sh
if [ "$1" = fuse ]; then
    echo $$ >> %q
    if mkdir %q 2>/dev/null; then
        :
    elif [ %q != WalkFailure ]; then
        if [ %q = ForcedUnmount ]; then
            read -r source_pid < %q
            kill -STOP "$source_pid"
        fi
        echo 'injected target mount failure' >&2
        exit 23
    else
        touch %q
    fi
fi
exec %q "$@"
`, pidFile, filepath.Join(state, "started"), failure, failure, pidFile, ready, env.Nydus(t))

			if !assert.NoError(t, os.WriteFile(builder, []byte(script), 0o700)) {
				t.FailNow()
			}

			checkBinary := env.Nydusify(t)
			unmountCalls := filepath.Join(state, "unmount-calls")

			if failure == "ForcedUnmount" {
				helpers := filepath.Join(state, "helpers")
				if !assert.NoError(t, os.Mkdir(helpers, 0o700)) {
					t.FailNow()
				}

				for _, name := range []string{"fusermount3", "fusermount", "umount"} {
					body := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' %q >> %q\n", name, unmountCalls)

					if name == "umount" {
						body += fmt.Sprintf("exec %q \"$@\"\n", env.RequireTool(t, "umount"))
					} else {
						body += "exit 23\n"
					}

					if !assert.NoError(t, os.WriteFile(filepath.Join(helpers, name), []byte(body), 0o700)) {
						t.FailNow()
					}
				}

				checkBinary = filepath.Join(state, "check")
				wrapper := fmt.Sprintf("#!/bin/sh\nexport PATH=%q:\"$PATH\"\nexec %q \"$@\"\n", helpers, env.Nydusify(t))
				if !assert.NoError(t, os.WriteFile(checkBinary, []byte(wrapper), 0o700)) {
					t.FailNow()
				}
			}

			if failure == "WalkFailure" {
				reg.Faults.Set(registry.Fault{Status: http.StatusForbidden, Match: func(r *http.Request) bool {
					_, err := os.Stat(ready)
					return err == nil && registry.IsBlobGet(r) && strings.HasPrefix(r.URL.Path, "/v2/"+repo+"/blobs/")
				}})
			}

			t.Cleanup(func() {
				mounts, err := mount.MountsUnder(work)
				if !assert.NoError(t, err) {
					t.FailNow()
				}

				for _, mnt := range mounts {
					mount.Unmount(mnt)
				}

				if len(mounts) != 0 {
					data, err := os.ReadFile(pidFile)
					if !assert.NoError(t, err) {
						t.FailNow()
					}

					for value := range strings.FieldsSeq(string(data)) {
						pid, err := strconv.Atoi(value)
						if !assert.NoError(t, err) {
							t.FailNow()
						}

						signal := unix.SIGTERM
						if failure == "ForcedUnmount" {
							signal = unix.SIGKILL
						}

						if err := unix.Kill(pid, signal); !errors.Is(err, unix.ESRCH) {
							assert.NoError(t, err)
						}
					}
				}
			})

			started := time.Now()

			d := mount.StartDaemon(t, env.WorkDir(t), "check-target-failure", checkBinary,
				"check", "--source", target, "--target", target, "--builder", builder,
				"--source-plain-http", "--target-plain-http", "--work-dir", work)

			timeout := 10 * time.Second
			if failure == "ForcedUnmount" {
				timeout = 25 * time.Second
			}

			d.WaitFor(t, timeout, "failed check to exit", func() bool { return !d.Alive() })

			if !assert.Positive(t, d.ExitCode()) {
				t.FailNow()
			}

			if failure != "WalkFailure" {
				if !assert.Contains(t, d.Log(), "mount target image") {
					t.FailNow()
				}

				assert.Contains(t, d.Log(), "injected target mount failure")
			} else {
				assert.Positive(t, reg.Faults.Hits())
				assert.Contains(t, d.Log(), "walk source rootfs")
			}

			if failure == "ForcedUnmount" {
				assert.GreaterOrEqual(t, time.Since(started), 10*time.Second)
				calls, err := os.ReadFile(unmountCalls)
				if !assert.NoError(t, err) {
					t.FailNow()
				}

				assert.Equal(t, "fusermount3\nfusermount\numount\n", string(calls))
			}

			data, err := os.ReadFile(pidFile)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			pids := strings.Fields(string(data))
			if !assert.Len(t, pids, 2) {
				t.FailNow()
			}

			for _, value := range pids {
				pid, err := strconv.Atoi(value)
				if !assert.NoError(t, err) {
					t.FailNow()
				}

				assert.ErrorIs(t, unix.Kill(pid, 0), unix.ESRCH)
			}

			expectCheckScratchClean(t, work)
		})
	}
}

func expectCheckScratchClean(t *testing.T, work string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(work, "scratch"))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.Empty(t, entries)
	mounts, err := mount.MountsUnder(work)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.Empty(t, mounts)
}
