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
	"github.com/dragonflyoss/nydus/tests/e2e/internal/proc"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/stretchr/testify/require"
)

// TestCheck runs `nydusify check` on converted images: against their OCI
// source it passes for chunk-based and native layers alike (manifest,
// bootstrap and a full filesystem diff), it fails on an image of different
// content, and on a single image it exports exactly what the registry holds.
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
				require.NoError(t, err)
				remoteImg := remoteImage(t, target)
				raw, err := remoteImg.RawManifest()
				require.NoError(t, err)
				require.Equal(t, string(raw), string(exported), "exported manifest")
				exported, err = os.ReadFile(filepath.Join(work, "target", "config.json"))
				require.NoError(t, err)
				raw, err = remoteImg.RawConfigFile()
				require.NoError(t, err)
				require.Equal(t, string(raw), string(exported), "exported config")
				pulled := pullNydus(t, target, src.want)
				require.Equal(t, fileSHA256(t, pulled.Bootstrap),
					fileSHA256(t, filepath.Join(work, "target", "bootstrap", bootstrapInLayer)), "exported bootstrap")
			})
		}
	}

	t.Run("Mismatch", func(t *testing.T) {
		t.Parallel()
		target := reg.Ref("check-single", "mismatch")
		nydusify(t, "convert", "--source", refs["single"], "--target", target)
		work := t.TempDir()
		out, err := tryNydusify(t, "check", "--source", refs["multi"], "--target", target, "--work-dir", work)
		require.Error(t, err, "an image checked against another image's source must fail:\n%s", out)
		require.Contains(t, out, "filesystem mismatch")
		requireCheckScratchClean(t, work)
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
			require.NoError(t, os.WriteFile(builder, []byte(script), 0o700))
			checkBinary := env.Nydusify(t)
			unmountCalls := filepath.Join(state, "unmount-calls")
			if failure == "ForcedUnmount" {
				helpers := filepath.Join(state, "helpers")
				require.NoError(t, os.Mkdir(helpers, 0o700))
				for _, name := range []string{"fusermount3", "fusermount", "umount"} {
					body := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' %q >> %q\n", name, unmountCalls)
					if name == "umount" {
						body += fmt.Sprintf("exec %q \"$@\"\n", env.RequireTool(t, "umount"))
					} else {
						body += "exit 23\n"
					}
					require.NoError(t, os.WriteFile(filepath.Join(helpers, name), []byte(body), 0o700))
				}
				checkBinary = filepath.Join(state, "check")
				wrapper := fmt.Sprintf("#!/bin/sh\nexport PATH=%q:\"$PATH\"\nexec %q \"$@\"\n", helpers, env.Nydusify(t))
				require.NoError(t, os.WriteFile(checkBinary, []byte(wrapper), 0o700))
			}
			if failure == "WalkFailure" {
				reg.Faults.Set(registry.Fault{Status: http.StatusForbidden, Match: func(r *http.Request) bool {
					_, err := os.Stat(ready)
					return err == nil && registry.IsBlobGet(r) && strings.HasPrefix(r.URL.Path, "/v2/"+repo+"/blobs/")
				}})
			}
			t.Cleanup(func() {
				mounts, err := proc.MountsUnder(work)
				require.NoError(t, err)
				for _, mnt := range mounts {
					mount.Unmount(mnt)
				}
				if len(mounts) != 0 {
					data, err := os.ReadFile(pidFile)
					require.NoError(t, err)
					for _, value := range strings.Fields(string(data)) {
						pid, err := strconv.Atoi(value)
						require.NoError(t, err)
						signal := syscall.SIGTERM
						if failure == "ForcedUnmount" {
							signal = syscall.SIGKILL
						}
						err = syscall.Kill(pid, signal)
						require.True(t, err == nil || err == syscall.ESRCH, "%v", err)
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
			require.Positive(t, d.ExitCode(), "%s", d.Log())
			if failure != "WalkFailure" {
				require.Contains(t, d.Log(), "mount target image")
				require.Contains(t, d.Log(), "injected target mount failure")
			} else {
				require.Positive(t, reg.Faults.Hits())
				require.Contains(t, d.Log(), "walk source rootfs")
			}
			if failure == "ForcedUnmount" {
				require.GreaterOrEqual(t, time.Since(started), 10*time.Second, "exercise the unchanged forced-cleanup deadline")
				calls, err := os.ReadFile(unmountCalls)
				require.NoError(t, err)
				require.Equal(t, "fusermount3\nfusermount\numount\n", string(calls), "failed helpers must fall back to real umount")
			}
			data, err := os.ReadFile(pidFile)
			require.NoError(t, err, "the source daemon must have started")
			pids := strings.Fields(string(data))
			require.Len(t, pids, 2, "both source and target commands must have started")
			for _, value := range pids {
				pid, err := strconv.Atoi(value)
				require.NoError(t, err)
				require.ErrorIs(t, syscall.Kill(pid, 0), syscall.ESRCH, "daemon survived failed check")
			}
			requireCheckScratchClean(t, work)
		})
	}
}

func requireCheckScratchClean(t *testing.T, work string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(work, "scratch"))
	require.NoError(t, err)
	require.Empty(t, entries, "check must clean both source and target scratch directories")
	mounts, err := proc.MountsUnder(work)
	require.NoError(t, err)
	require.Empty(t, mounts, "check must unmount both images on failure")
}
