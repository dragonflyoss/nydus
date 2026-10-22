// Package compat executes feature contracts against a deliberately reduced
// CLI binary. CI builds each variant separately with --no-default-features.
package compat

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
)

func TestFeatures(t *testing.T) {
	t.Parallel()
	variant := os.Getenv("NYDUS_E2E_FEATURE_VARIANT")
	env.Require(t, variant != "", "set NYDUS_E2E_FEATURE_VARIANT to minimal, registry, or fileio")
	require.Contains(t, []string{"minimal", "registry", "fileio"}, variant)
	bin := env.Nydus(t)
	run := func(args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
		require.NoError(t, ctx.Err(), "binary hung: %s", out)
		return string(out), err
	}
	for _, command := range []string{"build", "check", "export", "fuse", "fileio", "nbd", "ublk", "uffd", "fanotify"} {
		t.Run(command, func(t *testing.T) {
			out, err := run(command, "--help")
			enabled := command == "build" || command == "check" || command == "export" || command == "fuse" || (command == "fileio" && variant == "fileio")
			if enabled {
				require.NoError(t, err, "%s", out)
				require.Contains(t, out, "Usage:")
			} else {
				require.Error(t, err, "%s", out)
				require.Contains(t, out, "unrecognized subcommand")
			}
		})
	}

	t.Run("DisabledBackendConfig", func(t *testing.T) {
		dir := env.WorkDir(t)
		cfg := mount.Config{Backend: mount.RegistryBackend(mount.Registry{
			Addr: "http://127.0.0.1:1", Repository: "feature-test",
		})}
		disabled := "registry"
		if variant != "minimal" {
			disabled = "dragonfly"
			cfg.Backend = mount.RegistryBackend(mount.Registry{
				Addr: "http://127.0.0.1:1", Repository: "feature-test",
				Dragonfly: &mount.Dragonfly{SchedulerEndpoint: "http://127.0.0.1:1"},
			})
		}
		path := cfg.Write(t, dir, "config.json")
		out, err := run("fuse", "--config", path, "--mountpoint", dir,
			"--bootstrap", filepath.Join(dir, "unused.bootstrap"), "--log-dir", filepath.Join(dir, "logs"))
		require.Error(t, err)
		require.Contains(t, strings.ToLower(out), disabled)
		require.Contains(t, strings.ToLower(out), "feature",
			"must reject disabled config, not proceed to network/image/mount failure")
	})
}
