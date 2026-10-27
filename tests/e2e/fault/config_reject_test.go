package fault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
)

// rejectTimeout bounds how long a daemon may take to turn down a broken
// config: it never needs to touch the backend to do so.
const rejectTimeout = 10 * time.Second

// rejectCase is one broken daemon invocation.
type rejectCase struct {
	name string
	// edit breaks the config, a JSON object; dir is the case's directory.
	edit func(cfg map[string]any, dir string)
	// bootstrap, if set, replaces the image bootstrap by this file in dir.
	bootstrap string
	// args are extra daemon flags.
	args     func(dir string) []string
	fuseOnly bool
	// want is what the daemon's output must mention.
	want string
	// lenient accepts a daemon that mounts, as long as its reads fail.
	lenient bool
}

// TestConfigReject starts daemons on broken configs and arguments. Each
// exits non-zero within seconds, names what is wrong, and leaves no mount.
// A local backend directory that does not exist is the exception: the
// backend opens blobs lazily, so the daemon may mount, and then every read
// must fail.
func TestConfigReject(t *testing.T) {
	t.Parallel()
	img := fixture.Get(t, "zstd-4k")
	cases := []rejectCase{{
		name: "unknown-field",
		edit: func(cfg map[string]any, _ string) { cfg["no_such_field"] = true },
		want: "no_such_field",
	}, {
		name: "unknown-backend",
		edit: func(cfg map[string]any, _ string) {
			cfg["backend"] = map[string]any{"type": "no_such_backend", "config": map[string]any{}}
		},
		want: "no_such_backend",
	}, {
		name: "zero-concurrent-blobs",
		edit: func(cfg map[string]any, _ string) { section(cfg, "prefetch")["concurrent_blob_count"] = 0 },
		want: "concurrent_blob_count",
	}, {
		name: "invalid-retry-interval",
		edit: func(cfg map[string]any, _ string) {
			section(cfg, "prefetch")["retry_interval"] = "not-a-duration"
		},
		want: "retry_interval",
	}, {
		name:      "missing-bootstrap",
		bootstrap: "missing.bootstrap",
		want:      "No such file or directory",
	}, {
		name:     "missing-blob-dir-flag",
		args:     func(dir string) []string { return []string{"--blob-dir", filepath.Join(dir, "missing-blobs")} },
		fuseOnly: true,
		want:     "missing-blobs",
	}, {
		name: "missing-backend-dir",
		edit: func(cfg map[string]any, dir string) {
			cfg["backend"] = map[string]any{"type": "local", "config": map[string]any{"dir": filepath.Join(dir, "missing-blobs")}}
		},
		lenient: true,
	}}
	for _, a := range adapters {
		for _, c := range cases {
			if c.fuseOnly && a.Name() != "fuse" {
				continue
			}
			t.Run(a.Name()+"/"+c.name, func(t *testing.T) {
				t.Parallel()
				configReject(t, a, img, c)
			})
		}
	}
}

func configReject(t *testing.T, a mount.Adapter, img fixture.Image, c rejectCase) {
	a.Require(t)
	dir := env.WorkDir(t)
	mnt, export, cache := filepath.Join(dir, "mnt"), filepath.Join(dir, "export"), filepath.Join(dir, "cache")
	for _, d := range []string{mnt, export, cache} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("create %s: %v", d, err)
		}
	}

	cfg := map[string]any{
		"backend":  map[string]any{"type": "local", "config": map[string]any{"dir": img.BlobDir}},
		"storage":  map[string]any{"dir": cache},
		"prefetch": map[string]any{"scope": "none"},
	}
	if c.edit != nil {
		c.edit(cfg, dir)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	config := filepath.Join(dir, "config.json")
	if err := os.WriteFile(config, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	bootstrap := img.Bootstrap
	if c.bootstrap != "" {
		bootstrap = filepath.Join(dir, c.bootstrap)
	}

	name := "nydus-" + a.Name()
	args := []string{a.Name(),
		"--bootstrap", bootstrap,
		"--config", config,
		"--mountpoint", mnt,
		"--apiserver", "unix://" + mount.SocketPath(t),
	}
	if a.Name() == "fileio" {
		args = append(args, "--export-dir", export)
	}
	if c.args != nil {
		args = append(args, c.args(dir)...)
	}
	args = append(args, "--log-level", "info", "--log-dir", mount.LogDir(dir, name))
	d := mount.StartDaemon(t, dir, name, env.Nydus(t), args...)
	// Should the daemon mount after all, unmount before it is stopped.
	t.Cleanup(func() {
		for _, p := range []string{mnt, export} {
			mount.Unmount(p)
		}
	})

	mounted := false
	for deadline := time.Now().Add(rejectTimeout); d.Alive() && time.Now().Before(deadline); {
		if c.lenient && mount.IsMountpoint(mnt) {
			mounted = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if mounted {
		r := readWithin(t, mnt, lookup(t, img, primeFile), rejectTimeout)
		t.Logf("accepted at startup, reads fail later: %s", r)
		expectFailed(t, r)
		expectNotWrong(t, r)
		return
	}
	if d.Alive() {
		t.Fatalf("%s still running %s after starting on a broken config", name, rejectTimeout)
	}
	if code := d.ExitCode(); code <= 0 {
		t.Errorf("want a non-zero exit code, got %d", code)
	}
	if c.want != "" {
		if out := d.Log() + d.FileLog(); !strings.Contains(out, c.want) {
			t.Errorf("the daemon's output does not mention %q:\n%s", c.want, out)
		}
	}
	expectNoMounts(t, dir, mnt, export)
}

// section returns the object cfg[key], creating it if needed.
func section(cfg map[string]any, key string) map[string]any {
	s, ok := cfg[key].(map[string]any)
	if !ok {
		s = map[string]any{}
		cfg[key] = s
	}
	return s
}
