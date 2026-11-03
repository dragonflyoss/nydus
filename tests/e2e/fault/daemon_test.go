package fault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/util/proc"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestDaemonCrash(t *testing.T) {
	t.Parallel()
	img := image{fixture.Get(t, "zstd-4k")}

	for _, a := range adapters {
		t.Run(a.Name(), func(t *testing.T) {
			t.Parallel()
			m := img.mount(t, a, mount.Options{})
			rd := m.startReaders(t, img.dataFiles(t), 8)
			rd.waitOK(t, 8, readTimeout)

			kids := proc.Children(m.Daemon.Pid())
			m.Daemon.Kill()
			killed := time.Now()
			rd.stopWithin(t, 10*time.Second)
			t.Logf("readers drained %s after the kill", time.Since(killed).Round(time.Millisecond))

			r := img.lookup(t, bigFile).readWithin(t, m.Root, 10*time.Second)
			t.Logf("read after the kill: %s", r)
			r.expectNotWrong(t)

			if a.Name() == "fuse" {
				r.expectFailed(t)

				if r.err != nil {
					var errno unix.Errno
					if !assert.ErrorAs(t, r.err, &errno) {
						t.FailNow()
					}

					assert.Contains(t, []unix.Errno{unix.ENOTCONN, unix.ECONNABORTED, unix.EIO}, errno)
				}
			}

			m.Unmount()
			mount.ExpectNoMounts(t, m.Dir)
			proc.ExpectGone(t, kids, exitTimeout)

			again := img.mount(t, a, mount.Options{CacheDir: m.CacheDir})
			fstest.VerifyMount(t, again.Root, img.Want, img.Compare())
		})
	}
}

func TestSigterm(t *testing.T) {
	t.Parallel()
	img := image{fixture.Get(t, "zstd-4k")}

	cases := []struct {
		a    mount.Adapter
		busy bool
	}{
		{mount.FUSE{}, false},
		{mount.FUSE{}, true},
		{mount.Fileio{}, false},
	}

	for _, c := range cases {
		name := c.a.Name() + "/Idle"
		if c.busy {
			name = c.a.Name() + "/Busy"
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := img.mount(t, c.a, mount.Options{})
			m.prime(t)

			var rd *readers
			if c.busy {
				rd = m.startReaders(t, img.dataFiles(t), 16)
				rd.waitOK(t, 16, readTimeout)

				held, err := os.Open(m.Path(img.dataFiles(t)[0].rel))
				if !assert.NoError(t, err) {
					t.FailNow()
				}

				defer func() { _ = held.Close() }()
			}

			kids := proc.Children(m.Daemon.Pid())
			m.Daemon.Signal(unix.SIGTERM)
			m.mustExit(t, exitTimeout)

			if rd != nil {
				rd.stopWithin(t, 10*time.Second)
			}

			proc.ExpectGone(t, kids, exitTimeout)

			assert.Zero(t, m.Daemon.ExitCode())
			mount.ExpectNoMounts(t, m.Dir)
		})
	}
}

func TestExternalUmount(t *testing.T) {
	t.Parallel()
	img := image{fixture.Get(t, "zstd-4k")}

	cases := []struct {
		name     string
		flags    int
		holdOpen bool
	}{
		{"Umount", 0, false},
		{"Lazy", unix.MNT_DETACH, false},
		{"LazyOpenFile", unix.MNT_DETACH, true},
	}

	for _, a := range adapters {
		for _, c := range cases {
			t.Run(a.Name()+"/"+c.name, func(t *testing.T) {
				t.Parallel()
				fileio := a.Name() == "fileio"
				m := img.mount(t, a, mount.Options{})
				m.prime(t)
				kids := proc.Children(m.Daemon.Pid())
				big := img.lookup(t, bigFile)

				var held *os.File
				if c.holdOpen {
					f, err := os.Open(m.Path(big.rel))
					if !assert.NoError(t, err) {
						t.FailNow()
					}

					held = f
					defer func() { _ = held.Close() }()
				}

				if err := unix.Unmount(m.Root, c.flags); !assert.NoError(t, err) {
					t.FailNow()
				}

				if fileio {
					if !assert.False(t, mount.IsMountpoint(m.Root)) {
						t.FailNow()
					}
					if !assert.False(t, m.Daemon.WaitExit(5*time.Second)) {
						t.FailNow()
					}
				}

				if held != nil {
					big.judge(t, readTimeout, func() (string, error) { return fstest.HashCold(held) }).expectCorrect(t)
					assert.True(t, m.Daemon.Alive())

					if err := held.Close(); !assert.NoError(t, err) {
						t.FailNow()
					}
				}

				if fileio {
					m.Daemon.Signal(unix.SIGTERM)
				}

				m.mustExit(t, exitTimeout)
				assert.Zero(t, m.Daemon.ExitCode())
				mount.ExpectNoMounts(t, m.Dir)
				proc.ExpectGone(t, kids, exitTimeout)
			})
		}
	}
}

type rejectCase struct {
	name      string
	edit      func(cfg map[string]any, dir string)
	bootstrap string
	args      func(dir string) []string
	fuseOnly  bool
	want      string
	lenient   bool
}

func TestConfigReject(t *testing.T) {
	t.Parallel()
	img := image{fixture.Get(t, "zstd-4k")}

	cases := []rejectCase{{
		name: "UnknownField",
		edit: func(cfg map[string]any, _ string) { cfg["no_such_field"] = true },
		want: "no_such_field",
	}, {
		name: "UnknownBackend",
		edit: func(cfg map[string]any, _ string) {
			cfg["backend"] = map[string]any{"type": "no_such_backend", "config": map[string]any{}}
		},
		want: "no_such_backend",
	}, {
		name: "ZeroConcurrentBlobs",
		edit: func(cfg map[string]any, _ string) { section(cfg, "prefetch")["concurrent_blob_count"] = 0 },
		want: "concurrent_blob_count",
	}, {
		name: "InvalidRetryInterval",
		edit: func(cfg map[string]any, _ string) {
			section(cfg, "prefetch")["retry_interval"] = "not-a-duration"
		},
		want: "retry_interval",
	}, {
		name:      "MissingBootstrap",
		bootstrap: "missing.bootstrap",
		want:      "No such file or directory",
	}, {
		name:     "MissingBlobDirFlag",
		args:     func(dir string) []string { return []string{"--blob-dir", filepath.Join(dir, "missing-blobs")} },
		fuseOnly: true,
		want:     "missing-blobs",
	}, {
		name: "MissingBackendDir",
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
				c.configReject(t, a, img)
			})
		}
	}
}

func (c rejectCase) configReject(t *testing.T, a mount.Adapter, img image) {
	a.Require(t)
	dir := env.WorkDir(t)

	mnt, export, cache := filepath.Join(dir, "mnt"), filepath.Join(dir, "export"), filepath.Join(dir, "cache")
	for _, d := range []string{mnt, export, cache} {
		if err := os.MkdirAll(d, 0o755); !assert.NoError(t, err) {
			t.FailNow()
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
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	config := filepath.Join(dir, "config.json")
	if err := os.WriteFile(config, data, 0o644); !assert.NoError(t, err) {
		t.FailNow()
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

	t.Cleanup(func() {
		for _, p := range []string{mnt, export} {
			mount.Unmount(p)
		}
	})

	if !assert.Eventually(t, func() bool {
		return !d.Alive() || (c.lenient && mount.IsMountpoint(mnt))
	}, rejectTimeout, 50*time.Millisecond) {
		t.FailNow()
	}

	if d.Alive() {
		r := img.lookup(t, primeFile).readWithin(t, mnt, rejectTimeout)
		t.Logf("accepted at startup, reads fail later: %s", r)
		r.expectFailed(t)
		r.expectNotWrong(t)
		return
	}

	assert.Positive(t, d.ExitCode())

	if c.want != "" {
		out := d.Log() + d.FileLog()
		assert.Contains(t, out, c.want)
	}

	mount.ExpectNoMounts(t, dir)
}

func section(cfg map[string]any, key string) map[string]any {
	s, ok := cfg[key].(map[string]any)
	if !ok {
		s = map[string]any{}
		cfg[key] = s
	}

	return s
}
