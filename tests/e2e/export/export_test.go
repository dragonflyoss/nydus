package export

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
)

func TestExport(t *testing.T) {
	t.Parallel()
	nydus := env.Nydus(t)
	names := []string{fixture.HugePrefix + "zstd"}

	for _, layout := range fixture.Layouts {
		names = append(names, layout.Name)
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			img := fixture.Get(t, name)
			fstest.VerifyExport(t, nydus, img.Blob(t), img.Want)
		})
	}
}

func TestExportRoundtrip(t *testing.T) {
	t.Parallel()
	for _, layout := range fixture.Layouts {
		if !layout.Tar {
			continue
		}

		t.Run(layout.Name, func(t *testing.T) {
			t.Parallel()
			img := fixture.Get(t, layout.Name)

			once := rebuild(t, img.Blob(t), layout)
			once.Want = img.Want
			m := mount.Mount(t, mount.FUSE{}, once, mount.Options{Mode: mount.Blob})
			fstest.VerifyMount(t, m.Root, img.Want, fstest.CompareOptions{Tar: true})
			m.Unmount()

			twice := rebuild(t, once.Blob(t), layout)
			if !assert.Equal(t, fstest.FileSHA256(t, once.Bootstrap), fstest.FileSHA256(t, twice.Bootstrap)) {
				t.FailNow()
			}
			if !assert.Equal(t, filepath.Base(once.Blob(t)), filepath.Base(twice.Blob(t))) {
				t.FailNow()
			}

			t.Logf("first round trip reproduces the original image byte for byte: %v",
				fstest.FileSHA256(t, img.Bootstrap) == fstest.FileSHA256(t, once.Bootstrap))
		})
	}
}

func TestExportFailure(t *testing.T) {
	t.Parallel()
	img := fixture.Get(t, "zstd-4k")
	digest := fstest.FileSHA256(t, img.Blob(t))

	for _, tc := range []struct {
		name                       string
		corruptSource, pipe, abort bool
		output                     string
	}{
		{name: "BrokenPipe", pipe: true},
		{name: "NoSpace", output: "/dev/full"},
		{name: "CorruptSource", corruptSource: true},
		{name: "Cancellation", pipe: true, abort: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			source := img.Blob(t)
			if tc.corruptSource {
				source = filepath.Join(t.TempDir(), "bad.blob")
				if !assert.NoError(t, os.WriteFile(source, []byte("truncated"), 0o600)) {
					t.FailNow()
				}
			}

			args := []string{"export", source}
			if tc.output != "" {
				args = append(args, "--output", tc.output)
			}

			cmd := exec.CommandContext(ctx, env.Nydus(t), args...)
			cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
			cmd.WaitDelay = 5 * time.Second
			var stderr bytes.Buffer
			cmd.Stderr = &stderr

			if tc.pipe {
				r, w, err := os.Pipe()
				if !assert.NoError(t, err) {
					t.FailNow()
				}

				defer func() { _ = r.Close() }()
				defer func() { _ = w.Close() }()
				cmd.Stdout = w
				if !assert.NoError(t, cmd.Start()) {
					t.FailNow()
				}
				if !assert.NoError(t, w.Close()) {
					t.FailNow()
				}

				head := make([]byte, 512)
				_, err = io.ReadFull(r, head)
				assert.NoError(t, err)

				if tc.abort {
					cancel()
				} else {
					assert.NoError(t, r.Close())
				}
			} else {
				cmd.Stdout = io.Discard
				if !assert.NoError(t, cmd.Start()) {
					t.FailNow()
				}
			}

			err := cmd.Wait()
			var exit *exec.ExitError
			if !assert.ErrorAs(t, err, &exit) {
				t.FailNow()
			}

			if tc.abort {
				assert.Equal(t, syscall.SIGTERM, exit.Sys().(syscall.WaitStatus).Signal())
			} else {
				if !assert.NoError(t, ctx.Err()) {
					t.FailNow()
				}
				if !assert.Positive(t, exit.ExitCode()) {
					t.FailNow()
				}

				assert.NotEqual(t, 101, exit.ExitCode())
				assert.NotEmpty(t, stderr.String())
			}

			assert.Equal(t, digest, fstest.FileSHA256(t, img.Blob(t)))
		})
	}
}

func rebuild(t testing.TB, blob string, layout fixture.Layout) fixture.Image {
	t.Helper()
	dir := env.WorkDir(t)

	img := fixture.Image{
		Name:      layout.Name,
		Layout:    layout,
		Bootstrap: filepath.Join(dir, "image.bootstrap"),
		BlobDir:   filepath.Join(dir, "blobs"),
	}

	export := exec.CommandContext(t.Context(), env.Nydus(t), "export", blob)
	var stderr bytes.Buffer
	export.Stderr = &stderr
	stdout, err := export.StdoutPipe()
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.NoError(t, export.Start()) {
		t.FailNow()
	}

	t.Cleanup(func() {
		_ = export.Wait()

		if t.Failed() {
			t.Logf("nydus export %s:\n%s", blob, stderr.String())
		}
	})

	rebuilt, _ := fixture.BuildTar(t, img.BlobDir, img.Bootstrap, stdout, layout)
	img.Blobs = []string{rebuilt}
	assert.NoError(t, export.Wait())

	return img
}
