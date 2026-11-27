package kernel

import (
	"context"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
)

const (
	stressReaders = 16
	stressMaxRead = 2 << 20
)

func TestStress(t *testing.T) {
	t.Parallel()
	duration := env.Duration(t, "NYDUS_E2E_SOAK_DURATION", 30*time.Second)

	for _, name := range []string{"erofs-none", "erofs-lz4", "erofs-zstd"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mount.MustHaveEROFS(t, fixture.MustLayout(t, name))
			img := fixture.Get(t, name)
			mnt := mountEROFS(t, img.Bootstrap, img.Blobs)

			var files []fstest.Entry

			for _, e := range img.Want {
				if e.Type == fstest.TypeReg && e.Size > 0 {
					files = append(files, e)
				}
			}

			seed := uint64(time.Now().UnixNano())
			t.Logf("reading %d files with seed %d", len(files), seed)
			ctx, cancel := context.WithTimeout(t.Context(), duration)
			defer cancel()
			errs := make(chan error, stressReaders+1)

			for i := range stressReaders {
				go func() {
					rng := rand.New(rand.NewPCG(seed, uint64(i)))
					var err error

					for err == nil && ctx.Err() == nil {
						f := files[rng.IntN(len(files))]
						off := rng.Int64N(f.Size)
						n := min(1+rng.Int64N(stressMaxRead), f.Size-off)
						err = fstest.SameRangeCold(filepath.Join(img.Source, string(f.Path)), filepath.Join(mnt, string(f.Path)), off, n)
					}

					errs <- err
				}()
			}

			go func() {
				var err error

				for err == nil && ctx.Err() == nil {
					err = os.WriteFile("/proc/sys/vm/drop_caches", []byte("3"), 0)
					time.Sleep(time.Second)
				}

				errs <- err
			}()

			for !t.Failed() && ctx.Err() == nil {
				fstest.VerifyMount(t, mnt, img.Want, img.Compare())
			}

			for range cap(errs) {
				assert.NoError(t, <-errs)
			}
		})
	}
}
