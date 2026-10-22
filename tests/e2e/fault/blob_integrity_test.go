package fault

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestBlobIntegrity(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
	image := fixture.Copy(t, fixture.Get(t, "none-4k"))
	want, err := os.ReadFile(filepath.Join(image.Source, forgedFile))
	require.NoError(t, err)
	blob, err := os.ReadFile(image.Blob())
	require.NoError(t, err)
	window := want[forgedOffset : forgedOffset+64]
	at := bytes.Index(blob, window)
	require.NotEqual(t, -1, at)
	require.False(t, bytes.Contains(blob[at+1:], window))
	blob[at] ^= 0xff
	require.NoError(t, os.WriteFile(image.Blob(), blob, 0o644))
	want[forgedOffset] ^= 0xff

	for _, skip := range []bool{false, true} {
		name := "default"
		if skip {
			name = "skip-checksums"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := mount.Mount(t, mount.FUSE{}, image, mount.Options{Config: func(c *mount.Config) {
				if skip {
					c.Storage.SkipVerifyChecksums = mount.Ptr(true)
				}
			}})
			got, err := os.ReadFile(filepath.Join(m.Root, forgedFile))
			if skip {
				require.NoError(t, err)
				require.Equal(t, want, got, "explicit opt-out serves the corrupted bytes")
			} else {
				require.ErrorIs(t, err, unix.EIO)
				require.Positive(t, m.API.Metrics(t).Sum("nydus_cache_write_failure_total", `reason="checksum"`))
			}
		})
	}
}
