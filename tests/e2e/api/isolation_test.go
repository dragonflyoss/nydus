package api

import (
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/stretchr/testify/require"
)

func TestIsolation(t *testing.T) {
	t.Parallel()
	img := fixture.Get(t, "zstd-4k")
	a := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
	b := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
	require.NotEqual(t, a.API.Socket, b.API.Socket)
	require.Empty(t, trace(t, a.API))
	require.Empty(t, trace(t, b.API))
	beforeB := b.API.Metrics(t).Sum("nydus_backend_read_total", `type="ondemand"`)
	oracle.VerifyMount(t, a.Root, img.Want, img.Compare())
	afterA := a.API.Metrics(t).Sum("nydus_backend_read_total", `type="ondemand"`)
	require.Positive(t, afterA)
	traceA := trace(t, a.API)
	require.NotEmpty(t, traceA)
	require.Empty(t, trace(t, b.API))
	require.Equal(t, beforeB, b.API.Metrics(t).Sum("nydus_backend_read_total", `type="ondemand"`))
	oracle.VerifyMount(t, b.Root, img.Want, img.Compare())
	require.Greater(t, b.API.Metrics(t).Sum("nydus_backend_read_total", `type="ondemand"`), beforeB)
	require.NotEmpty(t, trace(t, b.API))
	require.Equal(t, traceA, trace(t, a.API))
	require.Equal(t, afterA, a.API.Metrics(t).Sum("nydus_backend_read_total", `type="ondemand"`))
}
