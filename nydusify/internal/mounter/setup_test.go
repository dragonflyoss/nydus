package mounter

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/nydusify/internal/nydusfs"
	"github.com/stretchr/testify/require"
)

func TestMounterSetupFailures(t *testing.T) {
	for _, opt := range []MountOption{{}, {Target: "example.test/image:tag"}} {
		_, err := NewMounter(opt)
		require.Error(t, err)
	}
	for _, phase := range []string{"content", "scratch", "target"} {
		t.Run(phase, func(t *testing.T) {
			work := t.TempDir()
			m, err := NewMounter(MountOption{Target: "://invalid", WorkDir: work, Mountpoint: t.TempDir()})
			require.NoError(t, err)
			require.NotNil(t, m.opt.PlatformMC)
			require.Equal(t, "info", m.opt.LogLevel)
			want := "load target"
			if phase != "target" {
				path := filepath.Join(work, phase)
				want = "create dir"
				require.NoError(t, os.WriteFile(path, nil, 0o600))
			}
			require.ErrorContains(t, m.Mount(context.Background()), want)
		})
	}
	m := Mounter{}
	require.ErrorContains(t, m.mountNydus(context.Background(), nil, nil, &nydusfs.Image{}, t.TempDir()), "missing its bootstrap")
}
