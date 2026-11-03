package ublk

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/contract"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
)

const detachTimeout = 10 * time.Second

func TestContract(t *testing.T) {
	t.Parallel()
	contract.Run(t, Ublk{})
}

func TestGracefulShutdown(t *testing.T) {
	t.Parallel()
	Ublk{}.Require(t)
	m := mount.Mount(t, Ublk{}, fixture.Get(t, "zstd-4k"), mount.Options{})
	mount.ReadAll(t, m.Root)
	dev := devicePath(m.Daemon.Log())
	if !assert.NotEmpty(t, dev) {
		t.FailNow()
	}

	mount.Unmount(m.Root)

	if !assert.False(t, mount.IsMountpoint(m.Root)) {
		t.FailNow()
	}
	if !assert.True(t, m.Daemon.Stop()) {
		t.FailNow()
	}
	if !assert.Zero(t, m.Daemon.ExitCode()) {
		t.FailNow()
	}

	assert.Contains(t, m.Daemon.Log(), "received signal")

	assert.Eventually(t, func() bool {
		_, err := os.Stat(filepath.Join("/sys/block", filepath.Base(dev)))
		return errors.Is(err, fs.ErrNotExist)
	}, detachTimeout, 100*time.Millisecond)
}
