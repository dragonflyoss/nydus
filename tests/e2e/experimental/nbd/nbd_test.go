package nbd

import (
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/experimental/transport"
	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
)

const repo = "nydus-e2e/nbd"

func TestConcurrency(t *testing.T) {
	t.Parallel()
	transport.Concurrency(t, NBD{}, repo)
}

func TestPersistence(t *testing.T) {
	t.Parallel()
	transport.Persistence(t, NBD{}, repo)
}

func TestDemandPaging(t *testing.T) {
	t.Parallel()
	transport.DemandPaging(t, NBD{}, repo, func(t *testing.T, m *mount.Mounted, cache string) {
		env.Run(t, env.LookPath(t, "udevadm"), "settle", "--timeout=10")
		log := m.Daemon.Log()
		if !assert.Contains(t, log, "nbd service attached to") {
			t.FailNow()
		}

		assert.Contains(t, log, "mounted ")

		for _, f := range mount.CacheFiles(cache) {
			assert.Less(t, mount.Allocated(f), int64(16<<20))
		}
	})
}
