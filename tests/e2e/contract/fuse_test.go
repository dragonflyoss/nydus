package contract

import (
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/contract"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
)

func TestFUSE(t *testing.T) {
	t.Parallel()
	contract.Run(t, mount.FUSE{})
}
