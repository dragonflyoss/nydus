package contract

import (
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
)

func TestFUSE(t *testing.T) {
	t.Parallel()
	Run(t, mount.FUSE{})
}

func TestFileio(t *testing.T) {
	t.Parallel()
	Run(t, mount.Fileio{})
}
