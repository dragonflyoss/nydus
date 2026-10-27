package continuity

import (
	"testing"
)

func TestLiveOwnerWithoutControl(t *testing.T) {
	t.Parallel()
	t.Run("missing", func(t *testing.T) { testFuseLiveOwnerWithoutControl(t, false) })
	t.Run("unresponsive", func(t *testing.T) { testFuseLiveOwnerWithoutControl(t, true) })
}
