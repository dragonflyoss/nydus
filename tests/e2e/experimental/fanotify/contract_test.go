package fanotify

import (
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/contract"
)

// TestContract runs the filesystem contract through fanotify.
func TestContract(t *testing.T) {
	t.Parallel()
	contract.Run(t, Fanotify{})
}
