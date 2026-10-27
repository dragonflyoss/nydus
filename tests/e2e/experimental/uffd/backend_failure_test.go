package uffd

import (
	"os"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/stretchr/testify/require"
)

// TestBackendFailure breaks the local backend before the service starts: a
// cold FETCH fails closed within its deadline, returning no range at all,
// fails the same way again because nothing unverified was marked ready,
// and the service keeps answering new sessions.
func TestBackendFailure(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		damage func(t *testing.T, blob string)
	}{
		{"Truncated", func(t *testing.T, blob string) { require.NoError(t, os.Truncate(blob, 1024)) }},
		{"Removed", func(t *testing.T, blob string) { require.NoError(t, os.Remove(blob)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			img := fixture.Copy(t, standardImage(t))
			for _, blob := range img.Blobs {
				tc.damage(t, blob)
			}
			s := startService(t, img)
			deviceSize := s.deviceSize(t)

			for range 2 {
				conn := dial(t, s.socket)
				send(t, conn, msgFetch, encodeRange(0, deviceSize))
				requireFailsClosed(t, conn)
				_ = conn.Close()
			}
			requireAlive(t, s, deviceSize)
		})
	}
}
