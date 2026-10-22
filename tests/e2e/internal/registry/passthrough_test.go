package registry

import (
	"bytes"
	"crypto/rand"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPassthrough checks that the proxy serves a blob unchanged when no fault
// matches it, and flips exactly the requested bit when one does.
func TestPassthrough(t *testing.T) {
	t.Parallel()
	data := make([]byte, 64<<10)
	_, err := rand.Read(data)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "blob")
	require.NoError(t, os.WriteFile(path, data, 0o644))

	r := Start(t)
	digest := r.PushBlob(t, "passthrough", path)
	get := func() []byte {
		resp, err := http.Get(r.URL + "/v2/passthrough/blobs/sha256:" + digest)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return body
	}

	require.True(t, bytes.Equal(data, get()), "an unfaulted blob GET changed the bytes")

	at := int64(4097)
	r.Faults.Set(Fault{FlipBit: &at, Times: 1})
	want := bytes.Clone(data)
	want[at] ^= 1
	require.True(t, bytes.Equal(want, get()), "FlipBit must flip only the bit at %d", at)
	require.True(t, bytes.Equal(data, get()), "a spent fault must stop applying")
}
