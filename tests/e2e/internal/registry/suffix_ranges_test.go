package registry

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSuffixRanges(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "blob")
	require.NoError(t, os.WriteFile(path, []byte("0123456789"), 0o644))
	r := Start(t)
	digest := r.PushBlob(t, "ranges", path)
	for _, tc := range []struct {
		header, body, contentRange string
		status                     int
	}{
		{"bytes=-4", "6789", "bytes 6-9/10", http.StatusPartialContent},
		{"bytes=-20", "0123456789", "bytes 0-9/10", http.StatusPartialContent},
		{"bytes=2-4", "234", "bytes 2-4/10", http.StatusPartialContent},
		{"bytes=-0", "", "", http.StatusRequestedRangeNotSatisfiable},
		{"bytes=-bad", "", "", http.StatusRequestedRangeNotSatisfiable},
	} {
		t.Run(tc.header, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, r.URL+"/v2/ranges/blobs/sha256:"+digest, nil)
			require.NoError(t, err)
			req.Header.Set("Range", tc.header)
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, tc.status, resp.StatusCode)
			if tc.status == http.StatusPartialContent {
				require.Equal(t, tc.body, string(body))
				require.Equal(t, tc.contentRange, resp.Header.Get("Content-Range"))
			}
		})
	}
	require.Equal(t, "bytes=-4", r.Faults.Requests()[len(r.Faults.Requests())-5].Range)
}
