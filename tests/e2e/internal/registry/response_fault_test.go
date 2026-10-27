package registry

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResponseFault(t *testing.T) {
	t.Parallel()
	faults := &Faults{}
	faults.Set(Fault{Match: func(*http.Request) bool { return true }, Times: 1,
		Headers: map[string]string{"Content-Range": ""}, ShortBody: 2})
	server := httptest.NewServer(faults.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Range", "bytes 0-5/6")
		w.Header().Set("Content-Length", "6")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.WriteString(w, "abcdef")
	})))
	defer server.Close()
	for i := 0; i < 2; i++ {
		response, err := http.Get(server.URL)
		require.NoError(t, err)
		data, err := io.ReadAll(response.Body)
		require.NoError(t, err, "short body must be a complete HTTP response, not a transport truncation")
		require.NoError(t, response.Body.Close())
		require.Equal(t, http.StatusPartialContent, response.StatusCode)
		if i == 0 {
			require.Equal(t, "ab", string(data))
			require.EqualValues(t, 2, response.ContentLength)
			require.Empty(t, response.Header.Get("Content-Range"))
		} else {
			require.Equal(t, "abcdef", string(data))
			require.Equal(t, "bytes 0-5/6", response.Header.Get("Content-Range"))
		}
	}
	require.Equal(t, 1, faults.Hits())
	require.Len(t, faults.Requests(), 2)
}
