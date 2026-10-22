package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
)

func response(t *testing.T, socket, method, path string) *http.Response {
	t.Helper()
	c, err := net.DialTimeout("unix", socket, time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = fmt.Fprintf(c, "%s %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", method, path)
	require.NoError(t, err)
	r, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: method})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Body.Close() })
	_, err = io.ReadAll(r.Body)
	require.NoError(t, err)
	return r
}

func trace(t *testing.T, api *mount.API) []json.RawMessage {
	t.Helper()
	body, err := api.Get("/trace")
	require.NoError(t, err)
	var result struct {
		Version  int               `json:"version"`
		Patterns []json.RawMessage `json:"patterns"`
	}
	require.NoError(t, json.Unmarshal(body, &result))
	require.Equal(t, 1, result.Version)
	return result.Patterns
}
