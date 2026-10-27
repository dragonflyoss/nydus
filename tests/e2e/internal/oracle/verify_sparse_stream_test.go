package oracle

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifySparseStream(t *testing.T) {
	t.Parallel()
	data := make([]byte, 2<<20)
	want := Entry{Type: "reg", Size: int64(len(data))}
	require.NoError(t, verifySparseStream(bytes.NewReader(data), want), "all-hole files have no data extents")
	require.Error(t, verifySparseStream(bytes.NewReader(data), Entry{}), "a missing oracle is not an all-hole file")
	require.Error(t, verifySparseStream(bytes.NewReader(data[:len(data)-1]), want), "truncated holes must fail")
	data[len(data)-1] = 1
	require.ErrorContains(t, verifySparseStream(bytes.NewReader(data), want), "not zeros")
}
