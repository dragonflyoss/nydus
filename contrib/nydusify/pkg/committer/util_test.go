package committer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCounterWriteAndSize(t *testing.T) {
	var counter Counter
	require.Equal(t, int64(0), counter.Size())

	n, err := counter.Write([]byte("abc"))
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, int64(3), counter.Size())

	n, err = counter.Write([]byte("defg"))
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.Equal(t, int64(7), counter.Size())
}
