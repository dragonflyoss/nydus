package backend

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestLayout(t *testing.T) {
	require.Equal(t, fmt.Sprintf("%d", 4096), fmt.Sprintf("%d", unsafe.Sizeof(Header{})))
	require.Equal(t, fmt.Sprintf("%d", 256), fmt.Sprintf("%d", unsafe.Sizeof(ChunkMeta{})))
	require.Equal(t, fmt.Sprintf("%d", 256), fmt.Sprintf("%d", unsafe.Sizeof(ObjectMeta{})))
}
