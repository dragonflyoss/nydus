package backend

import (
	"fmt"
	"reflect"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestLayout(t *testing.T) {
	require.Equal(t, fmt.Sprintf("%d", 4096), fmt.Sprintf("%d", unsafe.Sizeof(Header{})))
	require.Equal(t, fmt.Sprintf("%d", 256), fmt.Sprintf("%d", unsafe.Sizeof(ChunkMeta{})))
	require.Equal(t, fmt.Sprintf("%d", 256), fmt.Sprintf("%d", unsafe.Sizeof(ObjectMeta{})))
}

func TestSplitObjectOffsets(t *testing.T) {
	tests := []struct {
		name      string
		totalSize int64
		chunkSize int64
		expected  []uint64
	}{
		{
			name:      "Chunk size is less than or equal to zero",
			totalSize: 100,
			chunkSize: 0,
			expected:  []uint64{},
		},
		{
			name:      "Total size is zero",
			totalSize: 0,
			chunkSize: 10,
			expected:  []uint64{},
		},
		{
			name:      "Total size is divisible by chunk size",
			totalSize: 100,
			chunkSize: 10,
			expected:  []uint64{0, 10, 20, 30, 40, 50, 60, 70, 80, 90},
		},
		{
			name:      "Total size is not divisible by chunk size",
			totalSize: 105,
			chunkSize: 10,
			expected:  []uint64{0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SplitObjectOffsets(tt.totalSize, tt.chunkSize)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("SplitObjectOffsets(%d, %d) = %v; want %v", tt.totalSize, tt.chunkSize, result, tt.expected)
			}
		})
	}
}
