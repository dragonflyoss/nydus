package external

import (
	"context"
	"testing"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/snapshotter/external/backend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockChunk struct {
	mock.Mock
}

func (m *MockChunk) ObjectID() uint32 {
	args := m.Called()
	return args.Get(0).(uint32)
}

func (m *MockChunk) ObjectContent() interface{} {
	args := m.Called()
	return args.Get(0)
}

func (m *MockChunk) ObjectOffset() uint64 {
	args := m.Called()
	return args.Get(0).(uint64)
}

func (m *MockChunk) FilePath() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockChunk) LimitChunkSize() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockChunk) BlobDigest() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockChunk) BlobSize() string {
	args := m.Called()
	return args.String(0)
}

type MockBackend struct {
	mock.Mock
}

func (m *MockBackend) Backend(ctx context.Context) (*backend.Backend, error) {
	args := m.Called(ctx)
	return args.Get(0).(*backend.Backend), args.Error(1)
}

func TestNewGenerators(t *testing.T) {
	t.Run("normal case", func(t *testing.T) {
		chunk := &MockChunk{}
		chunk.On("ObjectID").Return(uint32(1))
		chunk.On("ObjectContent").Return("content")
		chunk.On("ObjectOffset").Return(uint64(100))
		chunk.On("BlobDigest").Return("digest")
		chunk.On("BlobSize").Return("1024")

		ret := backend.Result{
			Chunks: []backend.Chunk{chunk},
			Backend: backend.Backend{
				Version: "1.0",
			},
			Files: []backend.FileAttribute{
				{
					RelativePath: "file1",
					FileSize:     1024,
				},
			},
		}

		generators, err := NewGenerators(ret)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(generators.Objects))
		assert.Equal(t, 1, len(generators.Chunks))
		assert.Equal(t, "1.0", generators.Backend.Version)
	})

	t.Run("empty input", func(t *testing.T) {
		ret := backend.Result{
			Chunks:  []backend.Chunk{},
			Backend: backend.Backend{},
			Files:   []backend.FileAttribute{},
		}

		generators, err := NewGenerators(ret)
		assert.NoError(t, err)
		assert.Equal(t, 0, len(generators.Objects))
		assert.Equal(t, 0, len(generators.Chunks))
	})
}

func TestGenerate(t *testing.T) {
	t.Run("normal case", func(t *testing.T) {
		generators := &Generators{
			MetaGenerator: MetaGenerator{
				Chunks: []backend.ChunkOndisk{
					{
						ObjectIndex:  0,
						ObjectOffset: 100,
					},
				},
				Objects: []backend.ObjectOndisk{
					{
						EntrySize:   10,
						EncodedData: []byte("encoded"),
					},
				},
			},
			Backend: backend.Backend{
				Version: "1.0",
			},
			Files: []backend.FileAttribute{
				{
					RelativePath: "file1",
					FileSize:     1024,
				},
			},
		}

		result, err := generators.Generate()
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "1.0", result.Backend.Version)
		assert.Equal(t, 1, len(result.Files))
	})
}

func TestMetaGeneratorGenerate(t *testing.T) {
	t.Run("normal case", func(t *testing.T) {
		generator := &MetaGenerator{
			Chunks: []backend.ChunkOndisk{
				{
					ObjectIndex:  0,
					ObjectOffset: 100,
				},
			},
			Objects: []backend.ObjectOndisk{
				{
					EntrySize:   10,
					EncodedData: []byte("encoded"),
				},
			},
		}

		data, err := generator.Generate()
		assert.NoError(t, err)
		assert.NotNil(t, data)
		assert.Greater(t, len(data), 0)
	})

	t.Run("empty input", func(t *testing.T) {
		generator := &MetaGenerator{}

		data, err := generator.Generate()
		assert.NoError(t, err)
		assert.NotNil(t, data)
		assert.Greater(t, len(data), 0)
	})
}
