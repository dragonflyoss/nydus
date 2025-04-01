package external

import (
	"bytes"
	"encoding/binary"
	"unsafe"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/snapshotter/external/backend"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v5"
)

type Result struct {
	Meta    []byte
	Backend backend.Backend
	Files   []backend.FileAttribute
}

type MetaGenerator struct {
	backend.Header
	backend.ChunkMeta
	Chunks []backend.ChunkOndisk
	backend.ObjectMeta
	ObjectOffsets []backend.ObjectOffset
	Objects       []backend.ObjectOndisk
}

type Generator interface {
	Generate() error
}

type Generators struct {
	MetaGenerator
	Backend backend.Backend
	Files   []backend.FileAttribute
}

func NewGenerators(ret backend.Result) (*Generators, error) {
	objects := []backend.ObjectOndisk{}
	chunks := []backend.ChunkOndisk{}
	objectMap := make(map[uint32]uint32) // object id -> object index

	for _, chunk := range ret.Chunks {
		objectID := chunk.ObjectID()
		objectIndex, ok := objectMap[objectID]
		if !ok {
			objectIndex = uint32(len(objects))
			objectMap[objectID] = objectIndex
			encoded, err := msgpack.Marshal(chunk.ObjectContent())
			if err != nil {
				return nil, errors.Wrap(err, "encode to msgpack format")
			}
			objects = append(objects, backend.ObjectOndisk{
				EntrySize:   uint32(len(encoded)),
				EncodedData: encoded[:],
			})
		}
		chunks = append(chunks, backend.ChunkOndisk{
			ObjectIndex:  objectIndex,
			ObjectOffset: chunk.ObjectOffset(),
		})
	}

	return &Generators{
		MetaGenerator: MetaGenerator{
			Chunks:  chunks,
			Objects: objects,
		},
		Backend: ret.Backend,
		Files:   ret.Files,
	}, nil
}

func (generators *Generators) Generate() (*Result, error) {
	meta, err := generators.MetaGenerator.Generate()
	if err != nil {
		return nil, errors.Wrap(err, "generate backend meta")
	}
	return &Result{
		Meta:    meta,
		Backend: generators.Backend,
		Files:   generators.Files,
	}, nil
}

func (generator *MetaGenerator) Generate() ([]byte, error) {
	// prepare data
	chunkMetaOffset := uint32(unsafe.Sizeof(generator.Header))
	generator.ChunkMeta.EntryCount = uint32(len(generator.Chunks))
	generator.ChunkMeta.EntrySize = uint32(unsafe.Sizeof(backend.ChunkOndisk{}))
	objectMetaOffset := chunkMetaOffset + uint32(unsafe.Sizeof(generator.ChunkMeta)) + generator.ChunkMeta.EntryCount*generator.ChunkMeta.EntrySize
	generator.Header = backend.Header{
		Magic:            backend.MetaMagic,
		Version:          backend.MetaVersion,
		ChunkMetaOffset:  chunkMetaOffset,
		ObjectMetaOffset: objectMetaOffset,
	}

	generator.ObjectMeta.EntryCount = uint32(len(generator.Objects))
	objectOffsets := []backend.ObjectOffset{}
	objectOffset := backend.ObjectOffset(objectMetaOffset + uint32(unsafe.Sizeof(generator.ObjectMeta)) + 4*generator.ObjectMeta.EntryCount)
	var lastEntrySize uint32
	fixedEntrySize := true
	for _, object := range generator.Objects {
		if lastEntrySize > 0 && lastEntrySize != object.EntrySize {
			fixedEntrySize = false
		}
		lastEntrySize = object.EntrySize
		objectOffsets = append(objectOffsets, objectOffset)
		objectOffset += backend.ObjectOffset(uint32(unsafe.Sizeof(object.EntrySize)) + uint32(len(object.EncodedData)))
	}
	if fixedEntrySize && len(generator.Objects) > 0 {
		generator.ObjectMeta.EntrySize = generator.Objects[0].EntrySize
	}
	generator.ObjectOffsets = objectOffsets

	// dump bytes
	var buf bytes.Buffer

	if err := binary.Write(&buf, binary.LittleEndian, generator.Header); err != nil {
		return nil, errors.Wrap(err, "dump")
	}
	if err := binary.Write(&buf, binary.LittleEndian, generator.ChunkMeta); err != nil {
		return nil, errors.Wrap(err, "dump")
	}

	for _, chunk := range generator.Chunks {
		if err := binary.Write(&buf, binary.LittleEndian, chunk); err != nil {
			return nil, errors.Wrap(err, "dump")
		}
	}
	if err := binary.Write(&buf, binary.LittleEndian, generator.ObjectMeta); err != nil {
		return nil, errors.Wrap(err, "dump")
	}
	for _, objectOffset := range generator.ObjectOffsets {
		if err := binary.Write(&buf, binary.LittleEndian, objectOffset); err != nil {
			return nil, errors.Wrap(err, "dump")
		}
	}
	for _, object := range generator.Objects {
		if err := binary.Write(&buf, binary.LittleEndian, object.EntrySize); err != nil {
			return nil, errors.Wrap(err, "dump")
		}
		if err := binary.Write(&buf, binary.LittleEndian, object.EncodedData); err != nil {
			return nil, errors.Wrap(err, "dump")
		}
	}

	return buf.Bytes(), nil
}
