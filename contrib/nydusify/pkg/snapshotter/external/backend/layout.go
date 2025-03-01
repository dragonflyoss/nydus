package backend

const MetaMagic uint32 = 0x0AF5_E1E2
const MetaVersion uint32 = 0x0000_0001

// Layout
//
// header: magic | version | chunk_meta_offset | object_meta_offset
// chunks: chunk_meta | chunk | chunk | ...
// objects: object_meta | [object_offsets] | object | object | ...

// 4096 bytes
type Header struct {
	Magic   uint32
	Version uint32

	ChunkMetaOffset  uint32
	ObjectMetaOffset uint32

	Reserved2 [4080]byte
}

// 256 bytes
type ChunkMeta struct {
	EntryCount uint32
	EntrySize  uint32

	Reserved [248]byte
}

// 256 bytes
type ObjectMeta struct {
	EntryCount uint32
	// = 0 means indeterminate entry size, and len(object_offsets) > 0.
	// > 0 means fixed entry size, and len(object_offsets) == 0.
	EntrySize uint32

	Reserved [248]byte
}

// 8 bytes
type ChunkOndisk struct {
	ObjectIndex  uint32
	Reserved     [4]byte
	ObjectOffset uint64
}

// 4 bytes
type ObjectOffset uint32

// Size depends on different external backend implementations
type ObjectOndisk struct {
	EntrySize   uint32
	EncodedData []byte
}
