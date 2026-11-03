package fixture

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The blob meta (NDBLMETA) layout, as nydus-format/src/blob/metadata.rs
// writes it: a 24-byte header, then table_count tables, each 8-byte aligned
// and made of a 16-byte header, its extension and the entries.
const (
	ChunkGroupTable      = 1
	ChunkLengthTable     = 2
	ChunkGroupIndexTable = 3

	blobMetaMagic      = "NDBLMETA"
	blobMetaHeaderSize = 24
	blobMetaTableSize  = 16
)

// BlobMeta is the blob meta written beside a blob.
type BlobMeta struct {
	// Incompat is the header's feature_incompat word.
	Incompat uint32
	// tables holds each table by type, header and entries included.
	tables map[uint16][]byte
}

// BlobMetaTable is one table of a blob meta.
type BlobMetaTable struct {
	// Header is the table header with its extension.
	Header []byte
	// Entries holds Count entries of the requested size.
	Entries []byte
	Count   int
}

// ReadBlobMeta reads and splits the blob meta of blob into its tables.
func ReadBlobMeta(t testing.TB, blob string) BlobMeta {
	t.Helper()
	le := binary.LittleEndian
	data, err := os.ReadFile(blob + ".blob.meta")
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.GreaterOrEqual(t, len(data), blobMetaHeaderSize) {
		t.FailNow()
	}
	if !assert.Equal(t, blobMetaMagic, string(data[:8])) {
		t.FailNow()
	}

	meta := BlobMeta{Incompat: le.Uint32(data[12:]), tables: map[uint16][]byte{}}
	offset := blobMetaHeaderSize

	for range int(le.Uint16(data[20:])) {
		offset = (offset + 7) / 8 * 8
		if !assert.LessOrEqual(t, offset+blobMetaTableSize, len(data)) {
			t.FailNow()
		}

		table := data[offset:]
		size := int(le.Uint16(table[2:])) + int(le.Uint32(table[8:]))*int(le.Uint32(table[12:]))
		if !assert.LessOrEqual(t, offset+size, len(data)) {
			t.FailNow()
		}

		meta.tables[le.Uint16(table)] = data[offset : offset+size]
		offset += size
	}

	return meta
}

// Table returns the table of type typ, failing t unless it is present with
// entries of entrySize bytes.
func (m BlobMeta) Table(t testing.TB, typ uint16, entrySize int) BlobMetaTable {
	t.Helper()
	le := binary.LittleEndian

	if !assert.Contains(t, m.tables, typ) {
		t.FailNow()
	}

	table := m.tables[typ]
	if !assert.Equal(t, entrySize, int(le.Uint32(table[8:]))) {
		t.FailNow()
	}

	headerSize := int(le.Uint16(table[2:]))

	return BlobMetaTable{Header: table[:headerSize], Entries: table[headerSize:], Count: int(le.Uint32(table[12:]))}
}
