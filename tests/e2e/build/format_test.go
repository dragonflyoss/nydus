package build

import (
	"context"
	"encoding/binary"
	"hash/crc32"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/stretchr/testify/assert"
)

var formatCRC = crc32.MakeTable(crc32.Castagnoli)

func sealFormatRegion(data []byte) {
	clear(data[16:20])
	binary.LittleEndian.PutUint32(data[16:20], crc32.Checksum(data, formatCRC))
}

func runNydus(t testing.TB, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, env.Nydus(t), args...).CombinedOutput()

	if !assert.NoError(t, ctx.Err()) {
		t.FailNow()
	}

	requireCleanExit(t, err)

	return out, err
}

func requireCleanExit(t testing.TB, err error) {
	t.Helper()
	if err == nil {
		return
	}

	var exit *exec.ExitError
	if !assert.ErrorAs(t, err, &exit) {
		t.FailNow()
	}
	if !assert.Positive(t, exit.ExitCode()) {
		t.FailNow()
	}

	assert.NotEqual(t, 101, exit.ExitCode())
}

const (
	footerSize      = 4096
	footerMagic     = "NDFOOTER"
	footerRawDevice = 1 << 1
)

type footer struct {
	incompat   uint32
	dataOffset uint64
	dataSize   uint64
	metaOffset uint64
	metaSize   uint64
}

func (f footer) rawDevice() bool { return f.incompat&footerRawDevice != 0 }

type blobFile string

func (b blobFile) footer(t testing.TB) footer {
	t.Helper()
	f, err := os.Open(string(b))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.GreaterOrEqual(t, st.Size(), int64(footerSize)) {
		t.FailNow()
	}

	buf := make([]byte, footerSize)
	_, err = f.ReadAt(buf, st.Size()-footerSize)
	assert.NoError(t, err)

	if !assert.Equal(t, footerMagic, string(buf[:8])) {
		t.FailNow()
	}

	le := binary.LittleEndian

	return footer{
		incompat:   le.Uint32(buf[12:]),
		dataOffset: le.Uint64(buf[24:]),
		dataSize:   le.Uint64(buf[32:]),
		metaOffset: le.Uint64(buf[64:]),
		metaSize:   le.Uint64(buf[72:]),
	}
}

func (b blobFile) chunkGroupOffsets(t testing.TB) []uint64 {
	t.Helper()
	groups := fixture.ReadBlobMeta(t, string(b)).Table(t, fixture.ChunkGroupTable, 24)

	offsets := make([]uint64, groups.Count)
	for i := range offsets {
		offsets[i] = binary.LittleEndian.Uint64(groups.Entries[i*24:])
	}

	return offsets
}
