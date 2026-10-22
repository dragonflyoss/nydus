package build

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/stretchr/testify/require"
)

func FuzzBlobFormat(f *testing.F) {
	dir := f.TempDir()
	src := filepath.Join(dir, "source")
	require.NoError(f, os.Mkdir(src, 0o755))
	require.NoError(f, os.WriteFile(filepath.Join(src, "payload"), bytes.Repeat([]byte("format\n"), 4096), 0o640))
	layout, err := fixture.LayoutByName("zstd-4k")
	require.NoError(f, err)
	blob, _ := fixture.BuildInto(f, filepath.Join(dir, "blobs"), filepath.Join(dir, "image.boot"), src, layout)
	original, err := os.ReadFile(blob)
	require.NoError(f, err)
	footer := readFooter(f, blob)
	expected, err := formatCommand(f, "export", blob)
	require.NoError(f, err)
	for _, value := range []uint64{0, 1, 4096, ^uint64(0)} {
		for field := uint8(0); field < 12; field++ {
			f.Add(field, value)
		}
	}
	f.Fuzz(func(t *testing.T, field uint8, value uint64) {
		data := bytes.Clone(original)
		tail := data[len(data)-footerSize:]
		field %= 12
		if field >= 8 {
			meta := data[footer.MetaOffset : footer.MetaOffset+footer.MetaSize]
			offsets := []int{12, 24 + 12, 24 + 8, 24}
			binary.LittleEndian.PutUint32(meta[offsets[field-8]:], uint32(value))
			sealFormatRegion(meta)
		} else if field == 0 {
			binary.LittleEndian.PutUint32(tail[8:], uint32(value))
		} else {
			binary.LittleEndian.PutUint64(tail[24+8*int(field-1):], value)
		}
		sealFormatRegion(tail)
		path := filepath.Join(env.WorkDir(t), "mutated.blob")
		require.NoError(t, os.WriteFile(path, data, 0o600))
		out, err := formatCommand(t, "export", path)
		if err == nil {
			require.Equal(t, expected, out, "accepted footer mutation changed exported content")
		}
		_, _ = formatCommand(t, "check", "--blob", path)
	})
}
