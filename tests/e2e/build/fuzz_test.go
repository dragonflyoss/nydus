package build

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/stretchr/testify/assert"
)

func FuzzBlobFormat(f *testing.F) {
	dir := f.TempDir()
	src := filepath.Join(dir, "source")
	if !assert.NoError(f, os.Mkdir(src, 0o755)) {
		f.FailNow()
	}
	if !assert.NoError(f, os.WriteFile(filepath.Join(src, "payload"), bytes.Repeat([]byte("format\n"), 4096), 0o640)) {
		f.FailNow()
	}

	layout := fixture.MustLayout(f, "zstd-4k")
	blob, _ := fixture.BuildInto(f, filepath.Join(dir, "blobs"), filepath.Join(dir, "image.boot"), src, layout)
	original, err := os.ReadFile(blob)
	if !assert.NoError(f, err) {
		f.FailNow()
	}

	footer := blobFile(blob).footer(f)
	expected, err := runNydus(f, "export", blob)
	if !assert.NoError(f, err) {
		f.FailNow()
	}

	for _, value := range []uint64{0, 1, 4096, ^uint64(0)} {
		for field := range uint8(12) {
			f.Add(field, value)
		}
	}

	f.Fuzz(func(t *testing.T, field uint8, value uint64) {
		data := bytes.Clone(original)
		tail := data[len(data)-footerSize:]

		field %= 12
		if field >= 8 {
			meta := data[footer.metaOffset : footer.metaOffset+footer.metaSize]
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
		if !assert.NoError(t, os.WriteFile(path, data, 0o600)) {
			t.FailNow()
		}

		out, err := runNydus(t, "export", path)
		if err == nil {
			assert.Equal(t, expected, out)
		}

		_, _ = runNydus(t, "check", "--blob", path)
	})
}
