package build

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/erofs"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/stretchr/testify/assert"
)

const erofsBlockSize = 4096

func TestCheck(t *testing.T) {
	t.Parallel()
	t.Run("MetadataOnly", func(t *testing.T) {
		t.Parallel()
		img := fixture.Get(t, "zstd-4k")
		report, err := nydusCheck(t, "--bootstrap", img.Bootstrap)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.Len(t, report.Blobs, 1) {
			t.FailNow()
		}

		assert.False(t, report.Blobs[0].Verified)
	})

	t.Run("MissingBlob", func(t *testing.T) {
		t.Parallel()
		img := fixture.Get(t, "zstd-4k")
		report, err := nydusCheck(t, "--bootstrap", img.Bootstrap, "--blob-dir", t.TempDir())
		if !assert.Error(t, err) {
			t.FailNow()
		}
		if !assert.Len(t, report.Blobs, 1) {
			t.FailNow()
		}

		assert.False(t, report.Blobs[0].Verified)
	})

	for _, layout := range fixture.Layouts {
		t.Run("Valid/"+layout.Name, func(t *testing.T) {
			t.Parallel()
			img := fixture.Get(t, layout.Name)
			requireVerified(t, img.Bootstrap, img.BlobDir, []string{img.Blob(t)})
			_, err := nydusCheck(t, "--blob", img.Blob(t))
			assert.NoError(t, err)
		})
	}

	for _, damage := range []string{"FooterCRC", "FooterIncompat", "FooterBounds", "MetaCRC", "MetaIncompat", "TableBounds"} {
		t.Run(damage, func(t *testing.T) {
			t.Parallel()
			img := fixture.Get(t, "zstd-4k")
			data, err := os.ReadFile(img.Blob(t))
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			f := blobFile(img.Blob(t)).footer(t)
			tail := data[len(data)-footerSize:]
			meta := data[f.metaOffset : f.metaOffset+f.metaSize]

			switch damage {
			case "FooterCRC":
				tail[16] ^= 1

			case "FooterIncompat":
				binary.LittleEndian.PutUint32(tail[12:], binary.LittleEndian.Uint32(tail[12:])|1<<31)
				sealFormatRegion(tail)

			case "FooterBounds":
				binary.LittleEndian.PutUint64(tail[64:], ^uint64(0)-4095)
				sealFormatRegion(tail)

			case "MetaCRC":
				meta[16] ^= 1

			case "MetaIncompat":
				binary.LittleEndian.PutUint32(meta[12:], binary.LittleEndian.Uint32(meta[12:])|1<<31)
				sealFormatRegion(meta)

			case "TableBounds":
				binary.LittleEndian.PutUint32(meta[24+12:], ^uint32(0))
				sealFormatRegion(meta)
			}

			path := filepath.Join(t.TempDir(), "damaged.blob")
			if !assert.NoError(t, os.WriteFile(path, data, 0o600)) {
				t.FailNow()
			}

			for _, args := range [][]string{{"check", "--blob", path}, {"export", path}} {
				_, err := runNydus(t, args...)
				assert.Error(t, err)
			}
		})
	}

	for _, damage := range []string{"Magic", "Incompat", "BlockSize", "DeviceBounds", "RootInode"} {
		t.Run("Bootstrap"+damage, func(t *testing.T) {
			t.Parallel()
			img := fixture.Get(t, "zstd-4k")
			data, err := os.ReadFile(img.Bootstrap)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			sb := data[erofs.SuperOffset:erofsBlockSize]

			switch damage {
			case "Magic":
				sb[0] ^= 1

			case "Incompat":
				binary.LittleEndian.PutUint32(sb[80:], binary.LittleEndian.Uint32(sb[80:])|1<<31)

			case "BlockSize":
				sb[12] = 255

			case "DeviceBounds":
				binary.LittleEndian.PutUint16(sb[88:], ^uint16(0))

			case "RootInode":
				binary.LittleEndian.PutUint16(sb[14:], ^uint16(0))
			}

			clear(sb[4:8])
			binary.LittleEndian.PutUint32(sb[4:], ^crc32.Checksum(sb, formatCRC))

			path := filepath.Join(t.TempDir(), "damaged.boot")
			if !assert.NoError(t, os.WriteFile(path, data, 0o600)) {
				t.FailNow()
			}

			_, err = runNydus(t, "check", "--bootstrap", path, "--blob-dir", img.BlobDir)
			assert.Error(t, err)
		})
	}

	t.Run("BlobFooterMagic", func(t *testing.T) {
		t.Parallel()
		img := fixture.Copy(t, fixture.Get(t, "zstd-4k"))
		blob := img.Blob(t)
		st, err := os.Stat(blob)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		fixture.FlipByte(t, blob, st.Size()-footerSize)
		_, err = nydusCheck(t, "--blob", blob)
		assert.Error(t, err)
	})

	for _, tc := range []struct {
		name   string
		image  string
		blobOf bool
	}{
		{name: "BlobData/Bootstrap", image: "zstd-4k"},
		{name: "BlobData/Blob", image: "zstd-4k", blobOf: true},
		{name: "NativeDevice/Bootstrap", image: "erofs-lz4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			img := fixture.Copy(t, fixture.Get(t, tc.image))
			blob := img.Blob(t)
			f := blobFile(blob).footer(t)
			fixture.FlipByte(t, blob, int64(f.dataOffset+f.dataSize/2))

			args := []string{"--bootstrap", img.Bootstrap, "--blob-dir", img.BlobDir}
			if tc.blobOf {
				args = []string{"--blob", blob}
			}

			report, err := nydusCheck(t, args...)
			if !assert.Len(t, report.Blobs, 1) {
				t.FailNow()
			}

			assert.False(t, report.Blobs[0].Verified)

			if !assert.Error(t, err) {
				t.FailNow()
			}

			out, err := runNydus(t, append([]string{"check"}, args...)...)
			if !assert.Error(t, err) {
				t.FailNow()
			}

			assert.Contains(t, string(out), "failed verification")
		})
	}
}
