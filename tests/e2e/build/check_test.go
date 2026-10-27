package build

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/stretchr/testify/require"
)

// TestCheck damages copies of built images and runs `nydus check` on them.
// Damage it cannot parse past fails the command.
func TestCheck(t *testing.T) {
	t.Parallel()

	t.Run("MetadataOnly", func(t *testing.T) {
		t.Parallel()
		img := fixture.Get(t, "zstd-4k")
		report, err := nydusCheck(t, "--bootstrap", img.Bootstrap)
		require.NoError(t, err, "metadata-only inspection does not verify unavailable blobs")
		require.Len(t, report.Blobs, 1)
		require.False(t, report.Blobs[0].Verified)
	})

	for _, layout := range fixture.Layouts {
		t.Run("Valid/"+layout.Name, func(t *testing.T) {
			t.Parallel()
			img := fixture.Get(t, layout.Name)
			requireVerified(t, img.Bootstrap, img.BlobDir, []string{img.Blob()})
			_, err := nydusCheck(t, "--blob", img.Blob())
			require.NoError(t, err)
		})
	}

	for _, damage := range []string{"FooterCRC", "FooterIncompat", "FooterBounds", "MetaCRC", "MetaIncompat", "TableBounds"} {
		t.Run(damage, func(t *testing.T) {
			t.Parallel()
			img := fixture.Get(t, "zstd-4k")
			data, err := os.ReadFile(img.Blob())
			require.NoError(t, err)
			f := readFooter(t, img.Blob())
			tail := data[len(data)-footerSize:]
			meta := data[f.MetaOffset : f.MetaOffset+f.MetaSize]
			switch damage {
			case "FooterCRC":
				tail[16] ^= 1
			case "FooterIncompat":
				binary.LittleEndian.PutUint32(tail[12:], 1<<31)
				sealFormatRegion(tail)
			case "FooterBounds":
				binary.LittleEndian.PutUint64(tail[64:], ^uint64(0)-4095)
				sealFormatRegion(tail)
			case "MetaCRC":
				meta[16] ^= 1
			case "MetaIncompat":
				binary.LittleEndian.PutUint32(meta[12:], 1<<31)
				sealFormatRegion(meta)
			case "TableBounds":
				binary.LittleEndian.PutUint32(meta[24+12:], ^uint32(0))
				sealFormatRegion(meta)
			}
			path := filepath.Join(t.TempDir(), "damaged.blob")
			require.NoError(t, os.WriteFile(path, data, 0o600))
			for _, args := range [][]string{{"check", "--blob", path}, {"export", path}} {
				out, err := formatCommand(t, args...)
				require.Error(t, err, "%v accepted %s:\n%s", args, damage, out)
			}
		})
	}

	for _, damage := range []string{"Magic", "Incompat", "BlockSize", "DeviceBounds", "RootInode"} {
		t.Run("Bootstrap"+damage, func(t *testing.T) {
			t.Parallel()
			img := fixture.Get(t, "zstd-4k")
			data, err := os.ReadFile(img.Bootstrap)
			require.NoError(t, err)
			sb := data[1024:]
			switch damage {
			case "Magic":
				sb[0] ^= 1
			case "Incompat":
				binary.LittleEndian.PutUint32(sb[80:], 1<<31)
			case "BlockSize":
				sb[12] = 255
			case "DeviceBounds":
				binary.LittleEndian.PutUint16(sb[88:], ^uint16(0))
			case "RootInode":
				binary.LittleEndian.PutUint32(sb[40:], ^uint32(0))
			}
			path := filepath.Join(t.TempDir(), "damaged.boot")
			require.NoError(t, os.WriteFile(path, data, 0o600))
			out, err := formatCommand(t, "check", "--bootstrap", path, "--blob-dir", img.BlobDir)
			require.Error(t, err, "accepted damaged bootstrap %s: %s", damage, out)
		})
	}

	t.Run("BlobFooterMagic", func(t *testing.T) {
		t.Parallel()
		img := fixture.Copy(t, fixture.Get(t, "zstd-4k"))
		blob := img.Blob()
		st, err := os.Stat(blob)
		require.NoError(t, err)
		flipByte(t, blob, st.Size()-footerSize) // the footer magic
		_, err = nydusCheck(t, "--blob", blob)
		require.Error(t, err, "a blob without a footer must fail the check")
	})

}
