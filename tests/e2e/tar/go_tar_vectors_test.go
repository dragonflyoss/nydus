// The vectors of TestGoTarVectors are copied from the tests of Go's
// archive/tar and containerd's pkg/archive; see vectors_helpers_test.go and
// containerd_helpers_test.go for attribution.

package tar

import (
	"archive/tar"
	"bytes"
	"fmt"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
)

// TestGoTarVectors converts archives built from the in-memory test vectors
// of Go's archive/tar and containerd's archive packages, plus an edge-case
// matrix, and checks each mount against the tree containerd applies from
// the same bytes, as TestGoTarCorpus does for the on-disk corpus. The matrix
// is also converted into every blob layout in tarLayouts.
func TestGoTarVectors(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)

	t.Run("HeaderAllowedFormats", func(t *testing.T) {
		t.Parallel()
		for i, v := range goHeaderAllowedFormats() {
			if v.formats == tar.FormatUnknown {
				t.Run(fmt.Sprintf("%02d", i), func(t *testing.T) {
					t.Parallel()
					_, err := writeGoTar(tarEntry{hdr: *v.header})
					require.Error(t, err, "Go encodes a header it declares unencodable")
				})
				continue
			}
			for _, format := range []tar.Format{tar.FormatUSTAR, tar.FormatPAX, tar.FormatGNU} {
				if v.formats&format == 0 {
					continue
				}
				hdr := *v.header
				hdr.Format = format
				if hdr.Name == "" {
					// An empty name is the root, which Apply ignores.
					hdr.Name = "file"
				}
				t.Run(fmt.Sprintf("%02d-%v", i, format), func(t *testing.T) {
					t.Parallel()
					if hdr.Size > tarBudget {
						// Too large to write out (TestLargeFiles streams such
						// sizes); the header alone, its data cut off, must
						// still be read as the size it declares and rejected.
						var buf bytes.Buffer
						require.NoError(t, tar.NewWriter(&buf).WriteHeader(&hdr))
						require.Equal(t, tarRejected, checkTarConversion(t, buf.Bytes(), tarLayout{}))
						return
					}
					data, err := writeGoTar(tarEntry{hdr: hdr})
					require.NoError(t, err)
					requireJudged(t, checkTarConversion(t, data, tarLayout{}))
				})
			}
		}
	})

	matrix := encodeTarVectors(t, tarEdgeMatrix())
	for _, group := range []struct {
		name  string
		cases []tarCase
		// load builds cases that need the on-disk corpus inside the group,
		// so a missing corpus fails only that group.
		load func(*testing.T) []tarCase
	}{
		{"HeaderRoundTrip", encodeTarVectors(t, goHeaderRoundTrip()), nil},
		{"Writer", encodeTarVectors(t, goWriterVectors()), nil},
		{"SplitUSTARPath", encodeTarVectors(t, goSplitUSTARPath()), nil},
		{"ReadTruncation", nil, goReadTruncation},
		{"ParseNumeric", goParseNumeric(), nil},
		{"ParsePAXTime", goParsePAXTime(), nil},
		{"ParsePAXRecord", goParsePAXRecord(), nil},
		{"ParsePAX", goParsePAX(), nil},
		{"GNUSparsePAXHeaders", goGNUSparsePAXHeaders(), nil},
		{"ReadOldGNUSparseMap", goReadOldGNUSparseMap(), nil},
		{"FileReader", goFileReader(), nil},
		{"SparseEntries", goSparseEntries(), nil},
		{"WriterAddFS", goWriterAddFS(t), nil},
		{"FileInfoHeader", goFileInfoHeader(t), nil},
		{"RejectedHeaders", goRejectedHeaders(), nil},
		{"ContainerdBreakouts", containerdBreakouts(t), nil},
		{"ContainerdApply", containerdApplyCases(t), nil},
		{"Matrix", matrix, nil},
	} {
		t.Run(group.name, func(t *testing.T) {
			t.Parallel()
			cases := group.cases
			if group.load != nil {
				cases = group.load(t)
			}
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					t.Parallel()
					requireJudged(t, checkTarConversion(t, c.data, tarLayout{}))
				})
			}
		})
	}

	t.Run("Layouts", func(t *testing.T) {
		t.Parallel()
		for name, layout := range tarLayouts {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				for _, c := range matrix {
					t.Run(c.name, func(t *testing.T) {
						t.Parallel()
						requireJudged(t, checkTarConversion(t, c.data, layout))
					})
				}
			})
		}
	})
}
