package tar

import (
	"archive/tar"
	"bytes"
	"fmt"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
)

func TestVectors(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)

	t.Run("HeaderAllowedFormats", func(t *testing.T) {
		t.Parallel()
		for i, v := range goHeaderAllowedFormats() {
			if v.formats == tar.FormatUnknown {
				continue
			}

			for _, format := range []tar.Format{tar.FormatUSTAR, tar.FormatPAX, tar.FormatGNU} {
				if v.formats&format == 0 {
					continue
				}

				hdr := *v.header

				hdr.Format = format
				if hdr.Name == "" {
					hdr.Name = "file"
				}

				t.Run(fmt.Sprintf("%02d-%v", i, format), func(t *testing.T) {
					t.Parallel()
					if hdr.Size > tarBudget {
						var buf bytes.Buffer
						if !assert.NoError(t, tar.NewWriter(&buf).WriteHeader(&hdr)) {
							t.FailNow()
						}

						assert.Equal(t, tarRejected, (tarLayout{}).checkTarConversion(t, buf.Bytes()))
						return
					}

					data, err := writeGoTar(tarEntry{hdr: hdr})
					if !assert.NoError(t, err) {
						t.FailNow()
					}

					requireVerdict(t, (tarLayout{}).checkTarConversion(t, data))
				})
			}
		}
	})

	matrix := encodeTarVectors(t, tarEdgeMatrix())
	for _, group := range []struct {
		name  string
		cases []tarCase
		load  func(*testing.T) []tarCase
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
					requireVerdict(t, (tarLayout{}).checkTarConversion(t, c.data))
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
						requireVerdict(t, layout.checkTarConversion(t, c.data))
					})
				}
			})
		}
	})
}

type tarEntry struct {
	hdr  tar.Header
	body []byte
}

type tarVector struct {
	name    string
	entries []tarEntry
}

type tarCase struct {
	name string
	data []byte
}

func encodeTarVectors(t *testing.T, vectors []tarVector) []tarCase {
	t.Helper()
	cases := make([]tarCase, 0, len(vectors))

	for _, v := range vectors {
		data, err := writeGoTar(v.entries...)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		cases = append(cases, tarCase{v.name, data})
	}

	return cases
}

func writeGoTar(entries ...tarEntry) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	for _, entry := range entries {
		hdr := entry.hdr
		if err := tw.WriteHeader(&hdr); err != nil {
			return nil, err
		}

		body := entry.body
		if body == nil && (hdr.Typeflag == tar.TypeReg || hdr.Typeflag == 0) {
			body = tarBody(hdr.Size)
		}

		if _, err := tw.Write(body); err != nil {
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
