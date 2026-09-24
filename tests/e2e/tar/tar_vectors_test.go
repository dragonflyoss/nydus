// The vectors of TestGoTarVectors marked "Go:" are copied from the tests of
// Go's archive/tar package (src/archive/tar/{tar,reader,writer}_test.go),
// Copyright 2009 The Go Authors, used under the BSD-3-Clause license in
// LICENSE-go.

package tar

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"maps"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e"
	"github.com/stretchr/testify/require"
)

// tarEntry is one archive member; a nil body of a regular file is filled
// with hdr.Size deterministic bytes.
type tarEntry struct {
	hdr  tar.Header
	body []byte
}

type tarVector struct {
	name    string
	entries []tarEntry
}

// tarCase is one archive to convert, already encoded.
type tarCase struct {
	name string
	data []byte
}

// tarLayouts are the blob layouts besides the default the matrix is also
// converted into.
var tarLayouts = map[string]tarLayout{
	"none":       {compressor: "none"},
	"lz4":        {compressor: "lz4"},
	"zstd-64k":   {chunkSize: 64 << 10},
	"erofs-none": {compressor: "erofs-none"},
	"erofs-zstd": {compressor: "erofs-zstd"},
}

// TestGoTarVectors converts archives built from the in-memory test vectors
// of Go's archive/tar and containerd's archive packages, plus an edge-case
// matrix, through nydus.Pack and checks each mount against the tree
// containerd applies from the same bytes, as TestGoTarCorpus does for the
// on-disk corpus.
func TestGoTarVectors(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root: the reference tree restores ownership and device nodes")
	}
	nydusBin := e2e.MustLookupExecutable(t, "nydus")

	t.Run("HeaderAllowedFormats", func(t *testing.T) {
		for i, v := range goHeaderAllowedFormats() {
			if v.formats == tar.FormatUnknown {
				t.Run(fmt.Sprintf("%02d", i), func(t *testing.T) {
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
					if hdr.Size > goTarCorpusBudget {
						t.Skipf("size %d over the %d-byte budget", hdr.Size, goTarCorpusBudget)
					}
					data, err := writeGoTar(tarEntry{hdr: hdr})
					require.NoError(t, err)
					checkTarConversion(t, nydusBin, data, tarLayout{})
				})
			}
		}
	})

	matrix := encodeTarVectors(t, tarEdgeMatrix())
	for _, group := range []struct {
		name  string
		cases []tarCase
	}{
		{"HeaderRoundTrip", encodeTarVectors(t, goHeaderRoundTrip())},
		{"Writer", encodeTarVectors(t, goWriterVectors())},
		{"SplitUSTARPath", encodeTarVectors(t, goSplitUSTARPath())},
		{"ReadTruncation", goReadTruncation(t)},
		{"ParseNumeric", goParseNumeric()},
		{"ParsePAXTime", goParsePAXTime()},
		{"ParsePAXRecord", goParsePAXRecord()},
		{"ParsePAX", goParsePAX()},
		{"GNUSparsePAXHeaders", goGNUSparsePAXHeaders()},
		{"ReadOldGNUSparseMap", goReadOldGNUSparseMap()},
		{"FileReader", goFileReader()},
		{"RejectedHeaders", goRejectedHeaders()},
		{"ContainerdBreakouts", containerdBreakouts(t)},
		{"Matrix", matrix},
	} {
		t.Run(group.name, func(t *testing.T) {
			for _, c := range group.cases {
				t.Run(c.name, func(t *testing.T) {
					checkTarConversion(t, nydusBin, c.data, tarLayout{})
				})
			}
		})
	}

	t.Run("Layouts", func(t *testing.T) {
		for name, layout := range tarLayouts {
			t.Run(name, func(t *testing.T) {
				for _, c := range matrix {
					t.Run(c.name, func(t *testing.T) {
						checkTarConversion(t, nydusBin, c.data, layout)
					})
				}
			})
		}
	})
}

// encodeTarVectors encodes each vector with Go's tar.Writer.
func encodeTarVectors(t *testing.T, vectors []tarVector) []tarCase {
	t.Helper()
	cases := make([]tarCase, 0, len(vectors))
	for _, v := range vectors {
		data, err := writeGoTar(v.entries...)
		require.NoError(t, err, v.name)
		cases = append(cases, tarCase{v.name, data})
	}
	return cases
}

// numberedTarCases names archives by their index in the Go vector table.
func numberedTarCases(archives [][]byte) []tarCase {
	cases := make([]tarCase, 0, len(archives))
	for i, data := range archives {
		cases = append(cases, tarCase{fmt.Sprintf("%02d", i), data})
	}
	return cases
}

// writeGoTar encodes entries with Go's tar.Writer.
func writeGoTar(entries ...tarEntry) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, entry := range entries {
		hdr := entry.hdr
		if err := tw.WriteHeader(&hdr); err != nil {
			return nil, err
		}
		body := entry.body
		// Typeflag 0 is Go's legacy TypeRegA, which the writer promotes.
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

// tarBody returns n deterministic, poorly compressible bytes.
func tarBody(n int64) []byte {
	b := make([]byte, n)
	x := uint32(n) | 1
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b[i] = byte(x)
	}
	return b
}

type allowedFormatsVector struct {
	header  *tar.Header
	formats tar.Format
}

// Go: TestHeaderAllowedFormats (tar_test.go). Each header is written in
// every format Go allows for it.
func goHeaderAllowedFormats() []allowedFormatsVector {
	const nameSize = 100
	return []allowedFormatsVector{
		{&tar.Header{}, tar.FormatUSTAR | tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{Size: 077777777777}, tar.FormatUSTAR | tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{Size: 077777777777, Format: tar.FormatUSTAR}, tar.FormatUSTAR},
		{&tar.Header{Size: 077777777777, Format: tar.FormatPAX}, tar.FormatUSTAR | tar.FormatPAX},
		{&tar.Header{Size: 077777777777, Format: tar.FormatGNU}, tar.FormatGNU},
		{&tar.Header{Size: 077777777777 + 1}, tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{Size: 077777777777 + 1, Format: tar.FormatPAX}, tar.FormatPAX},
		{&tar.Header{Size: 077777777777 + 1, Format: tar.FormatGNU}, tar.FormatGNU},
		{&tar.Header{Mode: 07777777}, tar.FormatUSTAR | tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{Mode: 07777777 + 1}, tar.FormatGNU},
		{&tar.Header{Devmajor: -123}, tar.FormatGNU},
		{&tar.Header{Devmajor: 1<<56 - 1}, tar.FormatGNU},
		{&tar.Header{Devmajor: 1 << 56}, tar.FormatUnknown},
		{&tar.Header{Devmajor: -1 << 56}, tar.FormatGNU},
		{&tar.Header{Devmajor: -1<<56 - 1}, tar.FormatUnknown},
		{&tar.Header{Name: "用戶名", Devmajor: -1 << 56}, tar.FormatGNU},
		{&tar.Header{Size: math.MaxInt64}, tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{Size: math.MinInt64}, tar.FormatUnknown},
		{&tar.Header{Uname: "0123456789abcdef0123456789abcdef"}, tar.FormatUSTAR | tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{Uname: "0123456789abcdef0123456789abcdefx"}, tar.FormatPAX},
		{&tar.Header{Name: "foobar"}, tar.FormatUSTAR | tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{Name: strings.Repeat("a", nameSize)}, tar.FormatUSTAR | tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{Name: strings.Repeat("a", nameSize+1)}, tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{Linkname: "用戶名"}, tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{Linkname: strings.Repeat("用戶名\x00", nameSize)}, tar.FormatUnknown},
		{&tar.Header{Linkname: "\x00hello"}, tar.FormatUnknown},
		{&tar.Header{Uid: 07777777}, tar.FormatUSTAR | tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{Uid: 07777777 + 1}, tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{Xattrs: nil}, tar.FormatUSTAR | tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{Xattrs: map[string]string{"foo": "bar"}}, tar.FormatPAX},                            //nolint:staticcheck
		{&tar.Header{Xattrs: map[string]string{"foo": "bar"}, Format: tar.FormatGNU}, tar.FormatUnknown}, //nolint:staticcheck
		{&tar.Header{Xattrs: map[string]string{"用戶名": "\x00hello"}}, tar.FormatPAX},                      //nolint:staticcheck
		{&tar.Header{Xattrs: map[string]string{"foo=bar": "baz"}}, tar.FormatUnknown},                    //nolint:staticcheck
		{&tar.Header{Xattrs: map[string]string{"foo": ""}}, tar.FormatPAX},                               //nolint:staticcheck
		{&tar.Header{ModTime: time.Unix(0, 0)}, tar.FormatUSTAR | tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{ModTime: time.Unix(077777777777, 0)}, tar.FormatUSTAR | tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{ModTime: time.Unix(077777777777+1, 0)}, tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{ModTime: time.Unix(math.MaxInt64, 0)}, tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{ModTime: time.Unix(math.MaxInt64, 0), Format: tar.FormatUSTAR}, tar.FormatUnknown},
		{&tar.Header{ModTime: time.Unix(-1, 0)}, tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{ModTime: time.Unix(1, 500)}, tar.FormatUSTAR | tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{ModTime: time.Unix(1, 0)}, tar.FormatUSTAR | tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{ModTime: time.Unix(1, 0), Format: tar.FormatPAX}, tar.FormatUSTAR | tar.FormatPAX},
		{&tar.Header{ModTime: time.Unix(1, 500), Format: tar.FormatUSTAR}, tar.FormatUSTAR},
		{&tar.Header{ModTime: time.Unix(1, 500), Format: tar.FormatPAX}, tar.FormatPAX},
		{&tar.Header{ModTime: time.Unix(1, 500), Format: tar.FormatGNU}, tar.FormatGNU},
		{&tar.Header{ModTime: time.Unix(-1, 500)}, tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{ModTime: time.Unix(-1, 500), Format: tar.FormatGNU}, tar.FormatGNU},
		{&tar.Header{AccessTime: time.Unix(0, 0)}, tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{AccessTime: time.Unix(0, 0), Format: tar.FormatUSTAR}, tar.FormatUnknown},
		{&tar.Header{AccessTime: time.Unix(0, 0), Format: tar.FormatPAX}, tar.FormatPAX},
		{&tar.Header{AccessTime: time.Unix(0, 0), Format: tar.FormatGNU}, tar.FormatGNU},
		{&tar.Header{AccessTime: time.Unix(-123, 0)}, tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{AccessTime: time.Unix(-123, 0), Format: tar.FormatPAX}, tar.FormatPAX},
		{&tar.Header{ChangeTime: time.Unix(123, 456)}, tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{ChangeTime: time.Unix(123, 456), Format: tar.FormatUSTAR}, tar.FormatUnknown},
		{&tar.Header{ChangeTime: time.Unix(123, 456), Format: tar.FormatGNU}, tar.FormatGNU},
		{&tar.Header{ChangeTime: time.Unix(123, 456), Format: tar.FormatPAX}, tar.FormatPAX},
		{&tar.Header{Name: "foo/", Typeflag: tar.TypeDir}, tar.FormatUSTAR | tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{Name: "foo/", Typeflag: tar.TypeReg}, tar.FormatUnknown},
		{&tar.Header{Name: "foo/", Typeflag: tar.TypeSymlink}, tar.FormatUSTAR | tar.FormatPAX | tar.FormatGNU},
	}
}

// Go: TestHeaderRoundTrip (tar_test.go), one archive per header.
func goHeaderRoundTrip() []tarVector {
	const (
		cISUID = 04000
		cISGID = 02000
		cISVTX = 01000
	)
	one := func(name string, hdr tar.Header) tarVector {
		return tarVector{name, []tarEntry{{hdr: hdr}}}
	}
	return []tarVector{
		one("regular", tar.Header{Name: "test.txt", Mode: 0644, Size: 12, ModTime: time.Unix(1360600916, 0), Typeflag: tar.TypeReg}),
		one("symlink", tar.Header{Name: "link.txt", Mode: 0777, ModTime: time.Unix(1360600852, 0), Typeflag: tar.TypeSymlink}),
		one("char", tar.Header{Name: "dev/null", Mode: 0666, ModTime: time.Unix(1360578951, 0), Typeflag: tar.TypeChar}),
		one("block", tar.Header{Name: "dev/sda", Mode: 0660, ModTime: time.Unix(1360578954, 0), Typeflag: tar.TypeBlock}),
		one("dir", tar.Header{Name: "dir/", Mode: 0755, ModTime: time.Unix(1360601116, 0), Typeflag: tar.TypeDir}),
		one("fifo", tar.Header{Name: "dev/initctl", Mode: 0600, ModTime: time.Unix(1360578949, 0), Typeflag: tar.TypeFifo}),
		one("setuid", tar.Header{Name: "bin/su", Mode: 0755 | cISUID, Size: 23232, ModTime: time.Unix(1355405093, 0), Typeflag: tar.TypeReg}),
		one("setgid", tar.Header{Name: "group.txt", Mode: 0750 | cISGID, ModTime: time.Unix(1360602346, 0), Typeflag: tar.TypeReg}),
		one("sticky", tar.Header{Name: "sticky.txt", Mode: 0600 | cISVTX, Size: 7, ModTime: time.Unix(1360602540, 0), Typeflag: tar.TypeReg}),
		{"hardlink", []tarEntry{
			// The link target, which the Go vector leaves implicit.
			{hdr: tar.Header{Name: "file.txt", Mode: 0644, ModTime: time.Unix(1360600916, 0), Typeflag: tar.TypeReg}},
			{hdr: tar.Header{Name: "hard.txt", Mode: 0644, Linkname: "file.txt", ModTime: time.Unix(1360600916, 0), Typeflag: tar.TypeLink}},
		}},
		one("info", tar.Header{Name: "info.txt", Mode: 0600, Uid: 1000, Gid: 1000, ModTime: time.Unix(1360602540, 0),
			Uname: "slartibartfast", Gname: "users", Typeflag: tar.TypeReg}),
	}
}

// Go: the in-memory headers of writer_test.go and TestInsecurePaths
// (reader_test.go).
func goWriterVectors() []tarVector {
	one := func(name string, hdr tar.Header) tarVector {
		return tarVector{name, []tarEntry{{hdr: hdr}}}
	}
	vectors := []tarVector{
		// TestPax, TestPaxSymlink, TestPaxNonAscii, TestPaxXattrs and
		// TestPaxHeadersSorted, with testdata/small.txt ("Kilts").
		one("Pax", tar.Header{Name: strings.Repeat("ab", 100), Mode: 0644, Size: 5, Typeflag: tar.TypeReg}),
		one("PaxSymlink", tar.Header{Name: "small.txt", Mode: 0644, Typeflag: tar.TypeSymlink,
			Linkname: strings.Repeat("1234567890/1234567890", 10)}),
		one("PaxNonAscii", tar.Header{Name: "文件名", Mode: 0644, Size: 5, Typeflag: tar.TypeReg, Gname: "組", Uname: "用戶名"}),
		{"PaxXattrs", []tarEntry{{hdr: tar.Header{Name: "small.txt", Mode: 0644, Size: 5, Typeflag: tar.TypeReg,
			Xattrs: map[string]string{"user.key": "value"}}, body: []byte("Kilts")}}}, //nolint:staticcheck
		one("PaxHeadersSorted", tar.Header{Name: "small.txt", Mode: 0644, Size: 5, Typeflag: tar.TypeReg,
			Xattrs: map[string]string{"foo": "foo", "bar": "bar", "baz": "baz", "qux": "qux"}}), //nolint:staticcheck
		one("USTARLongName", tar.Header{Typeflag: tar.TypeDir, Mode: 0644,
			Name: "/0000_0000000/00000-000000000/0000_0000000/00000-0000000000000/0000_0000000/00000-0000000-00000000/0000_0000000/00000000/0000_0000000/000/0000_0000000/00000000v00/0000_0000000/000000/0000_0000000/0000000/0000_0000000/00000y-00/0000/0000/00000000/0x000000/"}),
		one("ValidTypeflagWithPAXHeader", tar.Header{Name: strings.Repeat("ab", 100), Size: 4}),
		// TestWriter, trailing-slash.tar and file-and-dir.tar.
		one("TrailingSlash", tar.Header{Name: strings.Repeat("123456789/", 30)}),
		{"FileAndDir", []tarEntry{
			{hdr: tar.Header{Name: "small.txt", Size: 5}, body: []byte("Kilts")},
			{hdr: tar.Header{Name: "dir/"}},
		}},
		// TestRoundTrip (tar_test.go).
		{"RoundTrip", []tarEntry{{hdr: tar.Header{Name: "file.txt", Uid: 1 << 21, Size: 18, ModTime: time.Unix(1700000000, 0),
			PAXRecords: map[string]string{"uid": "2097152"}, Format: tar.FormatPAX, Typeflag: tar.TypeReg},
			body: []byte("some file contents")}}},
	}
	// TestIssue12594.
	for i, name := range []string{
		"0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/17/18/19/20/21/22/23/24/25/26/27/28/29/30/file.txt",
		"0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/17/18/19/20/21/22/23/24/25/26/27/28/29/30/31/32/33/file.txt",
		"0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/17/18/19/20/21/22/23/24/25/26/27/28/29/30/31/32/333/file.txt",
		"0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/17/18/19/20/21/22/23/24/25/26/27/28/29/30/31/32/33/34/35/36/37/38/39/40/file.txt",
		"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000/file.txt",
		"/home/support/.openoffice.org/3/user/uno_packages/cache/registry/com.sun.star.comp.deployment.executable.PackageRegistryBackend",
	} {
		vectors = append(vectors, one(fmt.Sprintf("Issue12594-%d", i), tar.Header{Name: name, Uid: 1 << 25}))
	}
	// TestInsecurePaths: an escaping member, then a secure one.
	for i, name := range []string{"../foo", "/foo", "a/b/../../../c"} {
		vectors = append(vectors, tarVector{fmt.Sprintf("InsecurePaths-%d", i), []tarEntry{
			{hdr: tar.Header{Name: name}},
			{hdr: tar.Header{Name: "secure"}},
		}})
	}
	return vectors
}

// Go: TestReadTruncation (reader_test.go), whole and truncated corpus
// archives, with trailing garbage.
func goReadTruncation(t *testing.T) []tarCase {
	testdata := goTarTestdata(t)
	var ss []string
	for _, name := range []string{"gnu.tar", "ustar-file-reg.tar", "pax-path-hdr.tar", "sparse-formats.tar"} {
		ss = append(ss, string(readCorpusArchive(t, filepath.Join(testdata, name))))
	}
	data1, data2, pax, sparse := ss[0], ss[1], ss[2], ss[3]
	data2 += strings.Repeat("\x00", 10*512)
	trash := strings.Repeat("garbage ", 64) // Exactly 512 bytes

	inputs := []string{
		"",
		data1[:511],
		data1[:512],
		data1[:1024],
		data1[:1536],
		data1[:2048],
		data1,
		data1[:2048] + data2[:1536],
		data2[:511],
		data2[:512],
		data2[:1195],
		data2[:1196],
		data2[:1200],
		data2[:1535],
		data2[:1536],
		data2[:1536] + trash[:1],
		data2[:1536] + trash[:511],
		data2[:1536] + trash,
		data2[:2048],
		data2[:2048] + trash[:1],
		data2[:2048] + trash[:511],
		data2[:2048] + trash,
		data2[:2560],
		data2[:2560] + trash[:1],
		data2[:2560] + trash[:511],
		data2[:2560] + trash,
		data2[:3072],
		pax,
		pax + trash[:1],
		pax + trash[:511],
		sparse[:511],
		sparse[:512],
		sparse[:3584],
		sparse[:9200],
		sparse[:9216],
		sparse[:9728],
		sparse[:10240],
		sparse[:11264],
		sparse,
		sparse + trash,
	}
	archives := make([][]byte, 0, len(inputs))
	for _, input := range inputs {
		archives = append(archives, []byte(input))
	}
	return numberedTarCases(archives)
}

type sparsePAXVector struct {
	data    string            // Leading member data: the 1.0 sparse map
	records map[string]string // PAX records of the member
	extents int64             // Sparse data bytes following data
}

// Go: TestReadGNUSparsePAXHeaders (reader_test.go). Go feeds each vector to
// an internal parser; here it becomes a member whose data is the map, when
// the vector has one, followed by as many data bytes as the expected map
// declares. tar.Writer drops GNU.sparse records, so the archive is encoded
// by hand.
func goGNUSparsePAXHeaders() []tarCase {
	vectors := goGNUSparsePAXVectors()
	var archives [][]byte
	for _, v := range vectors {
		body := append([]byte(v.data), tarBody(v.extents)...)
		archives = append(archives, rawPAXArchive(paxRecords(v.records), "sparse", body))
	}
	cases := numberedTarCases(archives)
	// Go's parser test has no size to check the maps against; with a real
	// size these two maps make archives Go accepts.
	for _, sized := range []struct {
		i    int
		size string
	}{{4, "5"}, {11, "35"}} {
		v := vectors[sized.i]
		records := maps.Clone(v.records)
		records["GNU.sparse.realsize"] = sized.size
		cases = append(cases, tarCase{fmt.Sprintf("%02d-sized", sized.i),
			rawPAXArchive(paxRecords(records), "sparse", append([]byte(v.data), tarBody(v.extents)...))})
	}
	return cases
}

func goGNUSparsePAXVectors() []sparsePAXVector {
	const (
		major     = "GNU.sparse.major"
		minor     = "GNU.sparse.minor"
		numBlocks = "GNU.sparse.numblocks"
		sparseMap = "GNU.sparse.map"
		size      = "GNU.sparse.size"
		realSize  = "GNU.sparse.realsize"
		name      = "GNU.sparse.name"
	)
	pad := func(s string) string {
		return s + strings.Repeat("\x00", int(-len(s)&511))
	}
	v10 := map[string]string{major: "1", minor: "0"}
	return []sparsePAXVector{
		{records: nil},
		{records: map[string]string{numBlocks: strconv.FormatInt(math.MaxInt64, 10), sparseMap: "0,1,2,3"}, extents: 4},
		{records: map[string]string{numBlocks: "4\x00", sparseMap: "0,1,2,3"}, extents: 4},
		{records: map[string]string{numBlocks: "4", sparseMap: "0,1,2,3"}, extents: 4},
		{records: map[string]string{numBlocks: "2", sparseMap: "0,1,2,3"}, extents: 4},
		{records: map[string]string{numBlocks: "2", sparseMap: "0, 1,2,3"}, extents: 4},
		{records: map[string]string{numBlocks: "2", sparseMap: "0,1,02,3", realSize: "4321"}, extents: 4},
		{records: map[string]string{numBlocks: "2", sparseMap: "0,one1,2,3"}, extents: 4},
		{records: map[string]string{major: "0", minor: "0", numBlocks: "2", sparseMap: "0,1,2,3",
			size: "1234", realSize: "4321", name: "realname"}, extents: 4},
		{records: map[string]string{major: "0", minor: "0", numBlocks: "1", sparseMap: "10737418240,512",
			size: "10737418240", name: "realname"}, extents: 512},
		{records: map[string]string{major: "0", minor: "0", numBlocks: "0", sparseMap: ""}},
		{records: map[string]string{major: "0", minor: "1", numBlocks: "4", sparseMap: "0,5,10,5,20,5,30,5"}, extents: 20},
		{records: map[string]string{major: "1", minor: "0", numBlocks: "4", sparseMap: "0,5,10,5,20,5,30,5"}},
		{data: pad("0\n"), records: v10},
		{data: pad("0\n")[:511] + "#", records: v10},
		{data: pad("0"), records: v10},
		{data: pad("ab\n"), records: v10},
		{data: pad("1\n2\n3\n"), records: v10, extents: 3},
		{data: pad("1\n2\n"), records: v10},
		{data: pad("1\n2\n\n"), records: v10},
		{data: strings.Repeat("\x00", 512) + pad("0\n"), records: v10},
		{data: strings.Repeat("0", 512) + pad("1\n5\n1\n"), records: v10, extents: 1},
		{data: pad(fmt.Sprintf("%d\n", int64(math.MaxInt64))), records: v10},
		{data: pad(strings.Repeat("0", 300) + "1\n" + strings.Repeat("0", 1000) + "5\n" + strings.Repeat("0", 800) + "2\n"),
			records: v10, extents: 2},
		{data: pad("2\n10737418240\n512\n21474836480\n512\n"), records: v10, extents: 1024},
		{data: pad("100\n" + func() string {
			var ss []string
			for i := 0; i < 100; i++ {
				ss = append(ss, fmt.Sprintf("%d\n%d\n", int64(i)<<30, 512))
			}
			return strings.Join(ss, "")
		}()), records: v10, extents: 100 * 512},
	}
}

// Go: TestSplitUSTARPath (writer_test.go), each name written by tar.Writer
// in whatever format it picks.
func goSplitUSTARPath() []tarVector {
	const nameSize, prefixSize = 100, 155
	sr := strings.Repeat
	var vectors []tarVector
	for i, name := range []string{
		"", "abc", "用戶名", sr("a", nameSize), sr("a", nameSize) + "/", sr("a", nameSize) + "/a",
		sr("a", prefixSize) + "/", sr("a", prefixSize) + "/a", sr("a", nameSize+1), sr("/", nameSize+1),
		sr("a", prefixSize) + "/" + sr("b", nameSize), sr("a", prefixSize) + "//" + sr("b", nameSize), sr("a/", nameSize),
	} {
		vectors = append(vectors, tarVector{fmt.Sprintf("%02d", i), []tarEntry{{hdr: tar.Header{Name: name}}}})
	}
	return vectors
}

// Go: TestParseNumeric (strconv_test.go). Each field becomes the 12-byte
// mtime of a header: octal inputs padded with NULs, base-256 inputs sign
// extended into a GNU header. The three inputs wider than any header field
// are left out.
func goParseNumeric() []tarCase {
	var archives [][]byte
	for _, in := range []string{
		"", "\x80", "\x80\x00", "\x80\x00\x00", "\xbf", "\xbf\xff", "\xbf\xff\xff", "\xff", "\xff\xff", "\xff\xff\xff",
		"\xc0", "\xc0\x00", "\xc0\x00\x00",
		"\x87\x76\xa2\x22\xeb\x8a\x72\x61", "\x80\x00\x00\x00\x07\x76\xa2\x22\xeb\x8a\x72\x61",
		"\xf7\x76\xa2\x22\xeb\x8a\x72\x61", "\xff\xff\xff\xff\xf7\x76\xa2\x22\xeb\x8a\x72\x61",
		"\x80\x7f\xff\xff\xff\xff\xff\xff\xff", "\x80\x80\x00\x00\x00\x00\x00\x00\x00",
		"\xff\x80\x00\x00\x00\x00\x00\x00\x00", "\xff\x7f\xff\xff\xff\xff\xff\xff\xff",
		"\xf5\xec\xd1\xc7\x7e\x5f\x26\x48\x81\x9f\x8f\x9b",
		"0000000\x00", " \x0000000\x00", " \x0000003\x00", "00000000227\x00", "032033\x00 ", "320330\x00 ",
		"0000660\x00 ", "\x00 0000660\x00 ", "0123\x7e\x5f\x264123",
	} {
		field := widenNumeric(in, 12)
		gnu := len(in) > 0 && in[0]&0x80 != 0
		hdr := rawTarHeader("f", tar.TypeReg, 0, gnu, func(blk []byte) { copy(blk[136:148], field) })
		archives = append(archives, append(hdr, make([]byte, 2*512)...))
	}
	return numberedTarCases(archives)
}

// widenNumeric places a tar numeric field into n bytes without changing the
// value Go parses from it.
func widenNumeric(in string, n int) []byte {
	out := make([]byte, n)
	if len(in) == 0 || in[0]&0x80 == 0 {
		copy(out, in)
		return out
	}
	pad := n - len(in)
	copy(out[pad:], in)
	if pad == 0 {
		return out
	}
	if in[0]&0x40 != 0 {
		for i := 0; i < pad; i++ {
			out[i] = 0xff
		}
	} else {
		out[0] = 0x80
		out[pad] &= 0x7f
	}
	return out
}

// Go: TestParsePAXTime (strconv_test.go), each input as a PAX mtime record.
func goParsePAXTime() []tarCase {
	var archives [][]byte
	for _, in := range []string{
		"1350244992.023960108", "1350244992.02396010", "1350244992.0239601089", "1350244992.3", "1350244992",
		"-1.000000001", "-1.000001", "-1.001000", "-1", "-1.999000", "-1.999999", "-1.999999999",
		"0.000000001", "0.000001", "0.001000", "0", "0.999000", "0.999999", "0.999999999",
		"1.000000001", "1.000001", "1.001000", "1", "1.999000", "1.999999", "1.999999999",
		"-1350244992.023960108", "-1350244992.02396010", "-1350244992.0239601089", "-1350244992.3", "-1350244992",
		"", "0", "1.", "0.0", ".5", "-1.3", "-1.0", "-0.0", "-0.1", "-0.01", "-0.99", "-0.98", "-1.1", "-1.01",
		"-2.99", "-5.98", "-", "+", "-1.-1", "99999999999999999999999999999999999999999999999",
		"0.123456789abcdef", "foo", "\x00", "𝟵𝟴𝟳𝟲𝟱.𝟰𝟯𝟮𝟭𝟬", "98765﹒43210",
	} {
		archives = append(archives, rawPAXArchive(paxRecords(map[string]string{"mtime": in}), "f", nil))
	}
	return numberedTarCases(archives)
}

// Go: TestParsePAXRecord (strconv_test.go), each input as a whole PAX header.
func goParsePAXRecord() []tarCase {
	medName := strings.Repeat("CD", 50)
	longName := strings.Repeat("AB", 100)
	var archives [][]byte
	for _, in := range []string{
		"6 k=v\n\n", "19 path=/etc/hosts\n", "210 path=" + longName + "\nabc", "110 path=" + medName + "\n",
		"9 foo=ba\n", "11 foo=bar\n\x00", "18 foo=b=\nar=\n==\x00\n", "27 foo=hello9 foo=ba\nworld\n",
		"27 ☺☻☹=日a本b語ç\nmeow mix", "17 \x00hello=\x00world\n", "1 k=1\n", "6 k~1\n", "6_k=1\n", "6 k=1 ",
		"632 k=1\n", "16 longkeyname=hahaha\n", "3 somelongkey=\n", "50 tooshort=\n",
		"0000000000000000000000000000000030 mtime=1432668921.098285006\n30 ctime=2147483649.15163319",
		"06 k=v\n", "00006 k=v\n", "000006 k=v\n", "000000 k=v\n", "0 k=v\n", "+0000005 x=\n",
	} {
		archives = append(archives, rawPAXArchive([]byte(in), "f", nil))
	}
	return numberedTarCases(archives)
}

// Go: TestParsePAX (reader_test.go), each input as a whole PAX header.
func goParsePAX() []tarCase {
	var archives [][]byte
	for _, in := range []string{
		"", "6 k=1\n", "10 a=name\n", "9 a=name\n", "30 mtime=1350244992.023960108\n", "3 somelongkey=\n",
		"50 tooshort=\n", "13 key1=haha\n13 key2=nana\n13 key3=kaka\n", "13 key1=val1\n13 key2=val2\n8 key1=\n",
		"22 GNU.sparse.size=10\n26 GNU.sparse.numblocks=2\n" +
			"23 GNU.sparse.offset=1\n25 GNU.sparse.numbytes=2\n" +
			"23 GNU.sparse.offset=3\n25 GNU.sparse.numbytes=4\n",
		"22 GNU.sparse.size=10\n26 GNU.sparse.numblocks=1\n" +
			"25 GNU.sparse.numbytes=2\n23 GNU.sparse.offset=1\n",
		"22 GNU.sparse.size=10\n26 GNU.sparse.numblocks=1\n" +
			"25 GNU.sparse.offset=1,2\n25 GNU.sparse.numbytes=2\n",
	} {
		// Sparse vectors carry the data bytes their numbytes records declare.
		body := tarBody(int64(strings.Count(in, "numbytes=2\n")*2 + strings.Count(in, "numbytes=4\n")*4))
		archives = append(archives, rawPAXArchive([]byte(in), "f", body))
	}
	return numberedTarCases(archives)
}

// Go: TestReadOldGNUSparseMap (reader_test.go). Each vector becomes an old
// GNU sparse member: its header and extension blocks followed by as many
// data bytes as the expected map declares.
func goReadOldGNUSparseMap() []tarCase {
	entries := func(spans ...[2]int64) []string {
		var out []string
		for _, s := range spans {
			out = append(out, string(gnuNumeric12(s[0]))+string(gnuNumeric12(s[1])))
		}
		return out
	}
	// populate fills up to max 24-byte entries from base, flagging the
	// extension byte when entries remain.
	populate := func(blk []byte, base, max, extended int, sps []string) []string {
		for i := 0; len(sps) > 0 && i < max; i++ {
			copy(blk[base+24*i:base+24*(i+1)], sps[0])
			sps = sps[1:]
		}
		if len(sps) > 0 {
			blk[extended] = 0x80
		}
		return sps
	}
	makeInput := func(gnu bool, realSize string, data int64, sps ...string) []byte {
		out := rawTarHeader("sparse", tar.TypeGNUSparse, data, true, func(blk []byte) {
			if !gnu {
				clear(blk[257:265])
			}
			copy(blk[483:495], realSize)
			sps = populate(blk, 386, 4, 482, sps)
		})
		for len(sps) > 0 {
			blk := make([]byte, 512)
			sps = populate(blk, 0, 21, 504, sps)
			out = append(out, blk...)
		}
		return out
	}
	complete := func(input []byte, data int64) []byte {
		out := append(input, tarBody(data)...)
		out = append(out, make([]byte, -data&511)...)
		return append(out, make([]byte, 2*512)...)
	}
	six := entries([2]int64{0, 1}, [2]int64{2, 1}, [2]int64{4, 1}, [2]int64{6, 1}, [2]int64{8, 1}, [2]int64{10, 1})
	extended := append(append(entries([2]int64{0, 1}, [2]int64{2, 1}), "", ""), entries([2]int64{4, 1}, [2]int64{6, 1})...)
	cases := numberedTarCases([][]byte{
		complete(makeInput(false, "", 0), 0),
		complete(makeInput(true, "1234", 0, "fewa"), 0),
		complete(makeInput(true, "0031", 0), 0),
		complete(makeInput(true, "80", 0), 0),
		complete(makeInput(true, "1234", 1, entries([2]int64{0, 0}, [2]int64{1, 1})...), 1),
		complete(makeInput(true, "1234", 1, append(entries([2]int64{0, 0}, [2]int64{1, 1}), "", "blah")...), 1),
		complete(makeInput(true, "3333", 4, entries([2]int64{0, 1}, [2]int64{2, 1}, [2]int64{4, 1}, [2]int64{6, 1})...), 4),
		complete(makeInput(true, "", 4, extended...), 4),
		makeInput(true, "", 6, six...)[:512],
		makeInput(true, "", 6, six...)[:3*512/2],
		complete(makeInput(true, "", 6, six...), 6),
		complete(makeInput(true, "", 1024, entries([2]int64{10 << 30, 512}, [2]int64{20 << 30, 512})...), 1024),
	})
	// Go never checks the maps against a real size; with one, the extension
	// block vectors are archives Go accepts.
	return append(cases,
		tarCase{"07-sized", complete(makeInput(true, "12", 4, extended...), 4)},
		tarCase{"10-sized", complete(makeInput(true, "16", 6, six...), 6)},
	)
}

// gnuNumeric12 formats a 12-byte numeric field as Go's writer does: octal
// while it fits, base-256 beyond.
func gnuNumeric12(v int64) []byte {
	if v < 1<<33 {
		return []byte(fmt.Sprintf("%011o\x00", v))
	}
	out := make([]byte, 12)
	binary.BigEndian.PutUint64(out[4:], uint64(v))
	out[0] = 0x80
	return out
}

// Go: the file makers of TestFileReader (reader_test.go). A regular maker
// is a member declaring size bytes but carrying str; a sparse maker is a PAX
// 0.1 sparse member whose physical data is its regular maker. Data shorter
// than declared ends the archive there.
func goFileReader() []tarCase {
	type sparse struct {
		str   string
		phys  int64
		spans [][2]int64
		size  int64
	}
	var archives [][]byte
	for _, reg := range []struct {
		str  string
		size int64
	}{{"", 0}, {"", 1}, {"hello", 5}, {"hello, world", 50}, {"hello, world", 5}} {
		archives = append(archives, rawSizedArchive(nil, "f", reg.size, []byte(reg.str)))
	}
	s := func(spans ...[2]int64) [][2]int64 { return spans }
	for _, v := range []sparse{
		{"abcde", 5, s([2]int64{0, 2}, [2]int64{5, 3}), 8},
		{"abcde", 5, s([2]int64{0, 2}, [2]int64{5, 3}), 10},
		{"abc", 5, s([2]int64{0, 2}, [2]int64{5, 3}), 10},
		{"abcde", 5, s([2]int64{1, 3}, [2]int64{6, 2}), 8},
		{"abcde", 5, s([2]int64{1, 3}, [2]int64{6, 0}, [2]int64{6, 0}, [2]int64{6, 2}), 8},
		{"abcde", 5, s([2]int64{1, 3}, [2]int64{6, 2}), 10},
		{"abcde", 5, s([2]int64{1, 3}, [2]int64{6, 2}, [2]int64{8, 0}, [2]int64{8, 0}, [2]int64{8, 0}, [2]int64{8, 0}), 10},
		{"", 0, s(), 2},
		{"", 8, s([2]int64{1, 3}, [2]int64{6, 5}), 15},
		{"ab", 2, s([2]int64{1, 3}, [2]int64{6, 5}), 15},
		{"ab", 8, s([2]int64{1, 3}, [2]int64{6, 5}), 15},
		{"abc", 3, s([2]int64{1, 3}, [2]int64{6, 5}), 15},
		{"abc", 8, s([2]int64{1, 3}, [2]int64{6, 5}), 15},
		{"abcde", 5, s([2]int64{1, 3}, [2]int64{6, 5}), 15},
		{"abcde", 8, s([2]int64{1, 3}, [2]int64{6, 5}), 15},
		{"abcdefghEXTRA", 13, s([2]int64{1, 3}, [2]int64{6, 5}), 15},
	} {
		var fields []string
		for _, span := range v.spans {
			fields = append(fields, strconv.FormatInt(span[0], 10), strconv.FormatInt(span[1], 10))
		}
		records := paxRecords(map[string]string{
			"GNU.sparse.major":     "0",
			"GNU.sparse.minor":     "1",
			"GNU.sparse.name":      "sparse",
			"GNU.sparse.numblocks": strconv.Itoa(len(v.spans)),
			"GNU.sparse.map":       strings.Join(fields, ","),
			"GNU.sparse.size":      strconv.FormatInt(v.size, 10),
		})
		archives = append(archives, rawSizedArchive(records, "f", v.phys, []byte(v.str)))
	}
	return numberedTarCases(archives)
}

// goRejectedHeaders holds headers Go's reader refuses: special files over
// its 1 MiB limit (the reader side of TestWriteLongHeader) and the NUL
// bytes TestWriter's error vectors expect the writer to refuse.
func goRejectedHeaders() []tarCase {
	const maxSpecialFileSize = 1 << 20
	long := bytes.Repeat([]byte("a"), maxSpecialFileSize+1)
	gnuLong := func(typeflag, memberType byte) []byte {
		out := rawTarHeader("././@LongLink", typeflag, int64(len(long)), true, nil)
		out = append(out, long...)
		out = append(out, make([]byte, -len(long)&511)...)
		out = append(out, rawTarHeader("f", memberType, 0, true, nil)...)
		return append(out, make([]byte, 2*512)...)
	}
	return []tarCase{
		{"gnu-long-name", gnuLong('L', tar.TypeReg)},
		{"gnu-long-linkname", gnuLong('K', tar.TypeSymlink)},
		{"pax-too-long", rawPAXArchive(paxRecords(map[string]string{"GOLANG.x": string(long)}), "f", nil)},
		{"pax-nul-xattr-key", rawPAXArchive(paxRecords(map[string]string{"SCHILY.xattr.null\x00null\x00": "fizzbuzz"}), "f", nil)},
		{"pax-nul-path", rawPAXArchive(paxRecords(map[string]string{"path": "null\x00.txt"}), "f", nil)},
	}
}

// tarEdgeMatrix covers header encodings and tree shapes real layers carry
// that neither Go's vectors nor its corpus exercise.
func tarEdgeMatrix() []tarVector {
	sr := strings.Repeat
	mtime := time.Unix(1700000000, 0)
	reg := func(name string, size int64) tarEntry {
		return tarEntry{hdr: tar.Header{Name: name, Mode: 0644, Size: size, ModTime: mtime, Typeflag: tar.TypeReg}}
	}
	dir := func(name string, mode int64) tarEntry {
		return tarEntry{hdr: tar.Header{Name: name, Mode: mode, ModTime: mtime, Typeflag: tar.TypeDir}}
	}
	symlink := func(name, target string) tarEntry {
		return tarEntry{hdr: tar.Header{Name: name, Linkname: target, Mode: 0777, ModTime: mtime, Typeflag: tar.TypeSymlink}}
	}
	link := func(name, target string) tarEntry {
		// Apply stamps a link's metadata onto the shared inode, so it
		// matches the target's as real writers record it.
		return tarEntry{hdr: tar.Header{Name: name, Linkname: target, Mode: 0644, ModTime: mtime, Typeflag: tar.TypeLink}}
	}
	with := func(entry tarEntry, edit func(*tar.Header)) tarEntry {
		edit(&entry.hdr)
		return entry
	}
	xattrs := func(entry tarEntry, kv ...string) tarEntry {
		return with(entry, func(h *tar.Header) {
			h.Format = tar.FormatPAX
			h.PAXRecords = map[string]string{}
			for i := 0; i < len(kv); i += 2 {
				h.PAXRecords["SCHILY.xattr."+kv[i]] = kv[i+1]
			}
		})
	}
	// A VFS_CAP_REVISION_2 capability granting CAP_NET_BIND_SERVICE.
	capNetBind := string([]byte{1, 0, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	var manyXattrs []string
	for i := 0; i < 32; i++ {
		manyXattrs = append(manyXattrs, fmt.Sprintf("user.k%02d", i), fmt.Sprintf("v%d", i))
	}
	vec := func(name string, entries ...tarEntry) tarVector { return tarVector{name, entries} }
	var bigDir []tarEntry
	for i := 0; i < 5000; i++ {
		bigDir = append(bigDir, reg(fmt.Sprintf("big/%04d-%s", i, sr("x", 100)), 0))
	}

	return []tarVector{
		// Names and link targets across the USTAR, PAX and GNU limits.
		vec("name-100", reg(sr("n", 100), 1)),
		vec("name-101", reg(sr("n", 101), 1)),
		vec("name-101-gnu", with(reg(sr("n", 101), 1), func(h *tar.Header) { h.Format = tar.FormatGNU })),
		vec("name-component-255", reg(sr("c", 255), 1)),
		vec("name-prefix-split", reg(sr("p", 155)+"/"+sr("n", 100), 1)),
		vec("name-deep-path", reg(sr("0123456789/", 90)+"file", 1)),
		vec("name-dot-segments", reg("./a/./b//c", 1)),
		vec("name-special-chars", reg("a b\tc\\d\ne", 1)),
		vec("name-long-with-newline", reg(sr("n", 120)+"\n"+sr("m", 20), 1)),
		vec("name-non-utf8-gnu", with(reg("caf\xe9", 1), func(h *tar.Header) { h.Format = tar.FormatGNU })),
		vec("linkname-100", symlink("s", sr("t", 100))),
		vec("linkname-101", symlink("s", sr("t", 101))),
		vec("linkname-1000", symlink("s", sr("t/", 500))),
		vec("hardlink-long-target", reg(sr("h", 150), 3), link("l", sr("h", 150))),
		// Numeric fields past the octal limits.
		vec("uid-2^21", with(reg("f", 1), func(h *tar.Header) { h.Uid, h.Gid = 1<<21, 1<<21 })),
		vec("uid-2^31-gnu", with(reg("f", 1), func(h *tar.Header) { h.Uid, h.Gid, h.Format = 1<<31, 1<<31, tar.FormatGNU })),
		vec("uid-max", with(reg("f", 1), func(h *tar.Header) { h.Uid, h.Gid = math.MaxUint32-1, math.MaxUint32-1 })),
		vec("mtime-nsec-pax", with(reg("f", 1), func(h *tar.Header) { h.ModTime, h.Format = time.Unix(1700000000, 123456789), tar.FormatPAX })),
		vec("mtime-zero", with(reg("f", 1), func(h *tar.Header) { h.ModTime = time.Unix(0, 0) })),
		vec("mtime-2^33", with(reg("f", 1), func(h *tar.Header) { h.ModTime = time.Unix(1<<33, 0) })),
		vec("mtime-negative", with(reg("f", 1), func(h *tar.Header) { h.ModTime = time.Unix(-1, 0) })),
		vec("device-max", with(reg("c", 0), func(h *tar.Header) {
			h.Typeflag, h.Mode, h.Devmajor, h.Devminor = tar.TypeChar, 0600, 4095, 1<<20-1
		}), with(reg("b", 0), func(h *tar.Header) { h.Typeflag, h.Mode, h.Devmajor, h.Devminor = tar.TypeBlock, 0600, 259, 7 })),
		// Modes.
		vec("mode-07777", with(reg("f", 1), func(h *tar.Header) { h.Mode = 07777 })),
		vec("mode-0", with(reg("f", 1), func(h *tar.Header) { h.Mode = 0 }), dir("d/", 0), reg("d/f", 1)),
		// Extended attributes.
		vec("xattr-security-capability", xattrs(reg("f", 1), "security.capability", capNetBind)),
		vec("xattr-binary-value", xattrs(reg("f", 1), "user.bin", "\x00=\n\xff")),
		vec("xattr-newline-name", xattrs(reg("f", 1), "user.a\nb", "v")),
		vec("xattr-empty-value", xattrs(reg("f", 1), "user.empty", "")),
		vec("xattr-large-value", xattrs(reg("f", 1), "user.big", sr("x", 3000))),
		vec("xattr-many", xattrs(reg("f", 1), manyXattrs...)),
		vec("xattr-on-dir", xattrs(dir("d/", 0755), "user.dir", "v")),
		// Apply refuses trusted.* from an archive: they steer overlayfs.
		vec("xattr-trusted-on-symlink", xattrs(symlink("s", "t"), "trusted.link", "v")),
		vec("xattr-trusted-overlay-opaque", xattrs(dir("d/", 0755), "trusted.overlay.opaque", "y")),
		vec("xattr-libarchive-ignored", with(reg("f", 1), func(h *tar.Header) {
			h.PAXRecords = map[string]string{"LIBARCHIVE.xattr.user.la": base64.StdEncoding.EncodeToString([]byte("v"))}
		})),
		// File sizes around block and chunk boundaries.
		vec("size-0", reg("f", 0)),
		vec("size-511-512-513", reg("a", 511), reg("b", 512), reg("c", 513)),
		vec("size-1MiB+1", reg("f", 1<<20+1)),
		vec("size-around-2MiB-chunks", reg("a", 2<<20-1), reg("b", 2<<20+1), reg("c", 6<<20+3)),
		vec("size-4MiB-zeros", tarEntry{hdr: reg("f", 4<<20).hdr, body: make([]byte, 4<<20)}),
		// A directory spanning many dirent blocks and readdir calls.
		vec("dir-5000-entries", bigDir...),
		// Hard links.
		vec("hardlink-to-symlink", symlink("s", "missing"), link("h", "s")),
		vec("hardlink-to-fifo", with(reg("p", 0), func(h *tar.Header) { h.Typeflag = tar.TypeFifo }), link("h", "p")),
		vec("hardlink-chain", reg("f", 3), link("l1", "f"), link("l2", "l1")),
		vec("hardlink-cross-dir", reg("d1/f", 3), link("d2/l", "d1/f")),
		vec("hardlink-own-metadata", reg("f", 3), with(link("l", "f"), func(h *tar.Header) { h.Mode, h.Uid = 0600, 7 })),
		vec("hardlink-missing-target", link("l", "missing")),
		vec("hardlink-to-dir", dir("d/", 0755), link("l", "d")),
		// Symlink targets.
		vec("symlink-absolute", symlink("s", "/etc/passwd")),
		vec("symlink-dotdot", symlink("d/s", "../../x")),
		vec("symlink-empty-target", symlink("s", "")),
		// Members under a symlinked parent land where it points inside the root.
		vec("parent-symlink", dir("b/", 0755), symlink("a", "b"), reg("a/f", 3)),
		vec("parent-symlink-absolute", dir("b/", 0755), symlink("a", "/b"), reg("a/f", 3)),
		vec("parent-symlink-escaping", symlink("a", "../../.."), reg("a/f", 3)),
		vec("parent-regular-file", reg("x", 1), reg("x/y", 1)),
		// Members that override earlier ones: the last one wins.
		vec("override-file", reg("f", 3), with(reg("f", 5), func(h *tar.Header) { h.Mode = 0600 })),
		vec("override-file-with-dir", reg("x", 3), dir("x/", 0750), reg("x/y", 1)),
		vec("override-dir-with-file", dir("x/", 0755), reg("x/y", 1), reg("x", 3)),
		vec("override-symlink-with-file", reg("t", 1), symlink("s", "t"), reg("s", 3)),
		vec("override-dir-mode", dir("d/", 0700), reg("d/f", 1), dir("d/", 0751)),
		// A member preceding its parent directory's own member.
		vec("child-before-parent", reg("p/c", 1), dir("p/", 0700)),
		// Apply ignores the root member.
		vec("root-member", xattrs(dir("./", 0700), "user.root", "v"), reg("f", 1)),
		// OCI whiteouts stay plain files in a layer.
		vec("whiteouts", reg(".wh.gone", 0), dir("d/", 0755), reg("d/.wh..wh..opq", 0)),
		vec("whiteout-invalid-name", reg("d/.wh..", 0)),
	}
}

// rawPAXArchive hand-encodes a single regular member, preceded by a PAX
// header when pax is not nil, for headers tar.Writer refuses to emit.
func rawPAXArchive(pax []byte, name string, body []byte) []byte {
	return rawSizedArchive(pax, name, int64(len(body)), body)
}

// rawSizedArchive is rawPAXArchive for a member declaring size bytes; data
// shorter than that ends the archive right after it.
func rawSizedArchive(pax []byte, name string, size int64, data []byte) []byte {
	var out []byte
	if pax != nil {
		out = append(out, rawTarHeader("PaxHeaders.0/"+name, tar.TypeXHeader, int64(len(pax)), false, nil)...)
		out = append(out, pax...)
		out = append(out, make([]byte, -len(pax)&511)...)
	}
	out = append(out, rawTarHeader(name, tar.TypeReg, size, false, nil)...)
	out = append(out, data...)
	if int64(len(data)) < size {
		return out
	}
	out = append(out, make([]byte, -len(data)&511)...)
	return append(out, make([]byte, 2*512)...)
}

// paxRecords encodes records in key order, or returns nil for none.
func paxRecords(records map[string]string) []byte {
	if len(records) == 0 {
		return nil
	}
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var pax bytes.Buffer
	for _, key := range keys {
		pax.WriteString(paxRecord(key, records[key]))
	}
	return pax.Bytes()
}

// paxRecord formats "<length> <key>=<value>\n", the length counting itself.
func paxRecord(key, value string) string {
	n := len(key) + len(value) + 3
	total := n + len(strconv.Itoa(n))
	if len(strconv.Itoa(total)) > len(strconv.Itoa(n)) {
		total++
	}
	return fmt.Sprintf("%d %s=%s\n", total, key, value)
}

// rawTarHeader returns a header block; edit may overwrite any field before
// the checksum is computed.
func rawTarHeader(name string, typeflag byte, size int64, gnu bool, edit func(blk []byte)) []byte {
	blk := make([]byte, 512)
	octal := func(field []byte, v int64) {
		copy(field, fmt.Sprintf("%0*o", len(field)-1, v))
	}
	copy(blk[0:100], name)
	octal(blk[100:108], 0644)
	octal(blk[108:116], 0)
	octal(blk[116:124], 0)
	octal(blk[124:136], size)
	octal(blk[136:148], 1700000000)
	blk[156] = typeflag
	if gnu {
		copy(blk[257:265], "ustar  \x00")
	} else {
		copy(blk[257:265], "ustar\x0000")
	}
	if edit != nil {
		edit(blk)
	}
	copy(blk[148:156], "        ")
	var sum int64
	for _, b := range blk {
		sum += int64(b)
	}
	copy(blk[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return blk
}
