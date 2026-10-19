// The vectors the goXxx functions return are copied from the tests of Go's
// archive/tar package (src/archive/tar/{tar,reader,writer,strconv,fuzz}_test.go),
// Copyright 2009 The Go Authors, used under the BSD-3-Clause license, refer to
// https://go.dev/LICENSE.

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
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// member is one archive member; a nil body of a regular file is filled
// with hdr.Size deterministic bytes.
type member struct {
	// hdr is the member's header.
	hdr tar.Header

	// body is the member's data.
	body []byte
}

// vector is one archive to convert, as members for tar.Writer to encode.
type vector struct {
	// name is the subtest name.
	name string

	// members are the archive's members.
	members []member
}

// encodedVector is one archive to convert, already encoded.
type encodedVector struct {
	// name is the subtest name.
	name string

	// data is the encoded archive.
	data []byte
}

// blobLayouts are the blob layouts besides the default the matrix is also
// converted into.
var blobLayouts = map[string]blobLayout{
	"none":       {compressor: "none"},
	"lz4":        {compressor: "lz4"},
	"zstd-64k":   {chunkSize: 64 << 10},
	"erofs-none": {compressor: "erofs-none"},
	"erofs-zstd": {compressor: "erofs-zstd"},
}

// TestGoTarVectors converts archives built from the in-memory test vectors
// of Go's archive/tar and containerd's archive packages, plus an edge-case
// matrix, through nydus build and checks each mount against the tree
// containerd applies from the same bytes, as TestGoTarCorpus does for the
// on-disk corpus.
func TestGoTarVectors(t *testing.T) {
	util.SkipUnlessRoot(t, "the reference tree restores ownership and device nodes")
	t.Parallel()

	// Write each header of TestHeaderAllowedFormats in every format Go
	// allows for it, and check Go refuses the ones it declares unencodable.
	t.Run("header allowed formats", func(t *testing.T) {
		t.Parallel()
		for i, v := range goHeaderAllowedFormats() {
			if v.formats == tar.FormatUnknown {
				t.Run(fmt.Sprintf("%02d", i), func(t *testing.T) {
					t.Parallel()
					_, err := encodeMembers(member{hdr: *v.header})
					assert.Error(t, err, "Go encodes a header it declares unencodable")
				})
				continue
			}

			for _, format := range []tar.Format{tar.FormatUSTAR, tar.FormatPAX, tar.FormatGNU} {
				if v.formats&format == 0 {
					continue
				}

				// An empty name is the root, which Apply ignores.
				hdr := *v.header
				hdr.Format = format
				if hdr.Name == "" {
					hdr.Name = "file"
				}

				t.Run(fmt.Sprintf("%02d-%v", i, format), func(t *testing.T) {
					t.Parallel()
					assert := assert.New(t)

					// A header too large to write out (TestLargeFiles streams
					// such sizes) goes alone, its data cut off: it must still
					// be read as the size it declares and rejected.
					if hdr.Size > maxExpandedSize {
						var buf bytes.Buffer
						assert.NoError(tar.NewWriter(&buf).WriteHeader(&hdr))
						checkConversion(t, buf.Bytes(), blobLayout{})
						return
					}

					data, err := encodeMembers(member{hdr: hdr})
					assert.NoError(err)
					checkConversion(t, data, blobLayout{})
				})
			}
		}
	})

	// Convert each group of vectors in the default layout.
	matrix := encodeVectors(t, edgeMatrix())
	for _, group := range []struct {
		name  string
		cases []encodedVector

		// load builds cases that need the on-disk corpus, inside the
		// group, so a missing corpus skips only that group.
		load func(*testing.T) []encodedVector
	}{
		{"header round trip", encodeVectors(t, goHeaderRoundTrip()), nil},
		{"writer", encodeVectors(t, goWriterVectors()), nil},
		{"split ustar path", encodeVectors(t, goSplitUSTARPath()), nil},
		{"read truncation", nil, goReadTruncation},
		{"parse numeric", goParseNumeric(), nil},
		{"parse pax time", goParsePAXTime(), nil},
		{"parse pax record", goParsePAXRecord(), nil},
		{"parse pax", goParsePAX(), nil},
		{"gnu sparse pax headers", goGNUSparsePAXHeaders(), nil},
		{"read old gnu sparse map", goReadOldGNUSparseMap(), nil},
		{"file reader", goFileReader(), nil},
		{"sparse entries", goSparseEntries(), nil},
		{"writer add fs", goWriterAddFS(t), nil},
		{"file info header", goFileInfoHeader(t), nil},
		{"rejected headers", goRejectedHeaders(), nil},
		{"containerd breakouts", containerdBreakouts(t), nil},
		{"containerd apply", containerdApplyVectors(t), nil},
		{"matrix", matrix, nil},
	} {
		t.Run(group.name, func(t *testing.T) {
			t.Parallel()
			cases := group.cases
			if group.load != nil {
				cases = group.load(t)
			}

			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()
					checkConversion(t, tc.data, blobLayout{})
				})
			}
		})
	}

	// Convert the edge-case matrix in every other blob layout.
	t.Run("layouts", func(t *testing.T) {
		t.Parallel()
		for name, layout := range blobLayouts {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				for _, tc := range matrix {
					t.Run(tc.name, func(t *testing.T) {
						t.Parallel()
						checkConversion(t, tc.data, layout)
					})
				}
			})
		}
	})
}

// encodeVectors encodes each vector with Go's tar.Writer.
func encodeVectors(t *testing.T, vectors []vector) []encodedVector {
	t.Helper()
	cases := make([]encodedVector, 0, len(vectors))
	for _, v := range vectors {
		data, err := encodeMembers(v.members...)
		assert.NoError(t, err, v.name)
		cases = append(cases, encodedVector{name: v.name, data: data})
	}

	return cases
}

// numberedVectors names archives by their index in the Go vector table.
func numberedVectors(archives [][]byte) []encodedVector {
	cases := make([]encodedVector, 0, len(archives))
	for i, data := range archives {
		cases = append(cases, encodedVector{name: fmt.Sprintf("%02d", i), data: data})
	}

	return cases
}

// encodeMembers encodes members with Go's tar.Writer.
func encodeMembers(members ...member) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	for _, m := range members {
		hdr := m.hdr
		if err := tw.WriteHeader(&hdr); err != nil {
			return nil, err
		}

		// Fill the body of a regular file; typeflag 0 is Go's legacy TypeRegA,
		// which the writer promotes.
		body := m.body
		if body == nil && (hdr.Typeflag == tar.TypeReg || hdr.Typeflag == 0) {
			body = pseudoRandomBytes(hdr.Size)
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

// pseudoRandomBytes returns n deterministic, poorly compressible bytes.
func pseudoRandomBytes(n int64) []byte {
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

// single is a vector of one header.
func single(name string, hdr tar.Header) vector {
	return vector{name: name, members: []member{{hdr: hdr}}}
}

// allowedFormatsVector is a header and the formats Go allows for it.
type allowedFormatsVector struct {
	// header is the header to write.
	header *tar.Header

	// formats are the formats Go allows for it, FormatUnknown for none.
	formats tar.Format
}

// goHeaderAllowedFormats returns the headers of Go's TestHeaderAllowedFormats
// (tar_test.go), each to be written in every format Go allows for it.
func goHeaderAllowedFormats() []allowedFormatsVector {
	const nameSize = 100

	return []allowedFormatsVector{
		{&tar.Header{}, tar.FormatUSTAR | tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{Size: 0o77777777777}, tar.FormatUSTAR | tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{Size: 0o77777777777, Format: tar.FormatUSTAR}, tar.FormatUSTAR},
		{&tar.Header{Size: 0o77777777777, Format: tar.FormatPAX}, tar.FormatUSTAR | tar.FormatPAX},
		{&tar.Header{Size: 0o77777777777, Format: tar.FormatGNU}, tar.FormatGNU},
		{&tar.Header{Size: 0o77777777777 + 1}, tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{Size: 0o77777777777 + 1, Format: tar.FormatPAX}, tar.FormatPAX},
		{&tar.Header{Size: 0o77777777777 + 1, Format: tar.FormatGNU}, tar.FormatGNU},
		{&tar.Header{Mode: 0o7777777}, tar.FormatUSTAR | tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{Mode: 0o7777777 + 1}, tar.FormatGNU},
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
		{&tar.Header{Uid: 0o7777777}, tar.FormatUSTAR | tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{Uid: 0o7777777 + 1}, tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{Xattrs: nil}, tar.FormatUSTAR | tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{Xattrs: map[string]string{"foo": "bar"}}, tar.FormatPAX},                            //nolint:staticcheck
		{&tar.Header{Xattrs: map[string]string{"foo": "bar"}, Format: tar.FormatGNU}, tar.FormatUnknown}, //nolint:staticcheck
		{&tar.Header{Xattrs: map[string]string{"用戶名": "\x00hello"}}, tar.FormatPAX},                      //nolint:staticcheck
		{&tar.Header{Xattrs: map[string]string{"foo=bar": "baz"}}, tar.FormatUnknown},                    //nolint:staticcheck
		{&tar.Header{Xattrs: map[string]string{"foo": ""}}, tar.FormatPAX},                               //nolint:staticcheck
		{&tar.Header{ModTime: time.Unix(0, 0)}, tar.FormatUSTAR | tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{ModTime: time.Unix(0o77777777777, 0)}, tar.FormatUSTAR | tar.FormatPAX | tar.FormatGNU},
		{&tar.Header{ModTime: time.Unix(0o77777777777+1, 0)}, tar.FormatPAX | tar.FormatGNU},
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

// goHeaderRoundTrip returns the headers of Go's TestHeaderRoundTrip
// (tar_test.go), one archive per header.
func goHeaderRoundTrip() []vector {
	const (
		cISUID = 0o4000
		cISGID = 0o2000
		cISVTX = 0o1000
	)

	return []vector{
		single("regular", tar.Header{Name: "test.txt", Mode: 0o644, Size: 12, ModTime: time.Unix(1360600916, 0), Typeflag: tar.TypeReg}),
		single("symlink", tar.Header{Name: "link.txt", Mode: 0o777, ModTime: time.Unix(1360600852, 0), Typeflag: tar.TypeSymlink}),
		single("char", tar.Header{Name: "dev/null", Mode: 0o666, ModTime: time.Unix(1360578951, 0), Typeflag: tar.TypeChar}),
		single("block", tar.Header{Name: "dev/sda", Mode: 0o660, ModTime: time.Unix(1360578954, 0), Typeflag: tar.TypeBlock}),
		single("dir", tar.Header{Name: "dir/", Mode: 0o755, ModTime: time.Unix(1360601116, 0), Typeflag: tar.TypeDir}),
		single("fifo", tar.Header{Name: "dev/initctl", Mode: 0o600, ModTime: time.Unix(1360578949, 0), Typeflag: tar.TypeFifo}),
		single("setuid", tar.Header{Name: "bin/su", Mode: 0o755 | cISUID, Size: 23232, ModTime: time.Unix(1355405093, 0), Typeflag: tar.TypeReg}),
		single("setgid", tar.Header{Name: "group.txt", Mode: 0o750 | cISGID, ModTime: time.Unix(1360602346, 0), Typeflag: tar.TypeReg}),
		single("sticky", tar.Header{Name: "sticky.txt", Mode: 0o600 | cISVTX, Size: 7, ModTime: time.Unix(1360602540, 0), Typeflag: tar.TypeReg}),
		{"hardlink", []member{
			// The link target, which the Go vector leaves implicit.
			{hdr: tar.Header{Name: "file.txt", Mode: 0o644, ModTime: time.Unix(1360600916, 0), Typeflag: tar.TypeReg}},
			{hdr: tar.Header{Name: "hard.txt", Mode: 0o644, Linkname: "file.txt", ModTime: time.Unix(1360600916, 0), Typeflag: tar.TypeLink}},
		}},
		single("info", tar.Header{Name: "info.txt", Mode: 0o600, Uid: 1000, Gid: 1000, ModTime: time.Unix(1360602540, 0),
			Uname: "slartibartfast", Gname: "users", Typeflag: tar.TypeReg}),
	}
}

// goWriterVectors returns the in-memory headers of Go's writer_test.go and
// TestInsecurePaths (reader_test.go).
func goWriterVectors() []vector {
	vectors := []vector{
		// TestPax, TestPaxSymlink, TestPaxNonAscii, TestPaxXattrs and
		// TestPaxHeadersSorted, with testdata/small.txt ("Kilts").
		single("pax", tar.Header{Name: strings.Repeat("ab", 100), Mode: 0o644, Size: 5, Typeflag: tar.TypeReg}),
		single("pax symlink", tar.Header{Name: "small.txt", Mode: 0o644, Typeflag: tar.TypeSymlink,
			Linkname: strings.Repeat("1234567890/1234567890", 10)}),
		single("pax non ascii", tar.Header{Name: "文件名", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg, Gname: "組", Uname: "用戶名"}),
		{"pax xattrs", []member{{hdr: tar.Header{Name: "small.txt", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg,
			Xattrs: map[string]string{"user.key": "value"}}, body: []byte("Kilts")}}}, //nolint:staticcheck
		single("pax headers sorted", tar.Header{Name: "small.txt", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg,
			Xattrs: map[string]string{"foo": "foo", "bar": "bar", "baz": "baz", "qux": "qux"}}), //nolint:staticcheck
		single("ustar long name", tar.Header{Typeflag: tar.TypeDir, Mode: 0o644,
			Name: "/0000_0000000/00000-000000000/0000_0000000/00000-0000000000000/0000_0000000/00000-0000000-00000000/0000_0000000/00000000/0000_0000000/000/0000_0000000/00000000v00/0000_0000000/000000/0000_0000000/0000000/0000_0000000/00000y-00/0000/0000/00000000/0x000000/"}),
		single("valid typeflag with pax header", tar.Header{Name: strings.Repeat("ab", 100), Size: 4}),
		// TestWriter, trailing-slash.tar and file-and-dir.tar.
		single("trailing slash", tar.Header{Name: strings.Repeat("123456789/", 30)}),
		{"file and dir", []member{
			{hdr: tar.Header{Name: "small.txt", Size: 5}, body: []byte("Kilts")},
			{hdr: tar.Header{Name: "dir/"}},
		}},
		// TestRoundTrip (tar_test.go).
		{"round trip", []member{{hdr: tar.Header{Name: "file.txt", Uid: 1 << 21, Size: 18, ModTime: time.Unix(1700000000, 0),
			PAXRecords: map[string]string{"uid": "2097152"}, Format: tar.FormatPAX, Typeflag: tar.TypeReg},
			body: []byte("some file contents")}}},
		// The seed of FuzzReader (fuzz_test.go).
		{"fuzz reader seed", []member{{hdr: tar.Header{Name: "lorem.txt", Mode: 0o600, Size: int64(len(fuzzLorem))},
			body: []byte(fuzzLorem)}}},
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
		vectors = append(vectors, single(fmt.Sprintf("issue12594-%d", i), tar.Header{Name: name, Uid: 1 << 25}))
	}

	// TestInsecurePaths: an escaping member, then a secure one.
	for i, name := range []string{"../foo", "/foo", "a/b/../../../c"} {
		vectors = append(vectors, vector{name: fmt.Sprintf("insecure paths-%d", i), members: []member{
			{hdr: tar.Header{Name: name}},
			{hdr: tar.Header{Name: "secure"}},
		}})
	}

	return vectors
}

// goReadTruncation returns the archives of Go's TestReadTruncation
// (reader_test.go): whole and truncated corpus archives, with trailing
// garbage.
func goReadTruncation(t *testing.T) []encodedVector {
	t.Helper()

	// Read the corpus archives the vectors cut up; the trash is exactly 512
	// bytes.
	testdata := goTarTestdata(t)
	var contents []string
	for _, name := range []string{"gnu.tar", "ustar-file-reg.tar", "pax-path-hdr.tar", "sparse-formats.tar"} {
		contents = append(contents, string(readCorpusArchive(t, corpusArchivePath(t, testdata, name))))
	}

	data1, data2, pax, sparse := contents[0], contents[1], contents[2], contents[3]
	data2 += strings.Repeat("\x00", 10*512)
	trash := strings.Repeat("garbage ", 64)

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

	return numberedVectors(archives)
}

// sparsePAXVector is one vector of Go's TestReadGNUSparsePAXHeaders.
type sparsePAXVector struct {
	// data is the leading member data, the 1.0 sparse map.
	data string

	// records are the PAX records of the member.
	records map[string]string

	// extents is how many sparse data bytes follow data.
	extents int64
}

// goGNUSparsePAXHeaders returns the vectors of Go's
// TestReadGNUSparsePAXHeaders (reader_test.go) as archives. Go feeds each
// vector to an internal parser; here it becomes a member whose data is the
// map, when the vector has one, followed by as many data bytes as the
// expected map declares. tar.Writer drops GNU.sparse records, so the archive
// is encoded by hand.
func goGNUSparsePAXHeaders() []encodedVector {
	vectors := goGNUSparsePAXVectors()
	var archives [][]byte
	for _, v := range vectors {
		body := append([]byte(v.data), pseudoRandomBytes(v.extents)...)
		archives = append(archives, rawPAXArchive(paxRecords(v.records), "sparse", body))
	}

	cases := numberedVectors(archives)

	// Go's parser test has no size to check the maps against; with a real
	// size these two maps make archives Go accepts.
	for _, sized := range []struct {
		i    int
		size string
	}{{4, "5"}, {11, "35"}} {
		v := vectors[sized.i]
		records := maps.Clone(v.records)
		records["GNU.sparse.realsize"] = sized.size
		cases = append(cases, encodedVector{name: fmt.Sprintf("%02d-sized", sized.i),
			data: rawPAXArchive(paxRecords(records), "sparse", append([]byte(v.data), pseudoRandomBytes(v.extents)...))})
	}

	return cases
}

// goGNUSparsePAXVectors returns the vectors of Go's
// TestReadGNUSparsePAXHeaders (reader_test.go).
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
		return s + strings.Repeat("\x00", -len(s)&511)
	}
	sparse10 := map[string]string{major: "1", minor: "0"}

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
		{data: pad("0\n"), records: sparse10},
		{data: pad("0\n")[:511] + "#", records: sparse10},
		{data: pad("0"), records: sparse10},
		{data: pad("ab\n"), records: sparse10},
		{data: pad("1\n2\n3\n"), records: sparse10, extents: 3},
		{data: pad("1\n2\n"), records: sparse10},
		{data: pad("1\n2\n\n"), records: sparse10},
		{data: strings.Repeat("\x00", 512) + pad("0\n"), records: sparse10},
		{data: strings.Repeat("0", 512) + pad("1\n5\n1\n"), records: sparse10, extents: 1},
		{data: pad(fmt.Sprintf("%d\n", int64(math.MaxInt64))), records: sparse10},
		{data: pad(strings.Repeat("0", 300) + "1\n" + strings.Repeat("0", 1000) + "5\n" + strings.Repeat("0", 800) + "2\n"),
			records: sparse10, extents: 2},
		{data: pad("2\n10737418240\n512\n21474836480\n512\n"), records: sparse10, extents: 1024},
		{data: pad("100\n" + func() string {
			var lines []string
			for i := range 100 {
				lines = append(lines, fmt.Sprintf("%d\n%d\n", int64(i)<<30, 512))
			}
			return strings.Join(lines, "")
		}()), records: sparse10, extents: 100 * 512},
	}
}

// goSplitUSTARPath returns the names of Go's TestSplitUSTARPath
// (writer_test.go), each written by tar.Writer in whatever format it picks.
func goSplitUSTARPath() []vector {
	const nameSize, prefixSize = 100, 155
	repeat := strings.Repeat

	var vectors []vector
	for i, name := range []string{
		"", "abc", "用戶名", repeat("a", nameSize), repeat("a", nameSize) + "/", repeat("a", nameSize) + "/a",
		repeat("a", prefixSize) + "/", repeat("a", prefixSize) + "/a", repeat("a", nameSize+1), repeat("/", nameSize+1),
		repeat("a", prefixSize) + "/" + repeat("b", nameSize), repeat("a", prefixSize) + "//" + repeat("b", nameSize), repeat("a/", nameSize),
	} {
		vectors = append(vectors, vector{name: fmt.Sprintf("%02d", i), members: []member{{hdr: tar.Header{Name: name}}}})
	}

	return vectors
}

// goParseNumeric returns the fields of Go's TestParseNumeric
// (strconv_test.go), each as the 12-byte mtime of a header: octal inputs
// padded with NULs, base-256 inputs sign extended into a GNU header. The
// three inputs wider than any header field are left out.
func goParseNumeric() []encodedVector {
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
		hdr := rawTarHeader("f", tar.TypeReg, 0, gnu, func(block []byte) { copy(block[136:148], field) })
		archives = append(archives, append(hdr, make([]byte, 2*512)...))
	}

	return numberedVectors(archives)
}

// widenNumeric places a tar numeric field into n bytes without changing the
// value Go parses from it.
func widenNumeric(in string, n int) []byte {
	out := make([]byte, n)
	if len(in) == 0 || in[0]&0x80 == 0 {
		copy(out, in)
		return out
	}

	// Sign extend a base-256 field into the padding.
	pad := n - len(in)
	copy(out[pad:], in)
	if pad == 0 {
		return out
	}
	if in[0]&0x40 != 0 {
		copy(out, bytes.Repeat([]byte{0xff}, pad))
	} else {
		out[0] = 0x80
		out[pad] &= 0x7f
	}

	return out
}

// goParsePAXTime returns the inputs of Go's TestParsePAXTime
// (strconv_test.go), each as a PAX mtime record.
func goParsePAXTime() []encodedVector {
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

	return numberedVectors(archives)
}

// goParsePAXRecord returns the inputs of Go's TestParsePAXRecord
// (strconv_test.go), each as a whole PAX header.
func goParsePAXRecord() []encodedVector {
	mediumName := strings.Repeat("CD", 50)
	longName := strings.Repeat("AB", 100)

	var archives [][]byte
	for _, in := range []string{
		"6 k=v\n\n", "19 path=/etc/hosts\n", "210 path=" + longName + "\nabc", "110 path=" + mediumName + "\n",
		"9 foo=ba\n", "11 foo=bar\n\x00", "18 foo=b=\nar=\n==\x00\n", "27 foo=hello9 foo=ba\nworld\n",
		"27 ☺☻☹=日a本b語ç\nmeow mix", "17 \x00hello=\x00world\n", "1 k=1\n", "6 k~1\n", "6_k=1\n", "6 k=1 ",
		"632 k=1\n", "16 longkeyname=hahaha\n", "3 somelongkey=\n", "50 tooshort=\n",
		"0000000000000000000000000000000030 mtime=1432668921.098285006\n30 ctime=2147483649.15163319",
		"06 k=v\n", "00006 k=v\n", "000006 k=v\n", "000000 k=v\n", "0 k=v\n", "+0000005 x=\n",
	} {
		archives = append(archives, rawPAXArchive([]byte(in), "f", nil))
	}

	return numberedVectors(archives)
}

// goParsePAX returns the inputs of Go's TestParsePAX (reader_test.go), each
// as a whole PAX header.
func goParsePAX() []encodedVector {
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
		body := pseudoRandomBytes(int64(strings.Count(in, "numbytes=2\n")*2 + strings.Count(in, "numbytes=4\n")*4))
		archives = append(archives, rawPAXArchive([]byte(in), "f", body))
	}

	return numberedVectors(archives)
}

// goReadOldGNUSparseMap returns the vectors of Go's TestReadOldGNUSparseMap
// (reader_test.go) as archives. Each becomes an old GNU sparse member: its
// header and extension blocks followed by as many data bytes as the expected
// map declares.
func goReadOldGNUSparseMap() []encodedVector {
	sparseEntries := func(spans ...[2]int64) []string {
		var out []string
		for _, s := range spans {
			out = append(out, string(gnuNumeric12(s[0]))+string(gnuNumeric12(s[1])))
		}
		return out
	}

	// populate fills up to capacity 24-byte entries from base, flagging the
	// extension byte when entries remain.
	populate := func(block []byte, base, capacity, extended int, entries []string) []string {
		for i := 0; len(entries) > 0 && i < capacity; i++ {
			copy(block[base+24*i:base+24*(i+1)], entries[0])
			entries = entries[1:]
		}
		if len(entries) > 0 {
			block[extended] = 0x80
		}
		return entries
	}

	// makeInput writes the header block and the extension blocks the entries
	// need; complete appends the data and the end-of-archive blocks.
	makeInput := func(gnu bool, realSize string, data int64, entries ...string) []byte {
		out := rawTarHeader("sparse", tar.TypeGNUSparse, data, true, func(block []byte) {
			if !gnu {
				clear(block[257:265])
			}
			copy(block[483:495], realSize)
			entries = populate(block, 386, 4, 482, entries)
		})
		for len(entries) > 0 {
			block := make([]byte, 512)
			entries = populate(block, 0, 21, 504, entries)
			out = append(out, block...)
		}
		return out
	}
	complete := func(input []byte, data int64) []byte {
		out := append(input, pseudoRandomBytes(data)...)
		out = append(out, make([]byte, -data&511)...)
		return append(out, make([]byte, 2*512)...)
	}

	six := sparseEntries([2]int64{0, 1}, [2]int64{2, 1}, [2]int64{4, 1}, [2]int64{6, 1}, [2]int64{8, 1}, [2]int64{10, 1})
	extended := slices.Concat(sparseEntries([2]int64{0, 1}, [2]int64{2, 1}), []string{"", ""}, sparseEntries([2]int64{4, 1}, [2]int64{6, 1}))
	cases := numberedVectors([][]byte{
		complete(makeInput(false, "", 0), 0),
		complete(makeInput(true, "1234", 0, "fewa"), 0),
		complete(makeInput(true, "0031", 0), 0),
		complete(makeInput(true, "80", 0), 0),
		complete(makeInput(true, "1234", 1, sparseEntries([2]int64{0, 0}, [2]int64{1, 1})...), 1),
		complete(makeInput(true, "1234", 1, append(sparseEntries([2]int64{0, 0}, [2]int64{1, 1}), "", "blah")...), 1),
		complete(makeInput(true, "3333", 4, sparseEntries([2]int64{0, 1}, [2]int64{2, 1}, [2]int64{4, 1}, [2]int64{6, 1})...), 4),
		complete(makeInput(true, "", 4, extended...), 4),
		makeInput(true, "", 6, six...)[:512],
		makeInput(true, "", 6, six...)[:3*512/2],
		complete(makeInput(true, "", 6, six...), 6),
		complete(makeInput(true, "", 1024, sparseEntries([2]int64{10 << 30, 512}, [2]int64{20 << 30, 512})...), 1024),
	})

	// Go never checks the maps against a real size; with one, the extension
	// block vectors are archives Go accepts.
	return append(cases,
		encodedVector{name: "07-sized", data: complete(makeInput(true, "12", 4, extended...), 4)},
		encodedVector{name: "10-sized", data: complete(makeInput(true, "16", 6, six...), 6)},
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

// goFileReader returns the file makers of Go's TestFileReader
// (reader_test.go) as archives. A regular maker is a member declaring size
// bytes but carrying content; a sparse maker is a PAX 0.1 sparse member whose
// physical data is its regular maker. Data shorter than declared ends the
// archive there.
func goFileReader() []encodedVector {
	type sparse struct {
		content  string
		physical int64
		spans    [][2]int64
		size     int64
	}

	var archives [][]byte
	for _, regular := range []struct {
		content string
		size    int64
	}{{"", 0}, {"", 1}, {"hello", 5}, {"hello, world", 50}, {"hello, world", 5}} {
		archives = append(archives, rawSizedArchive(nil, "f", regular.size, []byte(regular.content)))
	}

	for _, v := range []sparse{
		{"abcde", 5, [][2]int64{{0, 2}, {5, 3}}, 8},
		{"abcde", 5, [][2]int64{{0, 2}, {5, 3}}, 10},
		{"abc", 5, [][2]int64{{0, 2}, {5, 3}}, 10},
		{"abcde", 5, [][2]int64{{1, 3}, {6, 2}}, 8},
		{"abcde", 5, [][2]int64{{1, 3}, {6, 0}, {6, 0}, {6, 2}}, 8},
		{"abcde", 5, [][2]int64{{1, 3}, {6, 2}}, 10},
		{"abcde", 5, [][2]int64{{1, 3}, {6, 2}, {8, 0}, {8, 0}, {8, 0}, {8, 0}}, 10},
		{"", 0, nil, 2},
		{"", 8, [][2]int64{{1, 3}, {6, 5}}, 15},
		{"ab", 2, [][2]int64{{1, 3}, {6, 5}}, 15},
		{"ab", 8, [][2]int64{{1, 3}, {6, 5}}, 15},
		{"abc", 3, [][2]int64{{1, 3}, {6, 5}}, 15},
		{"abc", 8, [][2]int64{{1, 3}, {6, 5}}, 15},
		{"abcde", 5, [][2]int64{{1, 3}, {6, 5}}, 15},
		{"abcde", 8, [][2]int64{{1, 3}, {6, 5}}, 15},
		{"abcdefghEXTRA", 13, [][2]int64{{1, 3}, {6, 5}}, 15},
	} {
		archives = append(archives, paxSparse01(v.spans, v.size, v.physical, []byte(v.content)))
	}

	return numberedVectors(archives)
}

// paxSparse01 encodes a PAX 0.1 sparse member mapping spans within size;
// its data section declares physical bytes and carries data.
func paxSparse01(spans [][2]int64, size, physical int64, data []byte) []byte {
	var fields []string
	for _, span := range spans {
		fields = append(fields, strconv.FormatInt(span[0], 10), strconv.FormatInt(span[1], 10))
	}

	records := paxRecords(map[string]string{
		"GNU.sparse.major":     "0",
		"GNU.sparse.minor":     "1",
		"GNU.sparse.name":      "sparse",
		"GNU.sparse.numblocks": strconv.Itoa(len(spans)),
		"GNU.sparse.map":       strings.Join(fields, ","),
		"GNU.sparse.size":      strconv.FormatInt(size, 10),
	})

	return rawSizedArchive(records, "f", physical, data)
}

// goSparseEntries returns the maps of Go's TestSparseEntries (tar_test.go),
// each as a PAX 0.1 sparse member carrying as many bytes as its extents
// declare.
func goSparseEntries() []encodedVector {
	var archives [][]byte
	for _, v := range []struct {
		spans [][2]int64
		size  int64
	}{
		{nil, 0},
		{nil, 5000},
		{[][2]int64{{0, 5000}}, 5000},
		{[][2]int64{{1000, 4000}}, 5000},
		{[][2]int64{{0, 3000}}, 5000},
		{[][2]int64{{3000, 2000}}, 5000},
		{[][2]int64{{2000, 2000}}, 5000},
		{[][2]int64{{0, 2000}, {8000, 2000}}, 10000},
		{[][2]int64{{0, 2000}, {2000, 2000}, {4000, 0}, {4000, 3000}, {7000, 1000},
			{8000, 0}, {8000, 2000}}, 10000},
		{[][2]int64{{0, 0}, {1000, 0}, {2000, 0}, {3000, 0}, {4000, 0}, {5000, 0}}, 5000},
		{[][2]int64{{1, 0}}, 0},
		{[][2]int64{{-1, 0}}, 100},
		{[][2]int64{{0, -1}}, 100},
		{[][2]int64{{0, 0}}, -100},
		{[][2]int64{{math.MaxInt64, 3}, {6, -5}}, 35},
		{[][2]int64{{1, 3}, {6, -5}}, 35},
		{[][2]int64{{math.MaxInt64, math.MaxInt64}}, math.MaxInt64},
		{[][2]int64{{3, 3}}, 5},
		{[][2]int64{{2, 0}, {1, 0}, {0, 0}}, 3},
		{[][2]int64{{1, 3}, {2, 2}}, 10},
	} {
		var physical int64
		for _, span := range v.spans {
			if span[1] > 0 && span[1] < 1<<20 {
				physical += span[1]
			}
		}
		archives = append(archives, paxSparse01(v.spans, v.size, physical, pseudoRandomBytes(physical)))
	}

	return numberedVectors(archives)
}

// goWriterAddFS returns the fs.FS of Go's TestWriterAddFS (writer_test.go),
// archived by tar.Writer.
func goWriterAddFS(t *testing.T) []encodedVector {
	t.Helper()
	fsys := fstest.MapFS{
		"emptyfolder":          {Mode: 0o755 | os.ModeDir},
		"file.go":              {Data: []byte("hello")},
		"subfolder/another.go": {Data: []byte("world")},
		"symlink.go":           {Mode: 0o777 | os.ModeSymlink, Data: []byte("file.go")},
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	assert.NoError(t, tw.AddFS(fsys))
	assert.NoError(t, tw.Close())

	return []encodedVector{{"map fs", buf.Bytes()}}
}

// goFileInfoHeader returns the archive of Go's TestFileInfoHeader,
// TestFileInfoHeaderDir and TestFileInfoHeaderSymlink (tar_test.go): the
// headers tar.FileInfoHeader makes from real files.
func goFileInfoHeader(t *testing.T) []encodedVector {
	t.Helper()

	// Create the files.
	dir := t.TempDir()
	small := filepath.Join(dir, "small.txt")
	assert.NoError(t, os.WriteFile(small, []byte("Kilts"), 0o644))
	assert.NoError(t, os.Chmod(small, 0o4755))
	assert.NoError(t, os.Mkdir(filepath.Join(dir, "subdir"), 0o750))
	assert.NoError(t, os.Symlink("small.txt", filepath.Join(dir, "link")))
	assert.NoError(t, unix.Mkfifo(filepath.Join(dir, "fifo"), 0o600))

	// Archive them through tar.FileInfoHeader.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range []string{"small.txt", "subdir", "link", "fifo"} {
		path := filepath.Join(dir, name)
		fi, err := os.Lstat(path)
		assert.NoError(t, err)
		link, _ := os.Readlink(path)
		hdr, err := tar.FileInfoHeader(fi, link)
		assert.NoError(t, err)
		assert.NoError(t, tw.WriteHeader(hdr))
		if fi.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			assert.NoError(t, err)
			_, err = tw.Write(data)
			assert.NoError(t, err)
		}
	}

	assert.NoError(t, tw.Close())

	return []encodedVector{{"local files", buf.Bytes()}}
}

// fuzzLorem is the content of FuzzReader's seed archive (fuzz_test.go).
const fuzzLorem = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."

// goRejectedHeaders holds headers Go's reader refuses: special files over
// its 1 MiB limit (the reader side of TestWriteLongHeader) and the NUL
// bytes TestWriter's error vectors expect the writer to refuse.
func goRejectedHeaders() []encodedVector {
	const maxSpecialFileSize = 1 << 20
	long := bytes.Repeat([]byte("a"), maxSpecialFileSize+1)
	gnuLong := func(typeflag, memberType byte) []byte {
		out := rawTarHeader("././@LongLink", typeflag, int64(len(long)), true, nil)
		out = append(out, long...)
		out = append(out, make([]byte, -len(long)&511)...)
		out = append(out, rawTarHeader("f", memberType, 0, true, nil)...)
		return append(out, make([]byte, 2*512)...)
	}

	return []encodedVector{
		{"gnu-long-name", gnuLong('L', tar.TypeReg)},
		{"gnu-long-linkname", gnuLong('K', tar.TypeSymlink)},
		{"pax-too-long", rawPAXArchive(paxRecords(map[string]string{"GOLANG.x": string(long)}), "f", nil)},
		{"pax-nul-xattr-key", rawPAXArchive(paxRecords(map[string]string{"SCHILY.xattr.null\x00null\x00": "fizzbuzz"}), "f", nil)},
		{"pax-nul-path", rawPAXArchive(paxRecords(map[string]string{"path": "null\x00.txt"}), "f", nil)},
	}
}

// edgeMatrix covers header encodings and tree shapes real layers carry
// that neither Go's vectors nor its corpus exercise.
func edgeMatrix() []vector {
	repeat := strings.Repeat
	mtime := time.Unix(1700000000, 0)
	file := func(name string, size int64) member {
		return member{hdr: tar.Header{Name: name, Mode: 0o644, Size: size, ModTime: mtime, Typeflag: tar.TypeReg}}
	}
	dir := func(name string, mode int64) member {
		return member{hdr: tar.Header{Name: name, Mode: mode, ModTime: mtime, Typeflag: tar.TypeDir}}
	}
	symlink := func(name, target string) member {
		return member{hdr: tar.Header{Name: name, Linkname: target, Mode: 0o777, ModTime: mtime, Typeflag: tar.TypeSymlink}}
	}
	link := func(name, target string) member {
		// Apply stamps a link's metadata onto the shared inode, so it
		// matches the target's as real writers record it.
		return member{hdr: tar.Header{Name: name, Linkname: target, Mode: 0o644, ModTime: mtime, Typeflag: tar.TypeLink}}
	}
	with := func(m member, edit func(*tar.Header)) member {
		edit(&m.hdr)
		return m
	}
	xattrs := func(m member, kv ...string) member {
		return with(m, func(h *tar.Header) {
			h.Format = tar.FormatPAX
			h.PAXRecords = map[string]string{}
			for i := 0; i < len(kv); i += 2 {
				h.PAXRecords["SCHILY.xattr."+kv[i]] = kv[i+1]
			}
		})
	}
	newVector := func(name string, members ...member) vector { return vector{name: name, members: members} }
	global := func(name string) member {
		return member{hdr: tar.Header{Name: name, Typeflag: tar.TypeXGlobalHeader, PAXRecords: map[string]string{"comment": "g"}}}
	}

	// A VFS_CAP_REVISION_2 capability granting CAP_NET_BIND_SERVICE.
	capNetBind := string([]byte{1, 0, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

	var manyXattrs []string
	for i := range 32 {
		manyXattrs = append(manyXattrs, fmt.Sprintf("user.k%02d", i), fmt.Sprintf("v%d", i))
	}

	var bigDir []member
	for i := range 5000 {
		bigDir = append(bigDir, file(fmt.Sprintf("big/%04d-%s", i, repeat("x", 100)), 0))
	}

	return []vector{
		// Names and link targets across the USTAR, PAX and GNU limits.
		newVector("name-100", file(repeat("n", 100), 1)),
		newVector("name-101", file(repeat("n", 101), 1)),
		newVector("name-101-gnu", with(file(repeat("n", 101), 1), func(h *tar.Header) { h.Format = tar.FormatGNU })),
		newVector("name-component-255", file(repeat("c", 255), 1)),
		newVector("name-prefix-split", file(repeat("p", 155)+"/"+repeat("n", 100), 1)),
		newVector("name-deep-path", file(repeat("0123456789/", 90)+"file", 1)),
		newVector("name-dot-segments", file("./a/./b//c", 1)),
		newVector("name-special-chars", file("a b\tc\\d\ne", 1)),
		newVector("name-long-with-newline", file(repeat("n", 120)+"\n"+repeat("m", 20), 1)),
		newVector("name-non-utf8-gnu", with(file("caf\xe9", 1), func(h *tar.Header) { h.Format = tar.FormatGNU })),
		newVector("linkname-100", symlink("s", repeat("t", 100))),
		newVector("linkname-101", symlink("s", repeat("t", 101))),
		newVector("linkname-1000", symlink("s", repeat("t/", 500))),
		newVector("hardlink-long-target", file(repeat("h", 150), 3), link("l", repeat("h", 150))),
		// Numeric fields past the octal limits.
		newVector("uid-2^21", with(file("f", 1), func(h *tar.Header) { h.Uid, h.Gid = 1<<21, 1<<21 })),
		newVector("uid-2^31-gnu", with(file("f", 1), func(h *tar.Header) { h.Uid, h.Gid, h.Format = 1<<31, 1<<31, tar.FormatGNU })),
		newVector("uid-max", with(file("f", 1), func(h *tar.Header) { h.Uid, h.Gid = math.MaxUint32-1, math.MaxUint32-1 })),
		newVector("mtime-nsec-pax", with(file("f", 1), func(h *tar.Header) { h.ModTime, h.Format = time.Unix(1700000000, 123456789), tar.FormatPAX })),
		newVector("mtime-zero", with(file("f", 1), func(h *tar.Header) { h.ModTime = time.Unix(0, 0) })),
		newVector("mtime-2^33", with(file("f", 1), func(h *tar.Header) { h.ModTime = time.Unix(1<<33, 0) })),
		newVector("mtime-negative", with(file("f", 1), func(h *tar.Header) { h.ModTime = time.Unix(-1, 0) })),
		newVector("device-max", with(file("c", 0), func(h *tar.Header) {
			h.Typeflag, h.Mode, h.Devmajor, h.Devminor = tar.TypeChar, 0o600, 4095, 1<<20-1
		}), with(file("b", 0), func(h *tar.Header) { h.Typeflag, h.Mode, h.Devmajor, h.Devminor = tar.TypeBlock, 0o600, 259, 7 })),
		// Modes.
		newVector("mode-07777", with(file("f", 1), func(h *tar.Header) { h.Mode = 0o7777 })),
		newVector("mode-0", with(file("f", 1), func(h *tar.Header) { h.Mode = 0 }), dir("d/", 0), file("d/f", 1)),
		// Extended attributes.
		newVector("xattr-security-capability", xattrs(file("f", 1), "security.capability", capNetBind)),
		newVector("xattr-binary-value", xattrs(file("f", 1), "user.bin", "\x00=\n\xff")),
		newVector("xattr-newline-name", xattrs(file("f", 1), "user.a\nb", "v")),
		newVector("xattr-empty-value", xattrs(file("f", 1), "user.empty", "")),
		newVector("xattr-large-value", xattrs(file("f", 1), "user.big", repeat("x", 3000))),
		newVector("xattr-many", xattrs(file("f", 1), manyXattrs...)),
		newVector("xattr-on-dir", xattrs(dir("d/", 0o755), "user.dir", "v")),
		// Apply refuses trusted.* from an archive: they steer overlayfs.
		newVector("xattr-trusted-on-symlink", xattrs(symlink("s", "t"), "trusted.link", "v")),
		newVector("xattr-trusted-overlay-opaque", xattrs(dir("d/", 0o755), "trusted.overlay.opaque", "y")),
		newVector("xattr-libarchive-ignored", with(file("f", 1), func(h *tar.Header) {
			h.PAXRecords = map[string]string{"LIBARCHIVE.xattr.user.la": base64.StdEncoding.EncodeToString([]byte("v"))}
		})),
		// File sizes around block and chunk boundaries.
		newVector("size-0", file("f", 0)),
		newVector("size-511-512-513", file("a", 511), file("b", 512), file("c", 513)),
		newVector("size-1MiB+1", file("f", 1<<20+1)),
		newVector("size-around-2MiB-chunks", file("a", 2<<20-1), file("b", 2<<20+1), file("c", 6<<20+3)),
		newVector("size-4MiB-zeros", member{hdr: file("f", 4<<20).hdr, body: make([]byte, 4<<20)}),
		// A directory spanning many dirent blocks and readdir calls.
		newVector("dir-5000-entries", bigDir...),
		// Hard links.
		newVector("hardlink-to-symlink", symlink("s", "missing"), link("h", "s")),
		newVector("hardlink-to-fifo", with(file("p", 0), func(h *tar.Header) { h.Typeflag = tar.TypeFifo }), link("h", "p")),
		newVector("hardlink-chain", file("f", 3), link("l1", "f"), link("l2", "l1")),
		newVector("hardlink-cross-dir", file("d1/f", 3), link("d2/l", "d1/f")),
		newVector("hardlink-own-metadata", file("f", 3), with(link("l", "f"), func(h *tar.Header) { h.Mode, h.Uid = 0o600, 7 })),
		newVector("hardlink-missing-target", link("l", "missing")),
		newVector("hardlink-to-dir", dir("d/", 0o755), link("l", "d")),
		// Symlink targets.
		newVector("symlink-absolute", symlink("s", "/etc/passwd")),
		newVector("symlink-dotdot", symlink("d/s", "../../x")),
		newVector("symlink-empty-target", symlink("s", "")),
		// Members under a symlinked parent land where it points inside the root.
		newVector("parent-symlink", dir("b/", 0o755), symlink("a", "b"), file("a/f", 3)),
		newVector("parent-symlink-absolute", dir("b/", 0o755), symlink("a", "/b"), file("a/f", 3)),
		newVector("parent-symlink-escaping", symlink("a", "../../.."), file("a/f", 3)),
		newVector("parent-regular-file", file("x", 1), file("x/y", 1)),
		// Members that override earlier ones: the last one wins.
		newVector("override-file", file("f", 3), with(file("f", 5), func(h *tar.Header) { h.Mode = 0o600 })),
		newVector("override-file-with-dir", file("x", 3), dir("x/", 0o750), file("x/y", 1)),
		newVector("override-dir-with-file", dir("x/", 0o755), file("x/y", 1), file("x", 3)),
		newVector("override-symlink-with-file", file("t", 1), symlink("s", "t"), file("s", 3)),
		newVector("override-dir-mode", dir("d/", 0o700), file("d/f", 1), dir("d/", 0o751)),
		// A member preceding its parent directory's own member.
		newVector("child-before-parent", file("p/c", 1), dir("p/", 0o700)),
		// Apply ignores the root member.
		newVector("root-member", xattrs(dir("./", 0o700), "user.root", "v"), file("f", 1)),
		// OCI whiteouts stay plain files in a layer.
		newVector("whiteouts", file(".wh.gone", 0), dir("d/", 0o755), file("d/.wh..wh..opq", 0)),
		newVector("whiteout-invalid-name", file("d/.wh..", 0)),
		// Apply removes what a global header's name holds, then ignores it.
		newVector("global-header", global("pax_global_header"), file("f", 1)),
		newVector("global-header-implies-parents", global("g/h/pax_global_header"), file("f", 1)),
		newVector("global-header-removal-replaced", file("f", 3), global("f"), with(file("f", 1), func(h *tar.Header) { h.Mode = 0o600 })),
		newVector("global-header-removal-replaced-by-dir", file("f", 3), global("f"), file("f/x", 1)),
		newVector("global-header-removal-under-replaced-dir", file("d/x", 1), global("d/x"), file("d", 3)),
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

	var pax bytes.Buffer
	for _, key := range slices.Sorted(maps.Keys(records)) {
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
func rawTarHeader(name string, typeflag byte, size int64, gnu bool, edit func(block []byte)) []byte {
	block := make([]byte, 512)
	octal := func(field []byte, v int64) {
		copy(field, fmt.Sprintf("%0*o", len(field)-1, v))
	}

	copy(block[0:100], name)
	octal(block[100:108], 0o644)
	octal(block[108:116], 0)
	octal(block[116:124], 0)
	octal(block[124:136], size)
	octal(block[136:148], 1700000000)
	block[156] = typeflag
	if gnu {
		copy(block[257:265], "ustar  \x00")
	} else {
		copy(block[257:265], "ustar\x0000")
	}

	if edit != nil {
		edit(block)
	}
	fixChecksum(block)

	return block
}
