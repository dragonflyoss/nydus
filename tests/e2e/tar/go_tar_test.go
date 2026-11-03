// The go* vector functions in this file are copied from the tests of
// Go's archive/tar package
// (src/archive/tar/{tar,reader,writer,strconv,fuzz}_test.go),
// Copyright 2009 The Go Authors, used under the BSD-3-Clause license in
// LICENSE-go.

package tar

import (
	"archive/tar"
	"bytes"
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

	"github.com/dragonflyoss/nydus/tests/e2e/util/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestGoTarCorpus(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
	testdata := corpus.GoTarTestdata(t)
	archives, err := filepath.Glob(filepath.Join(testdata, "*.tar*"))
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.NotEmpty(t, archives) {
		t.FailNow()
	}

	for _, path := range archives {
		name := strings.TrimSuffix(filepath.Base(path), corpus.ObscuredSuffix)
		if slices.Contains(corpus.GoTarHugeArchives, name) {
			continue
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			requireVerdict(t, (tarLayout{}).checkTarConversion(t, corpus.ReadGoTarArchive(t, path)))
		})
	}
}

func rawPAXArchive(pax []byte, name string, body []byte) []byte {
	return rawSizedArchive(pax, name, int64(len(body)), body)
}

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

func paxRecord(key, value string) string {
	n := len(key) + len(value) + 3

	total := n + len(strconv.Itoa(n))
	if len(strconv.Itoa(total)) > len(strconv.Itoa(n)) {
		total++
	}

	return fmt.Sprintf("%d %s=%s\n", total, key, value)
}

func rawTarHeader(name string, typeflag byte, size int64, gnu bool, edit func(blk []byte)) []byte {
	blk := make([]byte, 512)

	octal := func(field []byte, v int64) {
		copy(field, fmt.Sprintf("%0*o", len(field)-1, v))
	}

	copy(blk[0:100], name)
	octal(blk[100:108], 0o644)
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

	fixChecksum(blk)

	return blk
}

func numberedTarCases(archives [][]byte) []tarCase {
	cases := make([]tarCase, 0, len(archives))

	for i, data := range archives {
		cases = append(cases, tarCase{fmt.Sprintf("%02d", i), data})
	}

	return cases
}

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

func one(name string, hdr tar.Header) tarVector {
	return tarVector{name, []tarEntry{{hdr: hdr}}}
}

type allowedFormatsVector struct {
	header  *tar.Header
	formats tar.Format
}

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

func goHeaderRoundTrip() []tarVector {
	const (
		cISUID = 0o4000
		cISGID = 0o2000
		cISVTX = 0o1000
	)

	return []tarVector{
		one("regular", tar.Header{Name: "test.txt", Mode: 0o644, Size: 12, ModTime: time.Unix(1360600916, 0), Typeflag: tar.TypeReg}),
		one("symlink", tar.Header{Name: "link.txt", Mode: 0o777, ModTime: time.Unix(1360600852, 0), Typeflag: tar.TypeSymlink}),
		one("char", tar.Header{Name: "dev/null", Mode: 0o666, ModTime: time.Unix(1360578951, 0), Typeflag: tar.TypeChar}),
		one("block", tar.Header{Name: "dev/sda", Mode: 0o660, ModTime: time.Unix(1360578954, 0), Typeflag: tar.TypeBlock}),
		one("dir", tar.Header{Name: "dir/", Mode: 0o755, ModTime: time.Unix(1360601116, 0), Typeflag: tar.TypeDir}),
		one("fifo", tar.Header{Name: "dev/initctl", Mode: 0o600, ModTime: time.Unix(1360578949, 0), Typeflag: tar.TypeFifo}),
		one("setuid", tar.Header{Name: "bin/su", Mode: 0o755 | cISUID, Size: 23232, ModTime: time.Unix(1355405093, 0), Typeflag: tar.TypeReg}),
		one("setgid", tar.Header{Name: "group.txt", Mode: 0o750 | cISGID, ModTime: time.Unix(1360602346, 0), Typeflag: tar.TypeReg}),
		one("sticky", tar.Header{Name: "sticky.txt", Mode: 0o600 | cISVTX, Size: 7, ModTime: time.Unix(1360602540, 0), Typeflag: tar.TypeReg}),
		{"hardlink", []tarEntry{
			{hdr: tar.Header{Name: "file.txt", Mode: 0o644, ModTime: time.Unix(1360600916, 0), Typeflag: tar.TypeReg}},
			{hdr: tar.Header{Name: "hard.txt", Mode: 0o644, Linkname: "file.txt", ModTime: time.Unix(1360600916, 0), Typeflag: tar.TypeLink}},
		}},
		one("info", tar.Header{Name: "info.txt", Mode: 0o600, Uid: 1000, Gid: 1000, ModTime: time.Unix(1360602540, 0),
			Uname: "slartibartfast", Gname: "users", Typeflag: tar.TypeReg}),
	}
}

const fuzzLorem = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."

func goWriterVectors() []tarVector {
	vectors := []tarVector{
		one("Pax", tar.Header{Name: strings.Repeat("ab", 100), Mode: 0o644, Size: 5, Typeflag: tar.TypeReg}),
		one("PaxSymlink", tar.Header{Name: "small.txt", Mode: 0o644, Typeflag: tar.TypeSymlink,
			Linkname: strings.Repeat("1234567890/1234567890", 10)}),
		one("PaxNonAscii", tar.Header{Name: "文件名", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg, Gname: "組", Uname: "用戶名"}),
		{"PaxXattrs", []tarEntry{{hdr: tar.Header{Name: "small.txt", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg,
			Xattrs: map[string]string{"user.key": "value"}}, body: []byte("Kilts")}}}, //nolint:staticcheck
		one("PaxHeadersSorted", tar.Header{Name: "small.txt", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg,
			Xattrs: map[string]string{"foo": "foo", "bar": "bar", "baz": "baz", "qux": "qux"}}), //nolint:staticcheck
		one("USTARLongName", tar.Header{Typeflag: tar.TypeDir, Mode: 0o644,
			Name: "/0000_0000000/00000-000000000/0000_0000000/00000-0000000000000/0000_0000000/00000-0000000-00000000/0000_0000000/00000000/0000_0000000/000/0000_0000000/00000000v00/0000_0000000/000000/0000_0000000/0000000/0000_0000000/00000y-00/0000/0000/00000000/0x000000/"}),
		one("ValidTypeflagWithPAXHeader", tar.Header{Name: strings.Repeat("ab", 100), Size: 4}),
		one("TrailingSlash", tar.Header{Name: strings.Repeat("123456789/", 30)}),
		{"FileAndDir", []tarEntry{
			{hdr: tar.Header{Name: "small.txt", Size: 5}, body: []byte("Kilts")},
			{hdr: tar.Header{Name: "dir/"}},
		}},
		{"RoundTrip", []tarEntry{{hdr: tar.Header{Name: "file.txt", Uid: 1 << 21, Size: 18, ModTime: time.Unix(1700000000, 0),
			PAXRecords: map[string]string{"uid": "2097152"}, Format: tar.FormatPAX, Typeflag: tar.TypeReg},
			body: []byte("some file contents")}}},
		{"FuzzReaderSeed", []tarEntry{{hdr: tar.Header{Name: "lorem.txt", Mode: 0o600, Size: int64(len(fuzzLorem))},
			body: []byte(fuzzLorem)}}},
	}

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

	for i, name := range []string{"../foo", "/foo", "a/b/../../../c"} {
		vectors = append(vectors, tarVector{fmt.Sprintf("InsecurePaths-%d", i), []tarEntry{
			{hdr: tar.Header{Name: name}},
			{hdr: tar.Header{Name: "secure"}},
		}})
	}

	return vectors
}

func goReadTruncation(t *testing.T) []tarCase {
	t.Helper()
	testdata := corpus.GoTarTestdata(t)
	var ss []string

	for _, name := range []string{"gnu.tar", "ustar-file-reg.tar", "pax-path-hdr.tar", "sparse-formats.tar"} {
		ss = append(ss, string(corpus.ReadGoTarArchive(t, corpus.GoTarArchive(testdata, name))))
	}

	gnu, ustar, pax, sparse := ss[0], ss[1], ss[2], ss[3]
	ustar += strings.Repeat("\x00", 10*512)
	trash := strings.Repeat("garbage ", 64)

	inputs := []string{
		"",
		gnu[:511],
		gnu[:512],
		gnu[:1024],
		gnu[:1536],
		gnu[:2048],
		gnu,
		gnu[:2048] + ustar[:1536],
		ustar[:511],
		ustar[:512],
		ustar[:1195],
		ustar[:1196],
		ustar[:1200],
		ustar[:1535],
		ustar[:1536],
		ustar[:1536] + trash[:1],
		ustar[:1536] + trash[:511],
		ustar[:1536] + trash,
		ustar[:2048],
		ustar[:2048] + trash[:1],
		ustar[:2048] + trash[:511],
		ustar[:2048] + trash,
		ustar[:2560],
		ustar[:2560] + trash[:1],
		ustar[:2560] + trash[:511],
		ustar[:2560] + trash,
		ustar[:3072],
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
	data     string
	records  map[string]string
	extents  int64
	realSize string
}

func goGNUSparsePAXHeaders() []tarCase {
	vectors := goGNUSparsePAXVectors()
	var archives [][]byte

	for _, v := range vectors {
		body := append([]byte(v.data), tarBody(v.extents)...)
		archives = append(archives, rawPAXArchive(paxRecords(v.records), "sparse", body))
	}

	cases := numberedTarCases(archives)

	for i, v := range vectors {
		if v.realSize == "" {
			continue
		}

		records := maps.Clone(v.records)
		records["GNU.sparse.realsize"] = v.realSize

		cases = append(cases, tarCase{fmt.Sprintf("%02d-sized", i),
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
		return s + strings.Repeat("\x00", -len(s)&511)
	}

	sparseVersion := map[string]string{major: "1", minor: "0"}

	return []sparsePAXVector{
		{records: nil},
		{records: map[string]string{numBlocks: strconv.FormatInt(math.MaxInt64, 10), sparseMap: "0,1,2,3"}, extents: 4},
		{records: map[string]string{numBlocks: "4\x00", sparseMap: "0,1,2,3"}, extents: 4},
		{records: map[string]string{numBlocks: "4", sparseMap: "0,1,2,3"}, extents: 4},
		{records: map[string]string{numBlocks: "2", sparseMap: "0,1,2,3"}, extents: 4, realSize: "5"},
		{records: map[string]string{numBlocks: "2", sparseMap: "0, 1,2,3"}, extents: 4},
		{records: map[string]string{numBlocks: "2", sparseMap: "0,1,02,3", realSize: "4321"}, extents: 4},
		{records: map[string]string{numBlocks: "2", sparseMap: "0,one1,2,3"}, extents: 4},
		{records: map[string]string{major: "0", minor: "0", numBlocks: "2", sparseMap: "0,1,2,3",
			size: "1234", realSize: "4321", name: "realname"}, extents: 4},
		{records: map[string]string{major: "0", minor: "0", numBlocks: "1", sparseMap: "10737418240,512",
			size: "10737418240", name: "realname"}, extents: 512},
		{records: map[string]string{major: "0", minor: "0", numBlocks: "0", sparseMap: ""}},
		{records: map[string]string{major: "0", minor: "1", numBlocks: "4", sparseMap: "0,5,10,5,20,5,30,5"}, extents: 20, realSize: "35"},
		{records: map[string]string{major: "1", minor: "0", numBlocks: "4", sparseMap: "0,5,10,5,20,5,30,5"}},
		{data: pad("0\n"), records: sparseVersion},
		{data: pad("0\n")[:511] + "#", records: sparseVersion},
		{data: pad("0"), records: sparseVersion},
		{data: pad("ab\n"), records: sparseVersion},
		{data: pad("1\n2\n3\n"), records: sparseVersion, extents: 3},
		{data: pad("1\n2\n"), records: sparseVersion},
		{data: pad("1\n2\n\n"), records: sparseVersion},
		{data: strings.Repeat("\x00", 512) + pad("0\n"), records: sparseVersion},
		{data: strings.Repeat("0", 512) + pad("1\n5\n1\n"), records: sparseVersion, extents: 1},
		{data: pad(fmt.Sprintf("%d\n", int64(math.MaxInt64))), records: sparseVersion},
		{data: pad(strings.Repeat("0", 300) + "1\n" + strings.Repeat("0", 1000) + "5\n" + strings.Repeat("0", 800) + "2\n"),
			records: sparseVersion, extents: 2},
		{data: pad("2\n10737418240\n512\n21474836480\n512\n"), records: sparseVersion, extents: 1024},
		{data: pad("100\n" + func() string {
			var ss []string

			for i := range 100 {
				ss = append(ss, fmt.Sprintf("%d\n%d\n", int64(i)<<30, 512))
			}

			return strings.Join(ss, "")
		}()), records: sparseVersion, extents: 100 * 512},
	}
}

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
		copy(out, bytes.Repeat([]byte{0xff}, pad))
	} else {
		out[0] = 0x80
		out[pad] &= 0x7f
	}

	return out
}

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
		body := tarBody(int64(strings.Count(in, "numbytes=2\n")*2 + strings.Count(in, "numbytes=4\n")*4))
		archives = append(archives, rawPAXArchive([]byte(in), "f", body))
	}

	return numberedTarCases(archives)
}

func goReadOldGNUSparseMap() []tarCase {
	entries := func(spans ...[2]int64) []string {
		var out []string

		for _, s := range spans {
			out = append(out, string(gnuNumericField(s[0]))+string(gnuNumericField(s[1])))
		}

		return out
	}

	populate := func(blk []byte, base, limit, extended int, sps []string) []string {
		for i := 0; len(sps) > 0 && i < limit; i++ {
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

	var archives [][]byte
	var sized []tarCase

	add := func(archive []byte) { archives = append(archives, archive) }

	addSized := func(archive, variant []byte) {
		sized = append(sized, tarCase{fmt.Sprintf("%02d-sized", len(archives)), variant})
		add(archive)
	}

	add(complete(makeInput(false, "", 0), 0))
	add(complete(makeInput(true, "1234", 0, "fewa"), 0))
	add(complete(makeInput(true, "0031", 0), 0))
	add(complete(makeInput(true, "80", 0), 0))
	add(complete(makeInput(true, "1234", 1, entries([2]int64{0, 0}, [2]int64{1, 1})...), 1))
	add(complete(makeInput(true, "1234", 1, append(entries([2]int64{0, 0}, [2]int64{1, 1}), "", "blah")...), 1))
	add(complete(makeInput(true, "3333", 4, entries([2]int64{0, 1}, [2]int64{2, 1}, [2]int64{4, 1}, [2]int64{6, 1})...), 4))
	addSized(complete(makeInput(true, "", 4, extended...), 4), complete(makeInput(true, "12", 4, extended...), 4))
	add(makeInput(true, "", 6, six...)[:512])
	add(makeInput(true, "", 6, six...)[:3*512/2])
	addSized(complete(makeInput(true, "", 6, six...), 6), complete(makeInput(true, "16", 6, six...), 6))
	add(complete(makeInput(true, "", 1024, entries([2]int64{10 << 30, 512}, [2]int64{20 << 30, 512})...), 1024))

	return append(numberedTarCases(archives), sized...)
}

func gnuNumericField(v int64) []byte {
	if v < 1<<33 {
		return []byte(fmt.Sprintf("%011o\x00", v))
	}

	out := make([]byte, 12)
	binary.BigEndian.PutUint64(out[4:], uint64(v))
	out[0] = 0x80

	return out
}

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
		archives = append(archives, paxSparseArchive(v.spans, v.size, v.phys, []byte(v.str)))
	}

	return numberedTarCases(archives)
}

func paxSparseArchive(spans [][2]int64, size, phys int64, data []byte) []byte {
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

	return rawSizedArchive(records, "f", phys, data)
}

func goSparseEntries() []tarCase {
	s := func(spans ...[2]int64) [][2]int64 { return spans }
	var archives [][]byte

	for _, v := range []struct {
		spans [][2]int64
		size  int64
	}{
		{s(), 0},
		{s(), 5000},
		{s([2]int64{0, 5000}), 5000},
		{s([2]int64{1000, 4000}), 5000},
		{s([2]int64{0, 3000}), 5000},
		{s([2]int64{3000, 2000}), 5000},
		{s([2]int64{2000, 2000}), 5000},
		{s([2]int64{0, 2000}, [2]int64{8000, 2000}), 10000},
		{s([2]int64{0, 2000}, [2]int64{2000, 2000}, [2]int64{4000, 0}, [2]int64{4000, 3000}, [2]int64{7000, 1000},
			[2]int64{8000, 0}, [2]int64{8000, 2000}), 10000},
		{s([2]int64{0, 0}, [2]int64{1000, 0}, [2]int64{2000, 0}, [2]int64{3000, 0}, [2]int64{4000, 0}, [2]int64{5000, 0}), 5000},
		{s([2]int64{1, 0}), 0},
		{s([2]int64{-1, 0}), 100},
		{s([2]int64{0, -1}), 100},
		{s([2]int64{0, 0}), -100},
		{s([2]int64{math.MaxInt64, 3}, [2]int64{6, -5}), 35},
		{s([2]int64{1, 3}, [2]int64{6, -5}), 35},
		{s([2]int64{math.MaxInt64, math.MaxInt64}), math.MaxInt64},
		{s([2]int64{3, 3}), 5},
		{s([2]int64{2, 0}, [2]int64{1, 0}, [2]int64{0, 0}), 3},
		{s([2]int64{1, 3}, [2]int64{2, 2}), 10},
	} {
		var phys int64

		for _, span := range v.spans {
			if span[1] > 0 && span[1] < 1<<20 {
				phys += span[1]
			}
		}

		archives = append(archives, paxSparseArchive(v.spans, v.size, phys, tarBody(phys)))
	}

	return numberedTarCases(archives)
}

func goWriterAddFS(t *testing.T) []tarCase {
	t.Helper()
	fsys := fstest.MapFS{
		"emptyfolder":          {Mode: 0o755 | os.ModeDir},
		"file.go":              {Data: []byte("hello")},
		"subfolder/another.go": {Data: []byte("world")},
		"symlink.go":           {Mode: 0o777 | os.ModeSymlink, Data: []byte("file.go")},
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if !assert.NoError(t, tw.AddFS(fsys)) {
		t.FailNow()
	}

	assert.NoError(t, tw.Close())

	return []tarCase{{"MapFS", buf.Bytes()}}
}

func goFileInfoHeader(t *testing.T) []tarCase {
	t.Helper()
	dir := t.TempDir()
	small := filepath.Join(dir, "small.txt")
	if !assert.NoError(t, os.WriteFile(small, []byte("Kilts"), 0o644)) {
		t.FailNow()
	}
	if !assert.NoError(t, os.Chmod(small, 0o4755)) {
		t.FailNow()
	}
	if !assert.NoError(t, os.Mkdir(filepath.Join(dir, "subdir"), 0o750)) {
		t.FailNow()
	}
	if !assert.NoError(t, os.Symlink("small.txt", filepath.Join(dir, "link"))) {
		t.FailNow()
	}
	if !assert.NoError(t, unix.Mkfifo(filepath.Join(dir, "fifo"), 0o600)) {
		t.FailNow()
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	for _, name := range []string{"small.txt", "subdir", "link", "fifo"} {
		path := filepath.Join(dir, name)
		fi, err := os.Lstat(path)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		link, _ := os.Readlink(path)
		hdr, err := tar.FileInfoHeader(fi, link)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.NoError(t, tw.WriteHeader(hdr)) {
			t.FailNow()
		}

		if fi.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			_, err = tw.Write(data)
			assert.NoError(t, err)
		}
	}

	assert.NoError(t, tw.Close())

	return []tarCase{{"LocalFiles", buf.Bytes()}}
}

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
