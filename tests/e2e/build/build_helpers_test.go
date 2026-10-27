// Package build tests `nydus build`, `merge`, `check` and `optimize` as
// command-line tools: their output contract, fsck.erofs, reproducibility and
// the trees the images they write reproduce.
package build

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/stretchr/testify/require"
)

// checkReport is what `nydus check --output json` prints.
type checkReport struct {
	Kind  string `json:"kind"`
	Blobs []struct {
		Index          int    `json:"index"`
		SlotSHA256     string `json:"slot_sha256"`
		SlotSHA256Kind string `json:"slot_sha256_kind"`
		Verified       bool   `json:"verified"`
	} `json:"blobs"`
}

// nydusCheck runs `nydus check --output json` with args. err is the exit
// status; the report is parsed whenever the command printed one.
func nydusCheck(t env.TB, args ...string) (checkReport, error) {
	t.Helper()
	args = append([]string{"check", "--output", "json"}, args...)
	cmd := exec.Command(env.Nydus(t), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil {
		err = fmt.Errorf("nydus %s: %w\n%s%s", strings.Join(args, " "), err, stdout.String(), stderr.String())
	}
	var report checkReport
	if out := bytes.TrimSpace(stdout.Bytes()); len(out) > 0 && out[0] == '{' {
		require.NoError(t, json.Unmarshal(out, &report), "parsing the check report:\n%s", out)
	}
	return report, err
}

// requireVerified checks a bootstrap and its blob directory with `nydus
// check` and asserts it resolved and verified exactly blobs, in device order.
func requireVerified(t env.TB, bootstrap, blobDir string, blobs []string) {
	t.Helper()
	report, err := nydusCheck(t, "--bootstrap", bootstrap, "--blob-dir", blobDir)
	require.NoError(t, err)
	require.Equal(t, "bootstrap", report.Kind)
	require.Len(t, report.Blobs, len(blobs), "blobs in the check report")
	for i, blob := range report.Blobs {
		require.Equal(t, filepath.Base(blobs[i]), blob.SlotSHA256, "device %d", i+1)
		require.True(t, blob.Verified, "device %d (%s) is not verified", i+1, blob.SlotSHA256)
	}
}

// The full-blob footer: the last 4KiB of every blob `nydus build` writes.
const (
	footerSize      = 4096
	footerMagic     = "NDFOOTER"
	footerRawDevice = 1 << 1
)

type footer struct {
	Incompat   uint32
	DataOffset uint64
	DataSize   uint64
	MetaOffset uint64
	MetaSize   uint64
}

func (f footer) rawDevice() bool { return f.Incompat&footerRawDevice != 0 }

func readFooter(t env.TB, blob string) footer {
	t.Helper()
	f, err := os.Open(blob)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	require.NoError(t, err)
	require.GreaterOrEqual(t, st.Size(), int64(footerSize), "%s is shorter than a footer", blob)
	buf := make([]byte, footerSize)
	_, err = f.ReadAt(buf, st.Size()-footerSize)
	require.NoError(t, err)
	require.Equal(t, footerMagic, string(buf[:8]), "footer magic of %s", blob)
	le := binary.LittleEndian
	return footer{
		Incompat:   le.Uint32(buf[12:]),
		DataOffset: le.Uint64(buf[24:]),
		DataSize:   le.Uint64(buf[32:]),
		MetaOffset: le.Uint64(buf[64:]),
		MetaSize:   le.Uint64(buf[72:]),
	}
}

// flipByte inverts the byte at off of path.
func flipByte(t env.TB, path string, off int64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	b := make([]byte, 1)
	_, err = f.ReadAt(b, off)
	require.NoError(t, err)
	b[0] ^= 0xff
	_, err = f.WriteAt(b, off)
	require.NoError(t, err)
}

func fileSHA256(t env.TB, path string) string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	h := sha256.New()
	_, err = io.Copy(h, f)
	require.NoError(t, err)
	return hex.EncodeToString(h.Sum(nil))
}

// compressor returns the --compressor a layout builds with.
func compressor(layout fixture.Layout) string {
	for i, arg := range layout.Args {
		if arg == "--compressor" && i+1 < len(layout.Args) {
			return layout.Args[i+1]
		}
	}
	return ""
}

var fsckVersion struct {
	once         sync.Once
	major, minor int
}

// fsckDecodes reports whether the installed fsck.erofs can extract images of
// layout. erofs-utils 1.7.1 (Ubuntu 24.04) has no zstd support and cannot
// decode the LZ4 packed inode the kernel reads fine; the kernel suite is the
// independent judge of those layouts there.
func fsckDecodes(t env.TB, layout fixture.Layout) bool {
	t.Helper()
	if c := compressor(layout); c != "erofs-lz4" && c != "erofs-zstd" {
		return true
	}
	fsck := env.RequireTool(t, "fsck.erofs")
	fsckVersion.once.Do(func() {
		out, _ := exec.Command(fsck, "-V").CombinedOutput()
		if m := regexp.MustCompile(`(\d+)\.(\d+)`).FindStringSubmatch(string(out)); m != nil {
			fsckVersion.major, _ = strconv.Atoi(m[1])
			fsckVersion.minor, _ = strconv.Atoi(m[2])
		}
	})
	if fsckVersion.major > 1 || (fsckVersion.major == 1 && fsckVersion.minor >= 8) {
		return true
	}
	t.Logf("fsck.erofs %d.%d cannot decode %s images; left to the kernel suite", fsckVersion.major, fsckVersion.minor, layout.Name)
	return false
}

// requireCacheArtifacts asserts the persistent cache holds the data, chunk
// group map and blob meta of exactly blobs, named by their full-blob digest.
func requireCacheArtifacts(t env.TB, cacheDir string, blobs []string) {
	t.Helper()
	entries, err := os.ReadDir(cacheDir)
	require.NoError(t, err)
	counts := map[string]int{}
	for _, entry := range entries {
		for _, suffix := range []string{".blob.data", ".group.map", ".blob.meta"} {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), suffix) {
				counts[suffix]++
			}
		}
	}
	for _, suffix := range []string{".blob.data", ".group.map", ".blob.meta"} {
		require.Equal(t, len(blobs), counts[suffix], "%s files in %s", suffix, cacheDir)
		for _, blob := range blobs {
			require.FileExists(t, filepath.Join(cacheDir, filepath.Base(blob)+suffix))
		}
	}
}

// The blob meta (NDBLMETA) sidecar: a 24-byte header, then tables at 8-byte
// boundaries, each with a header naming its kind, header size, entry size
// and entry count. Table 1 holds the chunk groups plus a terminator; an
// entry starts with the group's offset in the blob.
const (
	blobMetaMagic       = "NDBLMETA"
	chunkGroupTable     = 1
	chunkGroupEntrySize = 24
)

// chunkGroupOffsets returns where each chunk group of a blob starts, plus
// where the last one ends, read from the blob's meta sidecar.
func chunkGroupOffsets(t env.TB, metaPath string) []uint64 {
	t.Helper()
	meta, err := os.ReadFile(metaPath)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(meta), 24)
	require.Equal(t, blobMetaMagic, string(meta[:8]), "magic of %s", metaPath)
	le := binary.LittleEndian
	offset := 24
	for i := 0; i < int(le.Uint16(meta[20:])); i++ {
		offset = (offset + 7) / 8 * 8
		require.LessOrEqual(t, offset+16, len(meta), "table %d header of %s", i, metaPath)
		header := meta[offset:]
		headerSize := int(le.Uint16(header[2:]))
		entrySize := int(le.Uint32(header[8:]))
		count := int(le.Uint32(header[12:]))
		size := headerSize + entrySize*count
		require.LessOrEqual(t, offset+size, len(meta), "table %d of %s", i, metaPath)
		if le.Uint16(header) == chunkGroupTable {
			require.Equal(t, chunkGroupEntrySize, entrySize, "chunk group entry size")
			offsets := make([]uint64, count)
			for j := range offsets {
				offsets[j] = le.Uint64(meta[offset+headerSize+j*entrySize:])
			}
			return offsets
		}
		offset += size
	}
	t.Fatalf("%s has no chunk group table", metaPath)
	return nil
}

// newFiles returns the regular files in dir that are not in before.
func newFiles(t env.TB, dir string, before map[string]bool) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, entry := range entries {
		if entry.Type().IsRegular() && !before[entry.Name()] {
			names = append(names, entry.Name())
		}
	}
	return names
}

func listFiles(t env.TB, dir string) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	for _, name := range newFiles(t, dir, nil) {
		names[name] = true
	}
	return names
}
