package build

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/stretchr/testify/require"
)

// trace is the access pattern a daemon serves at /trace and `nydus optimize
// --trace-file` reads.
type trace struct {
	Version  int `json:"version"`
	Patterns []struct {
		BlobIndex       int `json:"blob_index"`
		ChunkGroupIndex int `json:"chunk_group_index"`
	} `json:"patterns"`
}

// TestOptimize records the access trace of a workload on a merged image,
// builds the ondemand blob from it with `nydus optimize`, and checks the
// result: the blob holds exactly the traced chunk groups, copied verbatim in
// access order; the rewritten bootstrap appends it to the device table and
// passes `nydus check`; and the optimized image, prefetching the ondemand
// blob, still reproduces the tree.
func TestOptimize(t *testing.T) {
	t.Parallel()
	nydus := env.Nydus(t)
	// optimize writes into the blob directory.
	img := fixture.Copy(t, fixture.Get(t, fixture.MergedPrefix+"zstd-4k"))
	parentSHA := fileSHA256(t, img.Bootstrap)
	parentTags, err := oracle.ErofsDeviceTags(img.Bootstrap)
	require.NoError(t, err)

	// The workload: the largest files, which span several chunk groups of
	// more than one layer, read largest first rather than in blob order.
	var files []oracle.Entry
	for _, e := range img.Want {
		if e.Type == "reg" && e.Size > 0 && e.SHA256 != "" {
			files = append(files, e)
		}
	}
	sort.SliceStable(files, func(i, j int) bool { return files[i].Size > files[j].Size })
	var workload []string
	for _, e := range files[:min(5, len(files))] {
		workload = append(workload, string(e.Path))
	}
	m := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
	for _, path := range workload {
		_, err := os.ReadFile(m.Path(path))
		require.NoError(t, err)
	}
	raw, err := m.API.Get("/trace")
	require.NoError(t, err)
	m.Unmount()
	var tr trace
	require.NoError(t, json.Unmarshal(raw, &tr), "trace: %s", raw)
	require.Equal(t, 1, tr.Version, "trace version")
	require.Greater(t, len(tr.Patterns), 1, "the workload must touch several chunk groups")

	dir := env.WorkDir(t)
	traceFile := filepath.Join(dir, "trace.json")
	require.NoError(t, os.WriteFile(traceFile, raw, 0o644))
	config := mount.LocalConfig(img.BlobDir, filepath.Join(dir, "cache")).Write(t, dir, "storage.json")
	optimized := filepath.Join(dir, "optimized.bootstrap")
	before := listFiles(t, img.BlobDir)
	fixture.Run(t, nydus, "optimize", "--parent-bootstrap", img.Bootstrap, "--bootstrap", optimized,
		"--blob-dir", img.BlobDir, "--config", config, "--trace-file", traceFile)

	require.Equal(t, parentSHA, fileSHA256(t, img.Bootstrap), "the parent bootstrap must be left untouched")
	added := newFiles(t, img.BlobDir, before)
	sort.Strings(added)
	require.Len(t, added, 2, "optimize writes the ondemand blob and its blob meta: %v", added)
	ondemand := filepath.Join(img.BlobDir, added[0])
	require.Equal(t, added[0]+".blob.meta", added[1])
	require.Equal(t, added[0], fileSHA256(t, ondemand), "the ondemand blob is named by its SHA256")
	tags, err := oracle.ErofsDeviceTags(optimized)
	require.NoError(t, err)
	require.Equal(t, append(append([]string(nil), parentTags...), added[0]), tags, "device table")
	requireVerified(t, optimized, img.BlobDir, append(append([]string(nil), img.Blobs...), ondemand))
	t.Run("AlreadyOptimizedTrace", func(t *testing.T) {
		tracePath := filepath.Join(dir, "optimized-trace.json")
		require.NoError(t, os.WriteFile(tracePath, []byte(fmt.Sprintf(
			`{"version":1,"patterns":[{"blob_index":%d,"chunk_group_index":0}]}`, len(tags))), 0o600))
		output := filepath.Join(dir, "reoptimized.boot")
		before := fileSHA256(t, optimized)
		out, err := formatCommand(t, "optimize", "--parent-bootstrap", optimized, "--bootstrap", output,
			"--blob-dir", img.BlobDir, "--config", config, "--trace-file", tracePath)
		require.Error(t, err, "%s", out)
		require.Contains(t, string(out), "already an ondemand blob")
		require.NoFileExists(t, output)
		require.Equal(t, before, fileSHA256(t, optimized))
	})

	// The ondemand blob's data region is every traced group's payload, as
	// stored in its source blob, deduplicated and in first-access order.
	var want bytes.Buffer
	seen := map[[2]int]bool{}
	offsets := map[string][]uint64{}
	for _, p := range tr.Patterns {
		key := [2]int{p.BlobIndex, p.ChunkGroupIndex}
		if seen[key] {
			continue
		}
		seen[key] = true
		require.True(t, p.BlobIndex >= 1 && p.BlobIndex <= len(parentTags), "trace names blob %d", p.BlobIndex)
		tag := parentTags[p.BlobIndex-1]
		if offsets[tag] == nil {
			offsets[tag] = chunkGroupOffsets(t, filepath.Join(img.BlobDir, tag+".blob.meta"))
		}
		groups := offsets[tag]
		require.Less(t, p.ChunkGroupIndex+1, len(groups), "trace names group %d of blob %d", p.ChunkGroupIndex, p.BlobIndex)
		want.Write(readRange(t, filepath.Join(img.BlobDir, tag), groups[p.ChunkGroupIndex], groups[p.ChunkGroupIndex+1]))
	}
	f := readFooter(t, ondemand)
	require.False(t, f.rawDevice())
	require.NotZero(t, f.MetaSize, "blob meta region of the ondemand blob")
	got := readRange(t, ondemand, f.DataOffset, f.DataOffset+f.DataSize)
	require.True(t, bytes.Equal(want.Bytes(), got),
		"ondemand blob data (%d bytes) is not the traced groups in access order (%d bytes)", len(got), want.Len())

	opt := img
	opt.Bootstrap = optimized
	opt.Blobs = append(append([]string(nil), img.Blobs...), ondemand)
	m = mount.Mount(t, mount.FUSE{}, opt, mount.Options{Config: func(c *mount.Config) {
		c.Prefetch = &mount.Prefetch{Scope: "ondemand"}
	}})
	// Reads race the prefetch of the ondemand blob into the sources' caches.
	oracle.VerifyMount(t, m.Root, opt.Want, opt.Compare())
}

func readRange(t env.TB, path string, start, end uint64) []byte {
	t.Helper()
	require.LessOrEqual(t, start, end)
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	buf := make([]byte, end-start)
	_, err = io.ReadFull(io.NewSectionReader(f, int64(start), int64(end-start)), buf)
	require.NoError(t, err, "reading [%d, %d) of %s", start, end, path)
	return buf
}
