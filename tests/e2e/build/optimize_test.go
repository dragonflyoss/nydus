package build

import (
	"bytes"
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/erofs"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
)

func TestOptimize(t *testing.T) {
	t.Parallel()
	nydus := env.Nydus(t)

	img := fixture.Copy(t, fixture.Get(t, fixture.MergedPrefix+"zstd-4k"))
	parentSHA := fstest.FileSHA256(t, img.Bootstrap)
	parentTags, err := erofs.DeviceTags(img.Bootstrap)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	var files []fstest.Entry

	for _, e := range img.Want {
		if e.Type == fstest.TypeReg && e.Size > 0 && e.SHA256 != "" {
			files = append(files, e)
		}
	}

	slices.SortStableFunc(files, func(a, b fstest.Entry) int { return cmp.Compare(b.Size, a.Size) })
	var workload []string

	for _, e := range files[:min(5, len(files))] {
		workload = append(workload, string(e.Path))
	}

	m := mount.Mount(t, mount.FUSE{}, img, mount.Options{})

	for _, path := range workload {
		_, err := os.ReadFile(m.Path(path))
		assert.NoError(t, err)
	}

	raw, err := m.API.Get("/trace")
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	tr := m.API.Trace(t)
	m.Unmount()

	if !assert.Greater(t, len(tr.Patterns), 1) {
		t.FailNow()
	}

	dir := env.WorkDir(t)
	traceFile := filepath.Join(dir, "trace.json")
	if !assert.NoError(t, os.WriteFile(traceFile, raw, 0o644)) {
		t.FailNow()
	}

	config := mount.LocalConfig(img.BlobDir, filepath.Join(dir, "cache")).Write(t, dir, "storage.json")
	optimized := filepath.Join(dir, "optimized.bootstrap")
	before := fixture.ListDir(t, img.BlobDir)

	env.Run(t, nydus, "optimize", "--parent-bootstrap", img.Bootstrap, "--bootstrap", optimized,
		"--blob-dir", img.BlobDir, "--config", config, "--trace-file", traceFile)

	if !assert.Equal(t, parentSHA, fstest.FileSHA256(t, img.Bootstrap)) {
		t.FailNow()
	}

	added := newFiles(t, img.BlobDir, before)
	slices.Sort(added)

	if !assert.Len(t, added, 2) {
		t.FailNow()
	}

	ondemand := filepath.Join(img.BlobDir, added[0])

	if !assert.Equal(t, added[0]+mount.CacheMetaSuffix, added[1]) {
		t.FailNow()
	}
	if !assert.Equal(t, added[0], fstest.FileSHA256(t, ondemand)) {
		t.FailNow()
	}

	tags, err := erofs.DeviceTags(optimized)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.Equal(t, append(append([]string(nil), parentTags...), added[0]), tags) {
		t.FailNow()
	}

	requireVerified(t, optimized, img.BlobDir, append(append([]string(nil), img.Blobs...), ondemand))

	t.Run("AlreadyOptimizedTrace", func(t *testing.T) {
		tracePath := filepath.Join(dir, "optimized-trace.json")
		if !assert.NoError(t, os.WriteFile(tracePath, []byte(fmt.Sprintf(
			`{"version":1,"patterns":[{"blob_index":%d,"chunk_group_index":0}]}`, len(tags))), 0o600)) {
			t.FailNow()
		}

		output := filepath.Join(dir, "reoptimized.boot")
		before := fstest.FileSHA256(t, optimized)

		out, err := runNydus(t, "optimize", "--parent-bootstrap", optimized, "--bootstrap", output,
			"--blob-dir", img.BlobDir, "--config", config, "--trace-file", tracePath)

		if !assert.Error(t, err) {
			t.FailNow()
		}

		assert.Contains(t, string(out), "already an ondemand blob")
		assert.NoFileExists(t, output)
		assert.Equal(t, before, fstest.FileSHA256(t, optimized))
	})

	var want bytes.Buffer
	seen := map[[2]int]bool{}
	offsets := map[string][]uint64{}

	for _, p := range tr.Patterns {
		key := [2]int{p.BlobIndex, p.ChunkGroupIndex}
		if seen[key] {
			continue
		}

		seen[key] = true

		if !assert.GreaterOrEqual(t, p.BlobIndex, 1) || !assert.LessOrEqual(t, p.BlobIndex, len(parentTags)) {
			t.FailNow()
		}

		tag := parentTags[p.BlobIndex-1]
		if offsets[tag] == nil {
			offsets[tag] = blobFile(filepath.Join(img.BlobDir, tag)).chunkGroupOffsets(t)
		}

		groups := offsets[tag]
		if !assert.Less(t, p.ChunkGroupIndex+1, len(groups)) {
			t.FailNow()
		}

		start, end := groups[p.ChunkGroupIndex], groups[p.ChunkGroupIndex+1]
		data, err := fstest.ReadAt(filepath.Join(img.BlobDir, tag), int64(start), int64(end-start))
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		want.Write(data)
	}

	f := blobFile(ondemand).footer(t)
	if !assert.False(t, f.rawDevice()) {
		t.FailNow()
	}
	if !assert.NotZero(t, f.metaSize) {
		t.FailNow()
	}

	got, err := fstest.ReadAt(ondemand, int64(f.dataOffset), int64(f.dataSize))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.True(t, bytes.Equal(want.Bytes(), got))

	opt := img
	opt.Bootstrap = optimized
	opt.Blobs = append(append([]string(nil), img.Blobs...), ondemand)

	m = mount.Mount(t, mount.FUSE{}, opt, mount.Options{Config: func(c *mount.Config) {
		c.Prefetch = &mount.PrefetchConfig{Scope: "ondemand"}
	}})

	fstest.VerifyMount(t, m.Root, opt.Want, opt.Compare())
}

func TestOptimizeReject(t *testing.T) {
	t.Parallel()
	base := fixture.Get(t, "zstd-4k")

	for _, tc := range []struct {
		name, trace  string
		mixedParent  bool
		outputIsDir  bool
		wantInOutput string
	}{
		{name: "Malformed", trace: `{"version":`},
		{name: "Version", trace: `{"version":999,"patterns":[]}`},
		{name: "Empty", trace: `{"version":1,"patterns":[]}`},
		{name: "UnknownBlob", trace: `{"version":1,"patterns":[{"blob_index":65535,"chunk_group_index":0}]}`},
		{name: "UnknownGroup", trace: `{"version":1,"patterns":[{"blob_index":1,"chunk_group_index":4294967295}]}`},
		{name: "IndexOverflow", trace: `{"version":1,"patterns":[{"blob_index":65536,"chunk_group_index":0}]}`},
		{name: "OutputFailure", trace: `{"version":1,"patterns":[{"blob_index":1,"chunk_group_index":0}]}`, outputIsDir: true},
		{
			name:         "MixedCompressors",
			trace:        `{"version":1,"patterns":[{"blob_index":1,"chunk_group_index":0},{"blob_index":2,"chunk_group_index":0}]}`,
			mixedParent:  true,
			wantInOutput: "the other source blobs",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			img := base

			if tc.mixedParent {
				img.Bootstrap, img.BlobDir = filepath.Join(dir, "parent.boot"), filepath.Join(dir, "sources")
				if !assert.NoError(t, os.Mkdir(img.BlobDir, 0o755)) {
					t.FailNow()
				}

				var blobs []string

				for _, layout := range []string{"lz4-64k", "zstd-4k"} {
					blob := fixture.Get(t, layout).Blob(t)
					if !assert.NoError(t, os.Symlink(blob, filepath.Join(img.BlobDir, filepath.Base(blob)))) {
						t.FailNow()
					}

					blobs = append(blobs, blob)
				}

				env.Run(t, env.Nydus(t), append([]string{"merge", "--bootstrap", img.Bootstrap}, blobs...)...)
			}

			parent := fstest.FileSHA256(t, img.Bootstrap)
			trace := filepath.Join(dir, "trace.json")
			if !assert.NoError(t, os.WriteFile(trace, []byte(tc.trace), 0o600)) {
				t.FailNow()
			}

			output := filepath.Join(dir, "optimized.boot")

			if tc.outputIsDir {
				if !assert.NoError(t, os.Mkdir(output, 0o755)) {
					t.FailNow()
				}
			}

			config := mount.LocalConfig(img.BlobDir, filepath.Join(dir, "cache")).Write(t, dir, "config.json")

			out, err := runNydus(t, "optimize",
				"--parent-bootstrap", img.Bootstrap, "--bootstrap", output, "--blob-dir", filepath.Join(dir, "blobs"),
				"--config", config, "--trace-file", trace)

			if !assert.Error(t, err) {
				t.FailNow()
			}
			if !assert.Contains(t, string(out), "error") {
				t.FailNow()
			}

			assert.Contains(t, string(out), tc.wantInOutput)
			assert.Equal(t, parent, fstest.FileSHA256(t, img.Bootstrap))

			if !tc.outputIsDir {
				assert.NoFileExists(t, output)
			}
		})
	}
}

// TestOptimizeDedup builds a tree whose two identical 2 MiB files share one
// lone chunk, records what reading them touches and optimizes that record.
// The aliased file's chunk index names the surviving group, so the record
// and the ondemand blob see one copy. The same tree built without a digester
// cannot deduplicate and records both groups.
func TestOptimizeDedup(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)

	dir := env.WorkDir(t)
	source := filepath.Join(dir, "source")
	if !assert.NoError(t, os.MkdirAll(filepath.Join(source, "nested"), 0o755)) {
		t.FailNow()
	}

	// a.bin and nested/b.bin are one lone chunk each, so the second
	// deduplicates into the first; c.bin differs and keeps its group.
	shared := corpus.Bytes(1, 2<<20)
	files := map[string][]byte{
		"a.bin":        shared,
		"nested/b.bin": shared,
		"c.bin":        corpus.Bytes(2, 2<<20),
	}
	for name, data := range files {
		if !assert.NoError(t, os.WriteFile(filepath.Join(source, name), data, 0o644)) {
			t.FailNow()
		}
	}

	layout := fixture.MustLayout(t, "zstd")
	blobDir := filepath.Join(dir, "blobs")
	bootstrap := filepath.Join(dir, "image.boot")
	blob, _ := fixture.BuildInto(t, blobDir, bootstrap, source, layout)
	img := fixture.Image{Layout: layout, Bootstrap: bootstrap, BlobDir: blobDir, Blobs: []string{blob}}

	// The aliased file resolves to the same group as the file it aliases.
	canonical, _ := traceRead(t, img, "a.bin")
	aliased, raw := traceRead(t, img, "nested/b.bin")
	if !assert.Len(t, canonical.Patterns, 1) || !assert.Len(t, aliased.Patterns, 1) {
		t.FailNow()
	}
	assert.Equal(t, canonical.Patterns, aliased.Patterns)

	// Reading both still records the shared group once.
	both, _ := traceRead(t, img, "a.bin", "nested/b.bin")
	assert.Len(t, both.Patterns, 1)

	// Without a digester the build cannot deduplicate: both copies are
	// stored and reading both files records both groups.
	plain := fixture.MustLayout(t, "zstd-no-digest")
	plainDir := filepath.Join(dir, "plain-blobs")
	plainBoot := filepath.Join(dir, "plain.boot")
	plainBlob, _ := fixture.BuildInto(t, plainDir, plainBoot, source, plain)
	plainImg := fixture.Image{Layout: plain, Bootstrap: plainBoot, BlobDir: plainDir, Blobs: []string{plainBlob}}
	plainBoth, _ := traceRead(t, plainImg, "a.bin", "nested/b.bin")
	assert.Len(t, plainBoth.Patterns, 2)

	// Optimizing the aliased file's record copies the group once.
	traceFile := filepath.Join(dir, "trace.json")
	if !assert.NoError(t, os.WriteFile(traceFile, raw, 0o644)) {
		t.FailNow()
	}
	config := mount.LocalConfig(blobDir, filepath.Join(dir, "optimize-cache")).Write(t, dir, "storage.json")
	optimized := filepath.Join(dir, "optimized.boot")
	before := fixture.ListDir(t, blobDir)
	env.Run(t, env.Nydus(t), "optimize", "--parent-bootstrap", bootstrap, "--bootstrap", optimized,
		"--blob-dir", blobDir, "--config", config, "--trace-file", traceFile)
	ondemand := requireOndemandBlob(t, blobDir, before, 1)

	opt := img
	opt.Bootstrap = optimized
	opt.Blobs = append(append([]string(nil), img.Blobs...), ondemand)
	m := mount.Mount(t, mount.FUSE{}, opt, mount.Options{Config: func(c *mount.Config) {
		c.Prefetch = &mount.PrefetchConfig{Scope: "ondemand"}
	}})
	for name := range files {
		assert.Equal(t, fstest.FileSHA256(t, filepath.Join(source, name)), fstest.FileSHA256(t, m.Path(name)))
	}
}

// TestOptimizeMergedAlias merges two layers carrying the same 2 MiB file,
// reads only the upper layer's copy and optimizes that record. Merge
// rewrote the copy's chunk index to the lower layer, so the record names
// the lower blob and the ondemand blob holds the group once.
func TestOptimizeMergedAlias(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)

	dir := env.WorkDir(t)
	layout := fixture.MustLayout(t, "zstd")
	shared := corpus.Bytes(3, 2<<20)

	lower := filepath.Join(dir, "lower")
	upper := filepath.Join(dir, "upper")
	if !assert.NoError(t, os.MkdirAll(filepath.Join(lower, "keep"), 0o755)) ||
		!assert.NoError(t, os.MkdirAll(filepath.Join(upper, "dup"), 0o755)) {
		t.FailNow()
	}
	if !assert.NoError(t, os.WriteFile(filepath.Join(lower, "keep/a.bin"), shared, 0o644)) ||
		!assert.NoError(t, os.WriteFile(filepath.Join(upper, "dup/b.bin"), shared, 0o644)) {
		t.FailNow()
	}

	blobDir := filepath.Join(dir, "blobs")
	lowerBlob, _ := fixture.BuildInto(t, blobDir, filepath.Join(dir, "lower.boot"), lower, layout)
	upperBlob, _ := fixture.BuildInto(t, blobDir, filepath.Join(dir, "upper.boot"), upper, layout)

	merged := filepath.Join(dir, "merged.boot")
	env.Run(t, env.Nydus(t), "merge", "--bootstrap", merged, lowerBlob, upperBlob)
	img := fixture.Image{Layout: layout, Bootstrap: merged, BlobDir: blobDir,
		Blobs: []string{lowerBlob, upperBlob}, Merged: true}

	// Only the upper layer's file is read; the record names the lower
	// layer's group because merge rewrote the chunk index.
	tr, raw := traceRead(t, img, "dup/b.bin")
	if !assert.Len(t, tr.Patterns, 1) {
		t.FailNow()
	}
	if !assert.Equal(t, 1, tr.Patterns[0].BlobIndex) {
		t.FailNow()
	}

	traceFile := filepath.Join(dir, "trace.json")
	if !assert.NoError(t, os.WriteFile(traceFile, raw, 0o644)) {
		t.FailNow()
	}
	config := mount.LocalConfig(blobDir, filepath.Join(dir, "optimize-cache")).Write(t, dir, "storage.json")
	optimized := filepath.Join(dir, "optimized.boot")
	before := fixture.ListDir(t, blobDir)
	env.Run(t, env.Nydus(t), "optimize", "--parent-bootstrap", merged, "--bootstrap", optimized,
		"--blob-dir", blobDir, "--config", config, "--trace-file", traceFile)
	ondemand := requireOndemandBlob(t, blobDir, before, 1)

	opt := img
	opt.Bootstrap = optimized
	opt.Blobs = append(append([]string(nil), img.Blobs...), ondemand)
	m := mount.Mount(t, mount.FUSE{}, opt, mount.Options{Config: func(c *mount.Config) {
		c.Prefetch = &mount.PrefetchConfig{Scope: "ondemand"}
	}})
	assert.Equal(t, fstest.FileSHA256(t, filepath.Join(lower, "keep/a.bin")), fstest.FileSHA256(t, m.Path("keep/a.bin")))
	assert.Equal(t, fstest.FileSHA256(t, filepath.Join(upper, "dup/b.bin")), fstest.FileSHA256(t, m.Path("dup/b.bin")))
}

// traceRead mounts img cold, reads paths, and returns the /trace document
// and its raw JSON before unmounting.
func traceRead(t testing.TB, img fixture.Image, paths ...string) (mount.Trace, []byte) {
	t.Helper()
	m := mount.Mount(t, mount.FUSE{}, img, mount.Options{})
	for _, path := range paths {
		if _, err := os.ReadFile(m.Path(path)); !assert.NoError(t, err) {
			t.FailNow()
		}
	}
	raw, err := m.API.Get("/trace")
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	tr := m.API.Trace(t)
	m.Unmount()
	return tr, raw
}

// requireOndemandBlob checks optimize appended a blob and its meta to
// blobDir, that the blob holds `groups` chunk groups, and returns its path.
func requireOndemandBlob(t testing.TB, blobDir string, before map[string]bool, groups int) string {
	t.Helper()
	added := newFiles(t, blobDir, before)
	slices.Sort(added)
	if !assert.Len(t, added, 2) {
		t.FailNow()
	}
	ondemand := filepath.Join(blobDir, added[0])
	assert.Equal(t, added[0]+mount.CacheMetaSuffix, added[1])
	assert.Equal(t, added[0], fstest.FileSHA256(t, ondemand))
	if !assert.Len(t, blobFile(ondemand).chunkGroupOffsets(t), groups+1) {
		t.FailNow()
	}
	return ondemand
}

func newFiles(t testing.TB, dir string, before map[string]bool) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	var names []string

	for _, entry := range entries {
		if entry.Type().IsRegular() && !before[entry.Name()] {
			names = append(names, entry.Name())
		}
	}

	return names
}
