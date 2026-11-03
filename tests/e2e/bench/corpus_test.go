package bench

import (
	"fmt"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
)

const (
	targetRel  = "large/file_0.bin"
	randRel    = "large/file_1.bin"
	statRel    = "small"
	readdirRel = "dirs"
	xattrRel   = "xattrs"
	xattrName  = "user.bench"
)

var imageLayout = fixture.Layout{Name: "bench", Args: []string{"--compressor", "zstd", "--chunk-size", "1048576"}}

func makePerfCorpus(t testing.TB, dir string, smallFileCount int) {
	t.Helper()
	c := corpus.New(t, dir)
	largeFileCount := env.Int(t, "NYDUS_E2E_BENCH_LARGE_FILE_COUNT", 8)
	largeFileSize := env.Int(t, "NYDUS_E2E_BENCH_LARGE_FILE_SIZE", 64<<20)
	mediumFileCount := env.Int(t, "NYDUS_E2E_BENCH_MEDIUM_FILE_COUNT", 256)
	mediumFileSize := env.Int(t, "NYDUS_E2E_BENCH_MEDIUM_FILE_SIZE", 1<<20)
	readdirDirs := env.Int(t, "NYDUS_E2E_BENCH_READDIR_DIRS", 128)
	readdirFilesPerDir := env.Int(t, "NYDUS_E2E_BENCH_READDIR_FILES_PER_DIR", 256)

	for i := range largeFileCount {
		c.CreateRandomFile(t, fmt.Sprintf("large/file_%d.bin", i), largeFileSize)
	}

	for i := range mediumFileCount {
		c.CreateRandomFile(t, fmt.Sprintf("medium/file_%04d.bin", i), mediumFileSize)
	}

	for i := range smallFileCount {
		c.CreateFile(t, fmt.Sprintf("small/file_%04d.txt", i), fmt.Appendf(nil, "content of small file %d\n", i))
	}

	for d := range readdirDirs {
		for f := range readdirFilesPerDir {
			c.CreateFile(t, fmt.Sprintf("dirs/d%02d/f%03d.txt", d, f), fmt.Appendf(nil, "d%d/f%d", d, f))
		}
	}

	for i := range 64 {
		name := fmt.Sprintf("xattrs/file_%02d", i)
		c.CreateFile(t, name, fmt.Appendf(nil, "xattr file %d\n", i))
		c.SetXattr(t, name, xattrName, []byte("value"))
	}
}
