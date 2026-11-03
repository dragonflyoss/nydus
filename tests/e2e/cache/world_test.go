package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
)

var imageRoot string

type world struct {
	lowerBlob, sharedBlob, upperBlob string
	lowerImage, upperImage           fixture.Image
	data                             map[string][]byte
	want                             map[string]string
}

var shared struct {
	sync.Mutex
	w      *world
	failed bool
}

func setup(t *testing.T) *world {
	t.Helper()
	mount.FUSE{}.Require(t)
	shared.Lock()
	defer shared.Unlock()

	if shared.failed {
		t.Fatal("the shared world failed to build in an earlier test")
	}

	if shared.w == nil {
		shared.failed = true
		shared.w = buildWorld(t, imageRoot)
		shared.failed = false
	}

	return shared.w
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func buildWorld(t testing.TB, dir string) *world {
	t.Helper()
	layout := fixture.MustLayout(t, "zstd-4k-group-64k")

	layers := []struct {
		file string
		size int
		seed uint64
	}{
		{"lower.bin", 1<<20 + 4096, 1},
		{"shared.bin", 12 << 20, 2},
		{"upper.bin", 1<<20 + 2048, 3},
	}

	w := &world{data: map[string][]byte{}, want: map[string]string{}}
	blobDir := filepath.Join(dir, "blobs")
	var blobs []string
	var trees [][]fstest.Entry

	for _, l := range layers {
		layer := strings.TrimSuffix(l.file, ".bin") + "-layer"
		src := filepath.Join(dir, layer)
		if err := os.MkdirAll(src, 0o755); !assert.NoError(t, err) {
			t.FailNow()
		}

		data := corpus.Bytes(l.seed, l.size)
		if err := os.WriteFile(filepath.Join(src, l.file), data, 0o644); !assert.NoError(t, err) {
			t.FailNow()
		}

		w.data[l.file] = data
		w.want[l.file] = sha256Hex(data)
		blob, _ := fixture.BuildInto(t, blobDir, filepath.Join(dir, layer+".bootstrap"), src, layout)
		blobs = append(blobs, blob)
		trees = append(trees, fstest.ScanSource(t, src))
	}

	merge := func(name string, lower, upper int) fixture.Image {
		bootstrap := filepath.Join(dir, name+".bootstrap")
		env.Run(t, env.Nydus(t), "merge", "--bootstrap", bootstrap, blobs[lower], blobs[upper])

		return fixture.Image{
			Name:      name,
			Layout:    layout,
			Bootstrap: bootstrap,
			BlobDir:   blobDir,
			Blobs:     []string{blobs[lower], blobs[upper]},
			Merged:    true,
			Want:      fstest.Overlay(trees[lower], trees[upper]),
		}
	}

	w.lowerBlob, w.sharedBlob, w.upperBlob = filepath.Base(blobs[0]), filepath.Base(blobs[1]), filepath.Base(blobs[2])
	w.lowerImage = merge("lower", 0, 1)
	w.upperImage = merge("upper", 1, 2)

	return w
}
