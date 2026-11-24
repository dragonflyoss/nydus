//go:build manual

package nydusify

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/stream"
	"github.com/stretchr/testify/assert"
)

const (
	// hugeExtent is the unit a generated file picks its content by.
	hugeExtent = 1 << 20
	// hugeSmallFile is the mean size of the files of the small-file layer.
	hugeSmallFile = 40 << 10
)

// TestHugeImage converts a generated OCI image of NYDUS_E2E_HUGE_IMAGE_GIB
// (default 100) to each compressor, checks it with nydusify, mounts it and
// compares every file with the digest taken while generating it.
//
// The image is streamed into the registry and never staged, and its content
// compresses well, so the source and the converted images take little disk.
// What takes disk is reading it back: `nydusify check --source` extracts the
// OCI image, and a chunk-based mount caches every chunk it decodes. Both
// need about the size of the image's data that is not zero;
// NYDUS_E2E_HUGE_IMAGE_DENSITY (percent, default 100) lowers that share and
// NYDUS_E2E_HUGE_IMAGE_CHECK_SOURCE=false leaves the source out of the check.
func TestHugeImage(t *testing.T) {
	t.Parallel()
	env.MustHaveRoot(t)
	mount.FUSE{}.Require(t)

	image := &hugeImage{
		size:    int64(env.Int(t, "NYDUS_E2E_HUGE_IMAGE_GIB", 100)) << 30,
		density: uint64(env.Int(t, "NYDUS_E2E_HUGE_IMAGE_DENSITY", 100)),
		sums:    map[string]string{},
	}
	checkSource := env.Bool(t, "NYDUS_E2E_HUGE_IMAGE_CHECK_SOURCE", true)

	compressors := "zstd erofs-lz4"
	if v := os.Getenv("NYDUS_E2E_HUGE_IMAGE_COMPRESSORS"); v != "" {
		compressors = v
	}

	reg := registry.Start(t)
	source := reg.Ref("huge", "oci")
	start := time.Now()
	image.push(t, reg, source)
	t.Logf("pushed %d files in %s", len(image.sums), time.Since(start).Round(time.Second))

	// One compressor at a time: each holds its scratch data until it ends.
	for _, compressor := range strings.Fields(compressors) {
		t.Run(compressor, func(t *testing.T) {
			target := reg.Ref("huge", compressor)
			flags := []string{"--target", target, "--builder", env.Nydus(t), "--target-plain-http", "--source-plain-http"}
			step := func(what string, args ...string) {
				start := time.Now()
				env.Run(t, env.Nydusify(t), append(args, flags...)...)
				t.Logf("%s took %s", what, time.Since(start).Round(time.Second))
			}

			step("convert", "convert", "--source", source, "--compressor", compressor)

			check := []string{"check", "--work-dir", env.WorkDir(t)}
			if checkSource {
				check = append(check, "--source", source)
			}

			step("check", check...)

			// The blobs are served from a local directory: a registry
			// backend does not serve the native erofs-* layers.
			start := time.Now()
			mnt := mount.Mount(t, mount.FUSE{}, ref(target).pull(t, nil), mount.Options{})
			image.verify(t, mnt.Root)
			t.Logf("mount and verify took %s", time.Since(start).Round(time.Second))
		})
	}
}

// hugeImage generates the layers of the image and remembers what it wrote.
type hugeImage struct {
	size int64
	// density is the percentage of extents that hold data; the rest are
	// zeros, which a chunk-based layer stores as holes.
	density uint64

	mu sync.Mutex
	// sums holds the hex SHA-256 of every generated file by its path.
	sums map[string]string
}

// push streams the image to ref as three gzip layers: one file of 48% of
// the size, far past every 32-bit offset; 48 files of 1% each; and the
// remaining 4% as small files, a thousand per directory.
func (g *hugeImage) push(t *testing.T, reg *registry.Registry, ref string) {
	t.Helper()

	sizes := rand.New(rand.NewPCG(1, 2))

	reg.PushLayers(t, ref,
		g.layer("huge", 1, func(int) string { return "huge/one" }, func(int) int64 { return g.size / 100 * 48 }),
		g.layer("mid", 48, func(i int) string { return fmt.Sprintf("mid/%02d", i) }, func(int) int64 { return g.size / 100 }),
		g.layer("small", int(g.size/100*4/hugeSmallFile),
			func(i int) string { return fmt.Sprintf("small/%04d/%03d", i/1000, i%1000) },
			func(int) int64 { return sizes.Int64N(2 * hugeSmallFile) }),
	)
}

// layer returns a layer of the directory dir and count files below it, whose
// tar stream is generated as it is uploaded.
func (g *hugeImage) layer(dir string, count int, path func(int) string, size func(int) int64) v1.Layer {
	pr, pw := io.Pipe()

	go func() {
		tw := tar.NewWriter(pw)

		err := g.writeFiles(tw, dir, count, path, size)
		if err == nil {
			err = tw.Close()
		}

		_ = pw.CloseWithError(err)
	}()

	return stream.NewLayer(pr, stream.WithCompressionLevel(gzip.BestSpeed))
}

// writeFiles writes the directory dir and count files below it. Every
// directory of a path is written before its first file.
func (g *hugeImage) writeFiles(tw *tar.Writer, dir string, count int, path func(int) string, size func(int) int64) error {
	modTime := time.Unix(1700000000, 0)
	buf := make([]byte, hugeExtent)
	dirs := map[string]bool{}

	mkdir := func(dir string) error {
		if dirs[dir] {
			return nil
		}

		dirs[dir] = true

		return tw.WriteHeader(&tar.Header{Name: dir + "/", Typeflag: tar.TypeDir, Mode: 0o755, ModTime: modTime})
	}

	if err := mkdir(dir); err != nil {
		return err
	}

	for i := range count {
		name, size := path(i), size(i)
		if err := mkdir(filepath.Dir(name)); err != nil {
			return err
		}

		hdr := &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: size, ModTime: modTime}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}

		seed := fnv.New64a()
		_, _ = seed.Write([]byte(name))
		sum := sha256.New()

		for off := int64(0); off < size; off += hugeExtent {
			data := buf[:min(size-off, hugeExtent)]
			g.fill(data, seed.Sum64(), uint64(off/hugeExtent))
			_, _ = sum.Write(data)

			if _, err := tw.Write(data); err != nil {
				return err
			}
		}

		g.mu.Lock()
		g.sums[name] = hex.EncodeToString(sum.Sum(nil))
		g.mu.Unlock()
	}

	return nil
}

// fill writes extent index of the file of seed into data: zeros outside the
// density, else random bytes for one extent in 512 and for the others 4KiB
// blocks of a repeated 16-byte stamp of the seed and the block's position,
// so that data read from the wrong file or offset differs.
func (g *hugeImage) fill(data []byte, seed, index uint64) {
	pick := rand.New(rand.NewPCG(seed, index))

	switch {
	case pick.Uint64N(100) >= g.density:
		clear(data)
	case pick.Uint64N(512) == 0:
		copy(data, corpus.Bytes(seed+index, len(data)))
	default:
		const block = 4096

		for off := 0; off < len(data); off += block {
			blk := data[off:min(off+block, len(data))]

			var stamp [16]byte

			binary.LittleEndian.PutUint64(stamp[:], seed)
			binary.LittleEndian.PutUint64(stamp[8:], index<<8|uint64(off/block))

			for n := copy(blk, stamp[:]); n < len(blk); n *= 2 {
				copy(blk[n:], blk[:n])
			}
		}
	}
}

// verify reads every regular file below root and compares its digest with
// the generated one.
func (g *hugeImage) verify(t *testing.T, root string) {
	t.Helper()

	seen := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

		sum, err := fstest.HashFile(path)
		if err != nil {
			return err
		}
		if sum != g.sums[rel] {
			return fmt.Errorf("%s differs from the generated file", rel)
		}

		seen++

		return nil
	})

	assert.NoError(t, err)
	assert.Len(t, g.sums, seen)
}
