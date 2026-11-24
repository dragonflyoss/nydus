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
	hugeExtentSize    = 1 << 20
	hugeSmallFileSize = 40 << 10
)

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

			start := time.Now()
			mnt := mount.Mount(t, mount.FUSE{}, ref(target).pull(t, nil), mount.Options{})
			image.verify(t, mnt.Root)
			t.Logf("mount and verify took %s", time.Since(start).Round(time.Second))
		})
	}
}

type hugeImage struct {
	size    int64
	density uint64
	mu      sync.Mutex
	sums    map[string]string
}

func (h *hugeImage) push(t *testing.T, reg *registry.Registry, ref string) {
	t.Helper()
	sizes := rand.New(rand.NewPCG(1, 2))

	reg.PushLayers(t, ref,
		h.layer("huge", 1, func(int) string { return "huge/one" }, func(int) int64 { return h.size / 100 * 48 }),
		h.layer("mid", 48, func(i int) string { return fmt.Sprintf("mid/%02d", i) }, func(int) int64 { return h.size / 100 }),
		h.layer("small", int(h.size/100*4/hugeSmallFileSize),
			func(i int) string { return fmt.Sprintf("small/%04d/%03d", i/1000, i%1000) },
			func(int) int64 { return sizes.Int64N(2 * hugeSmallFileSize) }),
	)
}

func (h *hugeImage) layer(dir string, count int, path func(int) string, size func(int) int64) v1.Layer {
	pr, pw := io.Pipe()

	go func() {
		tw := tar.NewWriter(pw)

		err := h.writeFiles(tw, dir, count, path, size)
		if err == nil {
			err = tw.Close()
		}

		_ = pw.CloseWithError(err)
	}()

	return stream.NewLayer(pr, stream.WithCompressionLevel(gzip.BestSpeed))
}

func (h *hugeImage) writeFiles(tw *tar.Writer, dir string, count int, path func(int) string, size func(int) int64) error {
	modTime := time.Unix(1700000000, 0)
	buf := make([]byte, hugeExtentSize)
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

		for off := int64(0); off < size; off += hugeExtentSize {
			data := buf[:min(size-off, hugeExtentSize)]
			h.fill(data, seed.Sum64(), uint64(off/hugeExtentSize))
			_, _ = sum.Write(data)

			if _, err := tw.Write(data); err != nil {
				return err
			}
		}

		h.mu.Lock()
		h.sums[name] = hex.EncodeToString(sum.Sum(nil))
		h.mu.Unlock()
	}

	return nil
}

func (h *hugeImage) fill(data []byte, seed, index uint64) {
	pick := rand.New(rand.NewPCG(seed, index))

	switch {
	case pick.Uint64N(100) >= h.density:
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

func (h *hugeImage) verify(t *testing.T, root string) {
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
		if sum != h.sums[rel] {
			return fmt.Errorf("%s differs from the generated file", rel)
		}

		seen++

		return nil
	})

	assert.NoError(t, err)
	assert.Len(t, h.sums, seen)
}
