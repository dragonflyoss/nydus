package cache

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/stretchr/testify/assert"
)

func TestSharedBlobUsesOneCacheEntry(t *testing.T) {
	t.Parallel()
	w := setup(t)
	cache := newCache(t)
	lowerMount := cache.mount(t, w.lowerImage)
	upperMount := cache.mount(t, w.upperImage)

	lowerMount.mustRead(t, "lower.bin", w.want["lower.bin"])
	upperMount.mustRead(t, "upper.bin", w.want["upper.bin"])
	peers{lowerMount, upperMount}.mustReadConcurrently(t, "shared.bin", w.want["shared.bin"])

	assert.FileExists(t, cache.file(w.sharedBlob, mount.CacheDataSuffix))
	data, err := filepath.Glob(filepath.Join(cache.path, "*"+mount.CacheDataSuffix))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.Len(t, data, 3)
}

func TestDiskless(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
	dir := env.WorkDir(t)
	img := fixture.Image{Bootstrap: filepath.Join(dir, "merged.boot"), BlobDir: filepath.Join(dir, "blobs"), Merged: true}
	layout := fixture.MustLayout(t, "zstd")
	files := map[string][]byte{"first": corpus.Bytes(1, 1<<20), "pressure": corpus.Bytes(2, 40<<20)}

	for _, name := range []string{"first", "pressure"} {
		src := filepath.Join(dir, name)
		if !assert.NoError(t, os.Mkdir(src, 0o755)) {
			t.FailNow()
		}
		if !assert.NoError(t, os.WriteFile(filepath.Join(src, name), files[name], 0o644)) {
			t.FailNow()
		}

		blob, _ := fixture.BuildInto(t, img.BlobDir, filepath.Join(dir, name+".boot"), src, layout)
		img.Blobs = append(img.Blobs, blob)
	}

	env.Run(t, env.Nydus(t), append([]string{"merge", "--bootstrap", img.Bootstrap}, img.Blobs...)...)
	reg := registry.Start(t)
	reg.PushBlobs(t, "diskless", img.Blobs)

	m := mount.Mount(t, mount.FUSE{}, img, mount.Options{Config: func(c *mount.Config) {
		c.Storage = &mount.StorageConfig{}
		c.Backend = mount.RegistryBackend(mount.RegistryConfig{Addr: reg.URL, Repository: "diskless", HTTP: &mount.HTTPConfig{MaxRetries: mount.Ptr(0)}})
	}})

	readFirst := func() ([]byte, error) {
		return fstest.ReadAtCold(m.Path("first"), 0, 4096)
	}

	data, err := readFirst()
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.Equal(t, files["first"][:4096], data) {
		t.FailNow()
	}

	data, err = os.ReadFile(m.Path("pressure"))
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.True(t, bytes.Equal(files["pressure"], data)) {
		t.FailNow()
	}

	reg.Faults.Set(registry.Fault{Status: http.StatusServiceUnavailable, Match: registry.BlobGet(filepath.Base(img.Blobs[0]))})
	_, err = readFirst()
	if !assert.Error(t, err) {
		t.FailNow()
	}
	if !assert.Positive(t, reg.Faults.Hits()) {
		t.FailNow()
	}

	reg.Faults.Clear()
	data, err = readFirst()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.Equal(t, files["first"][:4096], data)
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", m.Daemon.Pid()))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	fds, err := filepath.Glob(fmt.Sprintf("/proc/%d/fd/*", m.Daemon.Pid()))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	paths := strings.Fields(string(maps))

	for _, fd := range fds {
		target, _ := os.Readlink(fd)
		paths = append(paths, target)
	}

	var cached []string

	for _, path := range paths {
		if strings.Contains(path, mount.CacheDataSuffix) || strings.Contains(path, mount.CacheMapSuffix) {
			cached = append(cached, path)
		}
	}

	assert.Empty(t, cached)
	assert.True(t, m.Daemon.Alive())
}
