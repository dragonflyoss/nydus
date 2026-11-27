package snapshotter

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/stretchr/testify/assert"
)

type image struct {
	oci, nydus string
	files      map[string]string
}

func newImage(t *testing.T, reg *registry.Registry, repo string) image {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "busybox")
	copyFile(t, staticBusybox(t), filepath.Join(bin, "bin", "busybox"), 0o755)
	unique := t.TempDir()
	id := fmt.Sprintf("%s %016x\n", t.Name(), rand.Uint64())
	if !assert.NoError(t, os.WriteFile(filepath.Join(unique, "id"), []byte(id), 0o644)) {
		t.FailNow()
	}

	corpus := fixture.Corpus(t, fixture.Standard)
	img := image{oci: reg.Ref(repo, "oci"), nydus: reg.Ref(repo, "nydus"), files: map[string]string{"/id": sha256Hex(t, filepath.Join(unique, "id"))}}
	entries, err := os.ReadDir(filepath.Join(corpus, "files"))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	for _, entry := range entries {
		if entry.Type().IsRegular() {
			img.files["/files/"+entry.Name()] = sha256Hex(t, filepath.Join(corpus, "files", entry.Name()))
		}
	}

	reg.PushDirs(t, img.oci, bin, corpus, unique)
	convert(t, img.oci, img.nydus)
	return img
}

func (i image) on(host string) image {
	rehost := func(ref string) string {
		_, rest, _ := strings.Cut(ref, "/")
		return host + "/" + rest
	}
	i.oci, i.nydus = rehost(i.oci), rehost(i.nydus)
	return i
}

func assertFiles(t *testing.T, c *container, img image) {
	t.Helper()
	assert.Equal(t, img.files, c.sha256sum(t, slices.Collect(maps.Keys(img.files))...))
}

func convert(t *testing.T, src, target string) {
	t.Helper()
	env.Run(t, env.Nydusify(t), "convert", "--source", src, "--target", target,
		"--builder", env.Nydus(t), "--source-plain-http", "--target-plain-http")
}

func staticBusybox(t *testing.T) string {
	t.Helper()
	path := env.LookPath(t, "busybox")
	f, err := elf.Open(path)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	defer func() { _ = f.Close() }()

	for _, prog := range f.Progs {
		if prog.Type == elf.PT_INTERP {
			env.Skipf(t, "%s is dynamically linked: install busybox-static", path)
		}
	}

	return path
}

func copyFile(t *testing.T, src, dst string, mode os.FileMode) {
	t.Helper()
	data, err := os.ReadFile(src)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.NoError(t, os.MkdirAll(filepath.Dir(dst), 0o755))
	assert.NoError(t, os.WriteFile(dst, data, mode))
}

func sha256Hex(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if !assert.NoError(t, func() error { _, err := io.Copy(h, f); return err }()) {
		t.FailNow()
	}

	return hex.EncodeToString(h.Sum(nil))
}
