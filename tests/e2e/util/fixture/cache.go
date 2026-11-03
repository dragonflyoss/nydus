package fixture

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
)

const cacheVersion = "2"

// cacheRoot is the directory shared fixtures (corpora, built images) are
// cached under across test binaries: NYDUS_E2E_CACHE, or .test-tmp/e2e-cache
// in the repository.
func cacheRoot() (string, error) {
	if dir := os.Getenv("NYDUS_E2E_CACHE"); dir != "" {
		return dir, os.MkdirAll(dir, 0o755)
	}

	root, err := env.RepoRoot()
	if err != nil {
		return "", err
	}

	dir := filepath.Join(root, ".test-tmp", "e2e-cache")

	return dir, os.MkdirAll(dir, 0o755)
}

// cached returns the directory holding the artifact kind/name keyed by key,
// calling build on an empty directory the first time it is needed. Concurrent
// callers, in this process or in other test binaries, wait on a file lock
// instead of building twice. A failed build leaves no entry behind, and the
// next build removes the temporary directories a killed one left.
func cached(t testing.TB, kind, name, key string, build func(t testing.TB, dir string)) string {
	t.Helper()
	root, err := cacheRoot()
	if err != nil {
		t.Fatalf("cache root: %v", err)
	}

	parent := filepath.Join(root, kind)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatalf("create %s: %v", parent, err)
	}

	sum := sha256.Sum256([]byte(cacheVersion + "\x00" + key))
	dir := filepath.Join(parent, name+"-"+hex.EncodeToString(sum[:8]))
	done := dir + ".done"
	if _, err := os.Stat(done); err == nil {
		return dir
	}

	lock, err := os.OpenFile(dir+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("open lock: %v", err)
	}

	defer func() { _ = lock.Close() }()

	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		t.Fatalf("lock %s: %v", dir, err)
	}

	defer func() { _ = unix.Flock(int(lock.Fd()), unix.LOCK_UN) }()

	if _, err := os.Stat(done); err == nil {
		return dir
	}

	stale, _ := filepath.Glob(dir + ".tmp-*")
	for _, path := range append(stale, dir) {
		_ = os.RemoveAll(path)
	}

	tmp := fmt.Sprintf("%s.tmp-%d", dir, os.Getpid())
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatalf("create %s: %v", tmp, err)
	}

	defer func() { _ = os.RemoveAll(tmp) }()
	t.Logf("building %s/%s into the fixture cache", kind, name)
	build(t, tmp)

	if t.Failed() {
		t.FailNow()
	}
	if err := os.Rename(tmp, dir); err != nil {
		t.Fatalf("publish %s: %v", dir, err)
	}
	if err := os.WriteFile(done, nil, 0o644); err != nil {
		t.Fatalf("mark %s: %v", dir, err)
	}

	return dir
}

var (
	hashMu sync.Mutex
	hashes = map[string]string{}
)

// fileHash returns the sha256 of a file, memoized per process.
func fileHash(t testing.TB, path string) string {
	t.Helper()
	hashMu.Lock()
	defer hashMu.Unlock()

	if h, ok := hashes[path]; ok {
		return h
	}

	h, err := fstest.HashFile(path)
	if err != nil {
		t.Fatalf("hash %s: %v", path, err)
	}

	hashes[path] = h

	return h
}

// sourceHash fingerprints the Go sources that generate the corpora, so an
// edit to a generator invalidates the cached trees without a manual bump.
func sourceHash(t testing.TB) string {
	t.Helper()
	root, err := env.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}

	files, err := filepath.Glob(filepath.Join(root, "tests", "e2e", "util", "corpus", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus sources found: %v", err)
	}

	slices.Sort(files)
	var b strings.Builder

	for _, f := range files {
		b.WriteString(fileHash(t, f))
	}

	return b.String()
}
