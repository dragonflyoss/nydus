package fixture

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"golang.org/x/sys/unix"
)

// cacheVersion is bumped when the layout of the cache itself changes.
const cacheVersion = "1"

// cached returns the directory holding the artifact kind/name keyed by key,
// calling build on an empty directory the first time it is needed. Concurrent
// callers, in this process or in other test binaries, wait on a file lock
// instead of building twice; an interrupted build leaves no entry behind.
func cached(t env.TB, kind, name, key string, build func(dir string)) string {
	t.Helper()
	root, err := env.CacheRoot()
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
	if fileExists(done) {
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
	if fileExists(done) {
		return dir
	}

	_ = os.RemoveAll(dir)
	tmp := fmt.Sprintf("%s.tmp-%d", dir, os.Getpid())
	_ = os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatalf("create %s: %v", tmp, err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	t.Logf("building %s/%s into the fixture cache", kind, name)
	build(tmp)
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
func fileHash(t env.TB, path string) string {
	t.Helper()
	hashMu.Lock()
	defer hashMu.Unlock()
	if h, ok := hashes[path]; ok {
		return h
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatalf("hash %s: %v", path, err)
	}
	hashes[path] = hex.EncodeToString(h.Sum(nil))
	return hashes[path]
}

// sourceHash fingerprints the Go sources that generate the corpora, so an
// edit to a generator invalidates the cached trees without a manual bump.
func sourceHash(t env.TB) string {
	t.Helper()
	root, err := env.RepoRoot()
	if err != nil {
		t.Fatalf("%v", err)
	}
	files, err := filepath.Glob(filepath.Join(root, "tests", "e2e", "internal", "corpus", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus sources found: %v", err)
	}
	sort.Strings(files)
	var b strings.Builder
	for _, f := range files {
		b.WriteString(fileHash(t, f))
	}
	return b.String()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
