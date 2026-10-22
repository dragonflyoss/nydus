// Package fault injects backend errors, corruption, crashes, signals and a
// full disk under a mounted image. Whatever happens, a read returns the
// right bytes or fails within a bounded time; it never returns wrong bytes
// and never hangs the test.
package fault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/proc"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"golang.org/x/sys/unix"
)

const (
	// readTimeout bounds a single whole-file read; past it the daemon is
	// considered hung.
	readTimeout = 30 * time.Second
	// exitTimeout bounds how long a daemon may take to exit once it should.
	exitTimeout = 15 * time.Second

	// primeFile is read before a fault is injected, so the blob meta and the
	// backend connection are set up by a healthy request.
	primeFile = "data/size/00004096"
	// bigFile is 8MiB+4097 bytes of text spread over many chunk groups, so
	// reading it always reaches the backend.
	bigFile = "data/size/08392705"

	// repo is where the registry tests push the image blobs.
	repo = "e2e/fault"
)

// adapters are the transports the fault cases run against.
var adapters = []mount.Adapter{mount.FUSE{}, mount.Fileio{}}

// dataFile is a regular file the tests read whole and judge by its hash.
type dataFile struct {
	Rel    string
	Size   int64
	SHA256 string
}

// dataFiles lists the non-empty regular files under data/ of img, the part
// of the Seeded corpus that is plain content of at most a few MiB.
func dataFiles(t env.TB, img fixture.Image) []dataFile {
	t.Helper()
	var out []dataFile
	for _, e := range img.Want {
		rel := string(e.Path)
		if e.Type == "reg" && strings.HasPrefix(rel, "data/") && e.SHA256 != "" && e.Size > 0 && e.Size <= 16<<20 {
			out = append(out, dataFile{Rel: rel, Size: e.Size, SHA256: e.SHA256})
		}
	}
	if len(out) == 0 {
		t.Fatalf("image %s has no data files", img.Name)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out
}

// lookup returns the data file rel of img.
func lookup(t env.TB, img fixture.Image, rel string) dataFile {
	t.Helper()
	for _, f := range dataFiles(t, img) {
		if f.Rel == rel {
			return f
		}
	}
	t.Fatalf("image %s has no data file %s", img.Name, rel)
	return dataFile{}
}

// hashRead reads path whole and returns its SHA256. The file's page cache
// is dropped first, so the bytes come from the daemon rather than from an
// earlier read.
func hashRead(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	return hashFile(f)
}

// hashFile is hashRead of a file already open, read from its start.
func hashFile(f *os.File) (string, error) {
	_ = unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED)
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, 1<<62)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// result is the outcome of reading one file through a mount.
type result struct {
	File dataFile
	// Err is the read error, nil when the whole file arrived.
	Err error
	// Wrong reports that the whole file arrived but differs from the source.
	Wrong   bool
	Elapsed time.Duration
}

func (r result) String() string {
	switch {
	case r.Wrong:
		return fmt.Sprintf("%s: WRONG BYTES after %s", r.File.Rel, r.Elapsed)
	case r.Err != nil:
		return fmt.Sprintf("%s: %v after %s", r.File.Rel, r.Err, r.Elapsed)
	default:
		return fmt.Sprintf("%s: ok after %s", r.File.Rel, r.Elapsed)
	}
}

// readOnce reads f through the mount at root and fails t if the read hangs
// past readTimeout. A hung read is left behind; the daemon teardown
// unblocks it.
func readOnce(t env.TB, root string, f dataFile) result {
	t.Helper()
	return readWithin(t, root, f, readTimeout)
}

func readWithin(t env.TB, root string, f dataFile, timeout time.Duration) result {
	t.Helper()
	return judge(t, f, timeout, func() (string, error) { return hashRead(filepath.Join(root, f.Rel)) })
}

// judge runs read, which hashes f, and fails t if it does not return
// within timeout.
func judge(t env.TB, f dataFile, timeout time.Duration, read func() (string, error)) result {
	t.Helper()
	ch := make(chan result, 1)
	start := time.Now()
	go func() {
		sum, err := read()
		ch <- result{File: f, Err: err, Wrong: err == nil && sum != f.SHA256, Elapsed: time.Since(start)}
	}()
	select {
	case r := <-ch:
		return r
	case <-time.After(timeout):
		t.Fatalf("read of %s did not return within %s: the daemon hangs", f.Rel, timeout)
		return result{}
	}
}

// expectCorrect fails t unless r returned the right bytes.
func expectCorrect(t env.TB, r result) {
	t.Helper()
	if r.Err != nil || r.Wrong {
		t.Errorf("want the right bytes: %s", r)
	}
}

// expectNotWrong fails t if r returned wrong bytes; an error is fine.
func expectNotWrong(t env.TB, r result) {
	t.Helper()
	if r.Wrong {
		t.Errorf("never wrong bytes: %s", r)
	}
}

// expectFailed fails t unless r failed: the fault must surface as an error.
func expectFailed(t env.TB, r result) {
	t.Helper()
	if r.Err == nil {
		t.Errorf("want a read error: %s", r)
	}
}

// pushImage starts a registry holding img's blobs.
func pushImage(t env.TB, img fixture.Image) *registry.Registry {
	t.Helper()
	reg := registry.Start(t)
	reg.PushBlobs(t, repo, img.Blobs)
	return reg
}

// registryMount mounts img through a, reading blobs from the registry at
// addr. A nil http keeps the backend's defaults; verify turns on digest
// verification of every chunk group.
func registryMount(t env.TB, a mount.Adapter, img fixture.Image, addr string, http *mount.HTTP, verify bool) *mount.Mounted {
	t.Helper()
	return mount.Mount(t, a, img, mount.Options{Config: func(c *mount.Config) {
		c.Backend = mount.RegistryBackend(mount.Registry{Addr: addr, Repository: repo, HTTP: http})
		if verify {
			c.Storage.SkipVerifyChecksums = mount.Ptr(false)
		}
	}})
}

// prime reads primeFile through m, which must succeed: faults are injected
// only once the blob meta is loaded and the backend has served a request.
func prime(t env.TB, m *mount.Mounted) {
	t.Helper()
	expectCorrect(t, readOnce(t, m.Root, lookup(t, m.Image, primeFile)))
	if t.Failed() {
		t.FailNow()
	}
}

// waitExit waits up to timeout for d to exit and reports whether it did.
func waitExit(d *mount.Daemon, timeout time.Duration) bool {
	select {
	case <-d.Exited():
		return true
	case <-time.After(timeout):
		return false
	}
}

// mustExit fails t unless d exits within timeout.
func mustExit(t env.TB, d *mount.Daemon, timeout time.Duration, why string) {
	t.Helper()
	if !waitExit(d, timeout) {
		t.Fatalf("%s still running %s after %s", d.Name, timeout, why)
	}
}

// daemonDir is the directory a mount's daemon owns: its mountpoints, logs
// and, for fileio, the export.
func daemonDir(m *mount.Mounted) string { return filepath.Dir(m.Root) }

// mountpoints are the paths m mounts on.
func mountpoints(m *mount.Mounted) []string {
	if m.Daemon.Name == "nydus-fileio" {
		return []string{m.Root, filepath.Join(daemonDir(m), "export")}
	}
	return []string{m.Root}
}

// expectNoMounts fails t if anything is still mounted at or below dir.
// mountinfo can miss an entry while parallel tests mount and unmount, so
// the known mountpoints are also asked of the kernel directly; a dead FUSE
// mount fails stat and only shows up in mountinfo.
func expectNoMounts(t env.TB, dir string, known ...string) {
	t.Helper()
	left, err := proc.MountsUnder(dir)
	if err != nil {
		t.Fatalf("list mounts: %v", err)
	}
	for _, p := range known {
		if mount.IsMountpoint(p) && !contains(left, p) {
			left = append(left, p)
		}
	}
	if len(left) > 0 {
		t.Errorf("mounts left behind under %s: %v", dir, left)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// expectGone fails t unless every pid has exited (or is a zombie awaiting
// its new parent) within timeout.
func expectGone(t env.TB, pids []int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		var alive []int
		for _, pid := range pids {
			if running(pid) {
				alive = append(alive, pid)
			}
		}
		if len(alive) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("processes left behind: %v", alive)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// running reports whether pid exists and is not a zombie.
func running(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	i := strings.LastIndexByte(string(data), ')')
	fields := strings.Fields(string(data[i+1:]))
	return len(fields) > 0 && fields[0] != "Z" && fields[0] != "X"
}

// isErrno reports whether err is one of errnos.
func isErrno(err error, errnos ...syscall.Errno) bool {
	for _, e := range errnos {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// readers keep reading files through a mount in the background, judging
// every read, until stopped.
type readers struct {
	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}

	ok    atomic.Int64
	fails atomic.Int64

	mu        sync.Mutex
	wrong     []string
	firstErrs []string
}

// startReaders starts n goroutines cycling through files under root, each
// from a different starting file. They stop at the latest when t ends.
func startReaders(t env.TB, root string, files []dataFile, n int) *readers {
	r := &readers{stop: make(chan struct{}), done: make(chan struct{})}
	t.Cleanup(r.halt)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := i; ; j++ {
				select {
				case <-r.stop:
					return
				default:
				}
				f := files[j%len(files)]
				sum, err := hashRead(filepath.Join(root, f.Rel))
				switch {
				case err != nil:
					r.fails.Add(1)
					r.note(&r.firstErrs, fmt.Sprintf("%s: %v", f.Rel, err))
					// A dead filesystem fails every read at once; do not spin.
					time.Sleep(10 * time.Millisecond)
				case sum != f.SHA256:
					r.note(&r.wrong, f.Rel)
				default:
					r.ok.Add(1)
				}
			}
		}()
	}
	go func() { wg.Wait(); close(r.done) }()
	return r
}

func (r *readers) halt() { r.stopOnce.Do(func() { close(r.stop) }) }

func (r *readers) note(list *[]string, s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(*list) < 8 {
		*list = append(*list, s)
	}
}

// waitOK waits until at least n reads succeeded, so a fault lands while
// the readers are in full swing.
func (r *readers) waitOK(t env.TB, n int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for r.ok.Load() < n {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d reads succeeded within %s; errors: %v", r.ok.Load(), n, timeout, r.errors())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// stopWithin stops the readers, fails t if one is still stuck in a read
// after timeout, and fails t if any read returned wrong bytes.
func (r *readers) stopWithin(t env.TB, timeout time.Duration) {
	t.Helper()
	r.halt()
	select {
	case <-r.done:
	case <-time.After(timeout):
		t.Fatalf("a reader is still blocked %s after stop: reads hang", timeout)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.wrong) > 0 {
		t.Errorf("reads returned wrong bytes: %v", r.wrong)
	}
	t.Logf("readers: %d ok, %d failed; first errors: %v", r.ok.Load(), r.fails.Load(), r.firstErrs)
}

func (r *readers) errors() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.firstErrs...)
}

// authProxy fronts a registry with bearer-token auth, as Docker Hub and
// most registries do: a request without a valid token gets 401 with a
// challenge naming the token realm, which hands out a fresh token per call.
type authProxy struct {
	URL string

	mu     sync.Mutex
	valid  map[string]bool
	issued int
	denied int
}

func startAuthProxy(t env.TB, upstream string) *authProxy {
	t.Helper()
	target, err := url.Parse(upstream)
	if err != nil {
		t.Fatalf("parse %s: %v", upstream, err)
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ErrorLog = log.New(io.Discard, "", 0)
	p := &authProxy{valid: map[string]bool{}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"token": p.issue(), "expires_in": 3600})
			return
		}
		if !p.allow(r) {
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Bearer realm="%s/token",service="e2e",scope="repository:%s:pull"`, p.URL, repo))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		rp.ServeHTTP(w, r)
	}))
	p.URL = "http://" + srv.Listener.Addr().String()
	srv.Start()
	t.Cleanup(srv.Close)
	return p
}

func (p *authProxy) issue() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.issued++
	tok := fmt.Sprintf("token-%d", p.issued)
	p.valid[tok] = true
	return tok
}

func (p *authProxy) allow(r *http.Request) bool {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	p.mu.Lock()
	defer p.mu.Unlock()
	if ok && p.valid[tok] {
		return true
	}
	p.denied++
	return false
}

// revoke invalidates every token handed out so far, as an expiry or a
// credential rotation on the registry side does.
func (p *authProxy) revoke() {
	p.mu.Lock()
	defer p.mu.Unlock()
	clear(p.valid)
}

// counts returns how many tokens were issued and requests denied.
func (p *authProxy) counts() (issued, denied int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.issued, p.denied
}
