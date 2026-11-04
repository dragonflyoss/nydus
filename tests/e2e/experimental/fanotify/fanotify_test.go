package fanotify

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/experimental/transport"
	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/util/proc"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

const (
	repo      = "nydus-e2e/fanotify"
	straceLog = "strace.log"

	straceExitTimeout = 20 * time.Second
)

var (
	loopReady    = regexp.MustCompile(`event loop ready for [1-9][0-9]* blob device`)
	fanotifyInit = regexp.MustCompile(`fanotify_init\([^)]*\)\s*=\s*(\d+)`)
	cachePwrite  = regexp.MustCompile(`pwrite(?:64|v2?)\(\d+<[^>\n]*\.blob\.data>`)
)

func TestConcurrency(t *testing.T) {
	t.Parallel()
	transport.Concurrency(t, Fanotify{}, repo)
}

func TestPersistence(t *testing.T) {
	t.Parallel()
	transport.Persistence(t, Fanotify{}, repo)
}

func TestDemandPaging(t *testing.T) {
	t.Parallel()
	transport.DemandPaging(t, Fanotify{}, repo, func(t *testing.T, m *mount.Mounted, cache string) {
		assert.Regexp(t, loopReady, m.Daemon.Log())
		files := mount.CacheFiles(cache)
		if !assert.NotEmpty(t, files) {
			t.FailNow()
		}

		for _, f := range files {
			assert.Less(t, mount.Allocated(f), int64(1<<20))
		}
	})
}

type straced struct{ Fanotify }

func (straced) Require(t testing.TB) {
	t.Helper()
	Fanotify{}.Require(t)
	env.LookPath(t, "strace")
}

func (straced) Start(t testing.TB, req mount.Request) (string, *mount.Daemon, func()) {
	t.Helper()
	strace := env.LookPath(t, "strace")

	mnt, d, teardown := start(t, req, []string{strace, "-f", "-tt", "-y",
		"-e", "trace=fanotify_init,read,write,pwrite64,pwritev,pwritev2",
		"-o", filepath.Join(req.Dir, straceLog)})

	return mnt, d, func() {
		for _, pid := range proc.Children(d.Pid()) {
			_ = unix.Kill(pid, unix.SIGTERM)
		}

		d.WaitExit(straceExitTimeout)
		teardown()
	}
}

func TestEventLoopFillsCache(t *testing.T) {
	t.Parallel()
	straced{}.Require(t)
	s := transport.Serve(t, repo)
	m := s.Mount(t, straced{}, mount.Options{})
	if !assert.NoError(t, fstest.SameRange(filepath.Join(s.Image.Source, transport.LargeFile), m.Path(transport.LargeFile), 1<<20, 1<<20)) {
		t.FailNow()
	}

	m.Unmount()

	data, err := os.ReadFile(filepath.Join(filepath.Dir(m.Daemon.LogPath), straceLog))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	trace := string(data)
	match := fanotifyInit.FindStringSubmatch(trace)
	if !assert.NotNil(t, match) {
		t.FailNow()
	}

	fd := match[1]
	if !assert.Positive(t, countMatches(trace, `read\(`+fd+`[<,]`)) {
		t.FailNow()
	}
	if !assert.Positive(t, countMatches(trace, `write\(`+fd+`[<,]`)) {
		t.FailNow()
	}

	assert.NotEmpty(t, cachePwrite.FindAllString(trace, -1))
}

func countMatches(s, pattern string) int {
	return len(regexp.MustCompile(pattern).FindAllString(s, -1))
}
