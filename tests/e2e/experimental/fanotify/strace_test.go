package fanotify

import (
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/proc"
	"github.com/stretchr/testify/require"
)

const straceLog = "strace.log"

// straced runs the fanotify daemon under strace, logging to straceLog in
// the daemon's directory.
type straced struct{ Fanotify }

func (straced) Require(t env.TB) {
	t.Helper()
	Fanotify{}.Require(t)
	env.RequireTool(t, "strace")
}

func (straced) Start(t env.TB, req mount.Request) (string, *mount.Daemon, func()) {
	t.Helper()
	strace := env.RequireTool(t, "strace")
	mnt, d, teardown := start(t, req, []string{strace, "-f", "-tt", "-y",
		"-e", "trace=fanotify_init,read,write,pwrite64,pwritev,pwritev2",
		"-o", filepath.Join(req.Dir, straceLog)})
	return mnt, d, func() {
		// A signal to strace would leave the daemon shutting down on its
		// own; stop the daemon itself and let strace follow it out.
		for _, pid := range proc.Children(d.Pid()) {
			_ = syscall.Kill(pid, syscall.SIGTERM)
		}
		select {
		case <-d.Exited():
		case <-time.After(20 * time.Second):
		}
		teardown()
	}
}

var (
	fanotifyInit = regexp.MustCompile(`fanotify_init\([^)]*\)\s*=\s*(\d+)`)
	cachePwrite  = regexp.MustCompile(`pwrite(?:64|v2?)\(\d+<[^>\n]*\.blob\.data>`)
)

// TestStrace is the syscall-level proof that a cold read goes through the
// daemon: it reads a pre-content event off the fanotify group, writes the
// permission response back, and pwrites the fetched data into the cache
// file the kernel then reads.
func TestStrace(t *testing.T) {
	t.Parallel()
	straced{}.Require(t)
	s := serveDataset(t)
	m := s.mountWith(t, straced{}, "")
	require.NoError(t, sameRange(filepath.Join(s.img.Source, largeFile), m.Path(largeFile), 1<<20, 1<<20))
	m.Unmount()

	data, err := os.ReadFile(filepath.Join(filepath.Dir(m.Daemon.LogPath), straceLog))
	require.NoError(t, err)
	trace := string(data)
	match := fanotifyInit.FindStringSubmatch(trace)
	require.NotNil(t, match, "no fanotify_init in the trace")
	fd := match[1]
	require.Positive(t, countMatches(trace, `read\(`+fd+`[<,]`), "daemon read no event off fanotify fd %s", fd)
	require.Positive(t, countMatches(trace, `write\(`+fd+`[<,]`), "daemon wrote no response to fanotify fd %s", fd)
	require.Positive(t, len(cachePwrite.FindAllString(trace, -1)), "daemon wrote no fetched data into the cache")
}

func countMatches(s, pattern string) int {
	return len(regexp.MustCompile(pattern).FindAllString(s, -1))
}
