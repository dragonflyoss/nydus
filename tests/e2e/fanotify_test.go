package e2e

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/stretchr/testify/assert"
)

// fanotifyConfig is the registry backend config of the fanotify daemon, plain
// HTTP against the local registry, retrying the origin maxRetries times.
const fanotifyConfig = `backend:
  type: registry
  config:
    addr: http://%s
    repository: %s
    http:
      max_retries: %d
storage:
  dir: %s
prefetch:
  scope: none
`

// fanotifyRepository is the repository the fanotify image is pushed to.
const fanotifyRepository = "nydus-e2e/fanotify"

// TestFanotify converts the source tree to a nydus image in the local
// registry, boots `nydus fanotify` on its exported bootstrap and runs the
// shared service cases: cold reads through fanotify pre-content events are
// byte-exact and demand-paged, the warm cache survives a restart and SIGTERM
// shuts the daemon down cleanly. Two cases of its own follow: an unreachable
// registry denies a cold read instead of serving garbage, and strace shows
// the daemon reading events, answering them and writing the cache. It needs
// root, a 6.15 kernel for FAN_PRE_ACCESS, a nydus built with the fanotify
// feature and a registry.
func TestFanotify(t *testing.T) {
	util.SkipUnlessRoot(t, "CAP_SYS_ADMIN for fanotify")
	util.SkipUnlessSubcommand(t, nydusBin, "fanotify", "cli,fanotify")
	if major, minor := util.KernelVersion(t); major < 6 || (major == 6 && minor < 15) {
		t.Skipf("kernel %d.%d < 6.15: fanotify FAN_PRE_ACCESS unavailable", major, minor)
	}
	registry := util.SkipUnlessRegistry(t)

	// Push the image and point the daemon at the registry.
	suite := newServiceSuite(t)
	ref := fmt.Sprintf("%s/%s:%d", registry, fanotifyRepository, os.Getpid())
	suite.bootstrap = util.ConvertImage(t, nydusifyBin, nydusBin, suite.source, ref, filepath.Join(suite.workDir, "check"))
	config := fmt.Sprintf(fanotifyConfig, registry, fanotifyRepository, 3, suite.cacheDir)
	assert.NoError(t, os.WriteFile(suite.configPath, []byte(config), 0o644))
	suite.args = []string{
		nydusBin, "fanotify",
		"--bootstrap", suite.bootstrap,
		"--config", suite.configPath,
		"--mountpoint", suite.mountpoint,
		"--log-level", "debug",
		"--log-dir", suite.LogDir,
	}
	suite.readyPattern = `event loop ready`
	suite.shutdownPattern = `stop signal received`
	suite.startCold(t)

	suite.run(t, func(t *testing.T) {
		assert := assert.New(t)
		assert.True(util.IsMountpoint(suite.mountpoint), "mountpoint is not live")
		assert.Greater(suite.CountLogs(`marked device slot`), 0, "no device marked FAN_PRE_ACCESS")
		for _, blobData := range suite.blobDataFiles() {
			assert.Less(util.AllocatedBytes(t, blobData), int64(1<<20), "cache %s does not start sparse", blobData)
		}
	}, func(t *testing.T) {
		assert := assert.New(t)
		t.Logf("job-dispatched log lines: %d (lossy), fetch-allow log lines: %d", suite.CountLogs(`job [0-9]+ dispatched`), suite.CountLogs(`fetch succeeded`))
		assert.Equal(0, suite.CountLogs(`unknown event fd`), "unknown-device denies for legit reads")
		assert.Equal(0, suite.CountLogs(`immediate deny: InvalidRange`), "invalid-range denies for legit reads")
		assert.Equal(0, suite.CountLogs(`fetch backend failure`), "backend failures against the registry")
	})

	t.Run("fail closed", func(t *testing.T) {
		assert := assert.New(t)

		// Front the registry with a proxy the test can take down: the daemon
		// needs the backend to start, and must deny a cold read once it is
		// gone instead of serving anything else.
		target, err := url.Parse("http://" + registry)
		assert.NoError(err)
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if !assert.NoError(err) {
			t.FailNow()
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		director := proxy.Director
		proxy.Director = func(req *http.Request) {
			director(req)
			req.Host = target.Host
		}
		server := &http.Server{Handler: proxy, ReadHeaderTimeout: 10 * time.Second}
		go func() { _ = server.Serve(listener) }()
		t.Cleanup(func() { _ = server.Close() })

		suite.stop(t)
		config := fmt.Sprintf(fanotifyConfig, listener.Addr(), fanotifyRepository, 0, suite.cacheDir)
		assert.NoError(os.WriteFile(suite.configPath, []byte(config), 0o644))
		suite.startCold(t)
		assert.NoError(server.Close())

		_, err = util.ReadRange(filepath.Join(suite.mountpoint, "large.bin"), 50<<20, 4<<20)
		assert.Error(err, "an uncached read was served while the backend is unreachable")
		assert.Greater(suite.CountLogs(`fetch backend failure`), 0, "backend-failure deny not logged")
	})

	t.Run("strace ground truth", func(t *testing.T) {
		if os.Getenv("NYDUS_E2E_FANOTIFY_RUN_STRACE") == "0" {
			t.Skip("NYDUS_E2E_FANOTIFY_RUN_STRACE=0")
		}
		strace, err := exec.LookPath("strace")
		if err != nil {
			t.Skip("strace not installed")
		}
		assert := assert.New(t)

		// Restart cold under strace, detached so the daemon stays the direct
		// child and SIGTERM reaches it rather than the tracer.
		suite.stop(t)
		config := fmt.Sprintf(fanotifyConfig, registry, fanotifyRepository, 3, suite.cacheDir)
		assert.NoError(os.WriteFile(suite.configPath, []byte(config), 0o644))
		util.WipeCache(suite.cacheDir)
		straceLog := filepath.Join(suite.workDir, "strace.log")
		suite.startArgs(t, append([]string{strace, "-D", "-f", "-tt", "-y", "-e", "trace=fanotify_init,read,write,pwrite64,pwritev", "-o", straceLog}, suite.args...)...)

		// One cold read triggers pre-content events and a backend fetch; the
		// log is complete once the daemon has exited.
		_, err = util.ReadRange(filepath.Join(suite.mountpoint, "large.bin"), 1<<20, 1<<20)
		assert.NoError(err, "cold read failed under strace")
		assert.True(suite.stop(t), "daemon did not exit on SIGTERM under strace")

		output, err := os.ReadFile(straceLog)
		assert.NoError(err)
		fanotifyFd := fanotifyFdOf(string(output))
		reads := countSyscalls(string(output), "read", fanotifyFd)
		writes := countSyscalls(string(output), "write", fanotifyFd)
		pwrites := len(regexp.MustCompile(`pwrite(?:64|v)?\(.*blob\.data`).FindAllString(string(output), -1))
		t.Logf("strace: fanotify fd=%s read=%d write=%d pwrite(blob.data)=%d", fanotifyFd, reads, writes, pwrites)

		assert.Greater(reads, 0, "daemon never read a pre-content event off the fanotify fd")
		assert.Greater(writes, 0, "daemon never wrote a permission response")
		assert.Greater(pwrites, 0, "daemon never wrote fetched data into the blob cache")
	})
}

// fanotifyFdOf returns the fanotify fd from the strace output: the return
// value of fanotify_init, or failing that the anon_inode tag strace -y adds
// to every fd. Empty when neither is found.
func fanotifyFdOf(output string) string {
	if m := regexp.MustCompile(`fanotify_init\([^)]*\)\s*=\s*(\d+)`).FindStringSubmatch(output); len(m) > 1 {
		return m[1]
	}
	if m := regexp.MustCompile(`(\d+)<anon_inode:\[fanotify\]>`).FindStringSubmatch(output); len(m) > 1 {
		return m[1]
	}

	return ""
}

// countSyscalls counts the calls of syscall on fd in the strace output, in
// both the plain `read(3,` and the strace -y `read(3<anon_inode:...>,` forms.
func countSyscalls(output, syscall, fd string) int {
	if fd == "" {
		return 0
	}

	return len(regexp.MustCompile(regexp.QuoteMeta(syscall)+`\(`+fd+`[<,]`).FindAllString(output, -1))
}
