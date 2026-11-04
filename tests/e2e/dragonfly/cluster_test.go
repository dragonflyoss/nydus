package dragonfly

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/stretchr/testify/assert"
)

const (
	schedulerEnv = "NYDUS_E2E_DRAGONFLY_SCHEDULER"
	repo         = "nydus-e2e/dragonfly"
	kindGateway  = "172.30.0.1"

	imageTimeout    = 90 * time.Second
	policyTimeout   = 60 * time.Second
	recoveryTimeout = 90 * time.Second
	readTimeout     = 20 * time.Second

	windowStride = 64 << 10
	windowSize   = 4 << 10
)

type cluster struct {
	scheduler string
	stopped   map[string]bool
}

func newCluster(t *testing.T) *cluster {
	t.Helper()
	scheduler := os.Getenv(schedulerEnv)
	if scheduler == "" {
		env.Skipf(t, "%s is unset: start the upstream Kind/Helm cluster (see tests/e2e/README.md)", schedulerEnv)
	}
	env.MustHaveRoot(t)
	env.LookPath(t, "kubectl")
	c := &cluster{scheduler: scheduler, stopped: make(map[string]bool)}
	t.Cleanup(func() { c.restore(t) })

	return c
}

func (c *cluster) kubectl(t testing.TB, args ...string) {
	t.Helper()
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", append([]string{"--namespace", "dragonfly-system"}, args...)...)
	if !assert.NoError(t, cmd.Run()) {
		t.FailNow()
	}

	t.Logf("kubectl %s: %v", strings.Join(args, " "), time.Since(start).Round(time.Millisecond))
}

func (c *cluster) stop(t testing.TB, components ...string) {
	t.Helper()
	for _, component := range components {
		if component != "seed-client" && component != "scheduler" {
			t.Fatalf("unknown Dragonfly component %q", component)
		}

		c.stopped[component] = true
		c.kubectl(t, "scale", "statefulset", "dragonfly-"+component, "--replicas=0")
		c.kubectl(t, "wait", "--for=delete", "pod", "--selector", "component="+component, "--timeout=3m")
	}
}

func (c *cluster) restore(t testing.TB) {
	t.Helper()
	for _, component := range []string{"scheduler", "seed-client"} {
		if c.stopped[component] {
			c.kubectl(t, "scale", "statefulset", "dragonfly-"+component, "--replicas=1")
		}
	}

	for _, component := range []string{"scheduler", "seed-client"} {
		if c.stopped[component] {
			c.kubectl(t, "rollout", "status", "statefulset/dragonfly-"+component, "--timeout=3m")
			delete(c.stopped, component)
		}
	}
}

type options struct {
	timeout           string
	fallbackRateLimit int
	fetchSize         *int64
	prefetch          *mount.PrefetchConfig
}

func (c *cluster) mount(t testing.TB, img fixture.Image, addr string, o options) mounted {
	t.Helper()
	if o.timeout == "" {
		o.timeout = "5s"
	}

	if o.fallbackRateLimit == 0 {
		o.fallbackRateLimit = 20
	}

	cacheDir := filepath.Join(env.WorkDir(t), "cache")
	if err := os.MkdirAll(cacheDir, 0o755); !assert.NoError(t, err) {
		t.FailNow()
	}

	for _, blob := range img.Blobs {
		meta := filepath.Base(blob) + mount.CacheMetaSuffix
		data, err := os.ReadFile(filepath.Join(filepath.Dir(blob), meta))
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if err := os.WriteFile(filepath.Join(cacheDir, meta), data, 0o644); !assert.NoError(t, err) {
			t.FailNow()
		}
	}

	return mounted{mount.Mount(t, mount.FUSE{}, img, mount.Options{
		CacheDir: cacheDir,
		Config: func(cfg *mount.Config) {
			cfg.Backend = mount.RegistryBackend(mount.RegistryConfig{
				Addr:       addr,
				Repository: repo,
				HTTP:       &mount.HTTPConfig{RequestTimeout: o.timeout, MaxRetries: mount.Ptr(1)},
				Dragonfly: &mount.DragonflyConfig{
					SchedulerEndpoint: c.scheduler,
					RequestTimeout:    o.timeout,
					MaxRetries:        mount.Ptr(1),
					FallbackRateLimit: mount.Ptr(o.fallbackRateLimit),
				},
			})

			cfg.Storage.FetchSize = o.fetchSize

			if o.prefetch != nil {
				cfg.Prefetch = o.prefetch
			}
		},
	})}
}

func (c *cluster) mountFaulted(t testing.TB, status int) mounted {
	t.Helper()
	img := uniqueImage(t)
	origin := startOrigin(t, img)
	origin.Faults.Set(registry.Fault{Status: status})

	return c.mount(t, img, origin.URL, policyOptions)
}

var policyOptions = options{timeout: "10s", fallbackRateLimit: 1000}
