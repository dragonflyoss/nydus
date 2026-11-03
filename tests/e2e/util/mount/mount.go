// Package mount starts the nydus daemons under test, mounts images through
// them and tears everything down again, whatever state the daemon is left in.
package mount

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
)

// Mode is how an image is served.
type Mode string

const (
	// Blob serves a single blob on its own, with no bootstrap or config.
	Blob Mode = "blob"

	// Cold serves the bootstrap from an empty cache.
	Cold Mode = "cold"

	// Warm serves the bootstrap from a cache an earlier mount filled.
	Warm Mode = "warm"

	mountTimeout     = 60 * time.Second
	apiserverTimeout = 10 * time.Second
)

// Modes lists every Mode.
var Modes = []Mode{Blob, Cold, Warm}

// Options tune a mount. The zero value is a Cold mount with a private cache
// and a local backend over the image's blob directory.
type Options struct {
	Mode Mode
	// CacheDir is the persistent cache directory; shared-cache tests point
	// several mounts at one. Empty means a fresh directory per mount.
	CacheDir string
	// Config edits the generated config, e.g. to swap the backend.
	Config func(*Config)
	// Args are extra daemon flags.
	Args []string
}

// Request is what an adapter needs to start one daemon.
type Request struct {
	Image fixture.Image
	Mode  Mode
	// Dir is a private directory for the daemon's mountpoints and logs.
	Dir    string
	Config string
	// Socket is the --apiserver Unix socket path.
	Socket string
	Args   []string
}

// Adapter is a way of serving an image as a filesystem: FUSE, fileio and the
// experimental transports all implement it, so the contract cases run
// unchanged against each.
type Adapter interface {
	// Name returns the adapter's short name, such as fuse.
	Name() string
	// Require checks the adapter's preconditions (root, kernel, tools).
	Require(t testing.TB)
	// Supports reports whether the adapter can serve an image in mode.
	Supports(Mode) bool
	// Start starts serving and waits until the filesystem is mounted. The
	// returned teardown must unmount and stop whatever Start started.
	Start(t testing.TB, req Request) (root string, d *Daemon, teardown func())
}

// Mounted is a served image.
type Mounted struct {
	Root string
	// Dir is the daemon's private directory, holding its mountpoints and logs.
	Dir      string
	Daemon   *Daemon
	API      *API
	Image    fixture.Image
	Mode     Mode
	CacheDir string
	// Config is the path of the config the daemon was started with.
	Config string

	once     sync.Once
	teardown func()
}

// Unmount unmounts and stops the daemon. It is idempotent and also runs at
// the end of the test.
func (m *Mounted) Unmount() {
	m.once.Do(m.teardown)
}

// Path joins rel onto the mount root.
func (m *Mounted) Path(rel string) string {
	return filepath.Join(m.Root, rel)
}

// Mount serves img through a and returns once it is mounted.
func Mount(t testing.TB, a Adapter, img fixture.Image, opts Options) *Mounted {
	t.Helper()
	a.Require(t)

	if opts.Mode == "" {
		opts.Mode = Cold
	}

	if !a.Supports(opts.Mode) {
		t.Fatalf("%s does not support %s mode", a.Name(), opts.Mode)
	}
	if opts.Mode == Blob && (img.Merged || opts.Config != nil) {
		t.Fatal("blob mode serves a single blob with no config")
	}

	dir := env.WorkDir(t)

	if opts.CacheDir == "" {
		opts.CacheDir = filepath.Join(dir, "cache")
	}

	if err := os.MkdirAll(opts.CacheDir, 0o755); err != nil {
		t.Fatalf("create cache dir: %v", err)
	}

	cfg := LocalConfig(img.BlobDir, opts.CacheDir)

	if opts.Config != nil {
		opts.Config(&cfg)
	}

	configPath := cfg.Write(t, dir, "config.json")

	if opts.Mode == Warm {
		fill := start(t, a, img, Cold, dir, "fill", configPath, opts)
		warmUp(t, fill.Root, img.Want)
		fill.Unmount()
	}

	return start(t, a, img, opts.Mode, dir, "serve", configPath, opts)
}

func start(t testing.TB, a Adapter, img fixture.Image, mode Mode, dir, name, configPath string, opts Options) *Mounted {
	t.Helper()
	daemonDir := filepath.Join(dir, name)
	if err := os.MkdirAll(daemonDir, 0o755); err != nil {
		t.Fatalf("create %s: %v", daemonDir, err)
	}

	req := Request{
		Image:  img,
		Mode:   mode,
		Dir:    daemonDir,
		Config: configPath,
		Socket: SocketPath(t),
		Args:   opts.Args,
	}

	root, d, teardown := a.Start(t, req)

	if TraitsOf(a).API {
		// The daemon binds its apiserver only after mounting; once the
		// socket exists, connections queue until it serves them.
		d.WaitFor(t, apiserverTimeout, "apiserver at "+req.Socket, func() bool {
			_, err := os.Stat(req.Socket)
			return err == nil
		})
	}

	m := &Mounted{
		Root:     root,
		Dir:      daemonDir,
		Daemon:   d,
		API:      NewAPI(req.Socket),
		Image:    img,
		Mode:     mode,
		CacheDir: opts.CacheDir,
		Config:   configPath,
		teardown: teardown,
	}

	t.Cleanup(m.Unmount)

	return m
}

// SocketPath returns a fresh Unix socket path short enough for sun_path
// (108 bytes), which a per-test directory named after a nested subtest can
// exceed: a file in its own directory under the system temp directory.
func SocketPath(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "nydus-e2e-")
	if err != nil {
		t.Fatalf("create socket dir: %v", err)
	}

	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	return filepath.Join(dir, "api.sock")
}

// warmUp reads every byte of data the image holds through the mount at root:
// the small regular files, whose hash want records, whole, and only the
// recorded data extents of larger ones, since neither FUSE nor every kernel
// reader reports holes and a pass over a multi-gigabyte hole only moves
// zeros. Without a recorded tree it falls back to ReadAll.
func warmUp(t testing.TB, root string, want []fstest.Entry) {
	t.Helper()
	if len(want) == 0 {
		ReadAll(t, root)
		return
	}

	for _, e := range want {
		if e.Type != fstest.TypeReg {
			continue
		}
		if err := readEntry(filepath.Join(root, string(e.Path)), e); err != nil {
			t.Fatalf("warm up %s: %v", e.Path, err)
		}
	}
}

func readEntry(path string, e fstest.Entry) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}

	defer func() { _ = f.Close() }()

	if e.SHA256 != "" {
		_, err = io.Copy(io.Discard, f)
		return err
	}

	for _, x := range e.Extents {
		if _, err := io.Copy(io.Discard, io.NewSectionReader(f, x.Offset, x.Length)); err != nil {
			return err
		}
	}

	return nil
}

// ReadAll reads every regular file under root once: small files whole, large
// sparse ones only where SEEK_DATA finds data, so a multi-gigabyte hole is
// not streamed by a reader that reports holes.
func ReadAll(t testing.TB, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}

		return readFile(path)
	})

	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
}

func readFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}

	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return err
	}

	if st.Size() <= 64<<20 {
		_, err = io.Copy(io.Discard, f)
		return err
	}

	ranges, err := fstest.DataRanges(f)
	if err != nil {
		return err
	}

	for _, r := range ranges {
		if _, err := io.Copy(io.Discard, io.NewSectionReader(f, r[0], r[1]-r[0])); err != nil {
			return err
		}
	}

	return nil
}
