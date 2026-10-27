package mount

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"golang.org/x/sys/unix"
)

// Mode is how an image is served.
type Mode string

const (
	// Blob serves a single self-describing blob (--blob), no bootstrap.
	Blob Mode = "blob"
	// Cold serves the bootstrap with an empty persistent cache.
	Cold Mode = "cold"
	// Warm serves the bootstrap with a cache a previous mount filled by
	// reading every file, so reads come from the cache rather than the
	// backend.
	Warm Mode = "warm"
)

// Modes are all the modes, in matrix order.
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
	Name() string
	// Require checks the adapter's preconditions (root, kernel, tools).
	Require(t env.TB)
	Supports(Mode) bool
	// Start starts serving and waits until the filesystem is mounted. The
	// returned teardown must unmount and stop whatever Start started.
	Start(t env.TB, req Request) (root string, d *Daemon, teardown func())
}

// Mounted is a served image.
type Mounted struct {
	Root     string
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
func Mount(t env.TB, a Adapter, img fixture.Image, opts Options) *Mounted {
	t.Helper()
	a.Require(t)
	if opts.Mode == "" {
		opts.Mode = Cold
	}
	if !a.Supports(opts.Mode) {
		t.Fatalf("%s does not support %s mode", a.Name(), opts.Mode)
	}
	if opts.Mode == Blob && (img.Merged || opts.Config != nil) {
		t.Fatalf("blob mode serves a single blob with no config")
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
		WarmUp(t, fill.Root, img.Want)
		fill.Unmount()
	}
	return start(t, a, img, opts.Mode, dir, "serve", configPath, opts)
}

func start(t env.TB, a Adapter, img fixture.Image, mode Mode, dir, name, configPath string, opts Options) *Mounted {
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
		d.WaitFor(t, 10*time.Second, "apiserver at "+req.Socket, func() bool {
			_, err := os.Stat(req.Socket)
			return err == nil
		})
	}
	m := &Mounted{
		Root:     root,
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

var socketSeq struct {
	sync.Mutex
	dir string
	n   int
}

// SocketPath returns a fresh Unix socket path short enough for sun_path
// (108 bytes), which a per-test directory named after a nested subtest can
// exceed.
func SocketPath(t env.TB) string {
	t.Helper()
	socketSeq.Lock()
	defer socketSeq.Unlock()
	if socketSeq.dir == "" {
		dir, err := os.MkdirTemp("", "nydus-e2e-")
		if err != nil {
			t.Fatalf("create socket dir: %v", err)
		}
		socketSeq.dir = dir
	}
	socketSeq.n++
	path := filepath.Join(socketSeq.dir, fmt.Sprintf("%d.sock", socketSeq.n))
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

// WarmUp reads every byte of data the image holds through the mount at root:
// regular files whole, and only the recorded data extents of large sparse
// ones, since neither FUSE nor every kernel reader reports holes and a pass
// over a multi-gigabyte hole only moves zeros. Without a recorded tree it
// falls back to ReadAll.
func WarmUp(t env.TB, root string, want []oracle.Entry) {
	t.Helper()
	if len(want) == 0 {
		ReadAll(t, root)
		return
	}
	for _, e := range want {
		if e.Type != "reg" {
			continue
		}
		if err := readEntry(filepath.Join(root, string(e.Path)), e); err != nil {
			t.Fatalf("warm up %s: %v", e.Path, err)
		}
	}
}

func readEntry(path string, e oracle.Entry) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if len(e.Extents) == 0 {
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
func ReadAll(t env.TB, root string) {
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
	fd := int(f.Fd())
	for off := int64(0); off < st.Size(); {
		data, err := unix.Seek(fd, off, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("SEEK_DATA %s: %w", path, err)
		}
		hole, err := unix.Seek(fd, data, unix.SEEK_HOLE)
		if err != nil {
			return fmt.Errorf("SEEK_HOLE %s: %w", path, err)
		}
		if _, err := io.Copy(io.Discard, io.NewSectionReader(f, data, hole-data)); err != nil {
			return err
		}
		off = hole
	}
	return nil
}
