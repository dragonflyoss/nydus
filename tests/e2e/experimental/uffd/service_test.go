package uffd

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
)

const (
	blockSize    = 4096
	faultTimeout = 10 * time.Second
	caseTimeout  = 30 * time.Second

	daemonName = "nydus-uffd"
)

func standardImage(t testing.TB) fixture.Image {
	t.Helper()
	return fixture.Build(t, fixture.Standard, fixture.MustLayout(t, "zstd-4k"))
}

func layeredImage(t testing.TB, n int) fixture.Image {
	t.Helper()
	layout := fixture.MustLayout(t, "zstd-4k")
	dir := env.WorkDir(t)
	blobDir := filepath.Join(dir, "blobs")
	var blobs []string

	for i := range n {
		name := fmt.Sprintf("layer-%02d", i)
		src := filepath.Join(dir, name)
		corpus.New(t, src).CreateFile(t, name+".bin", bytes.Repeat([]byte{byte(i + 1)}, 8192+i*512))
		blob, _ := fixture.BuildInto(t, blobDir, filepath.Join(dir, name+".bootstrap"), src, layout)
		blobs = append(blobs, blob)
	}

	bootstrap := filepath.Join(dir, "merged.bootstrap")
	env.Run(t, env.Nydus(t), append([]string{"merge", "--bootstrap", bootstrap}, blobs...)...)

	return fixture.Image{
		Name:      fmt.Sprintf("layers-%d", n),
		Layout:    layout,
		Bootstrap: bootstrap,
		BlobDir:   blobDir,
		Blobs:     blobs,
		Merged:    true,
	}
}

type service struct {
	img    fixture.Image
	dir    string
	config string
	socket string
	daemon *mount.Daemon
}

func startService(t testing.TB, img fixture.Image) *service {
	t.Helper()
	env.MustHaveSubcommand(t, "uffd")
	dir := env.WorkDir(t)
	cache := filepath.Join(dir, "cache")
	if !assert.NoError(t, os.MkdirAll(cache, 0o755)) {
		t.FailNow()
	}

	s := &service{
		img:    img,
		dir:    dir,
		config: mount.LocalConfig(img.BlobDir, cache).Write(t, dir, "config.json"),
		socket: mount.SocketPath(t),
	}

	s.start(t)

	return s
}

func (s *service) start(t testing.TB) {
	t.Helper()
	s.daemon = mount.StartDaemon(t, s.dir, daemonName, env.Nydus(t), mount.DaemonArgs([]string{"uffd",
		"--bootstrap", s.img.Bootstrap,
		"--config", s.config,
		"--socket", s.socket,
		"--threads", "1",
	}, mount.Request{Dir: s.dir}, daemonName)...)

	s.daemon.WaitFor(t, caseTimeout, "socket "+s.socket, func() bool {
		conn, err := net.DialTimeout("unix", s.socket, 100*time.Millisecond)
		if err != nil {
			return false
		}

		_ = conn.Close()

		return true
	})
}

func (s *service) deviceSize(t testing.TB) uint64 {
	t.Helper()
	conn := dial(t, s.socket)
	defer func() { _ = conn.Close() }()
	size, _ := conn.stat(t)

	return size
}

func (s *service) expectAlive(t testing.TB, wantSize uint64) {
	t.Helper()
	assert.Equal(t, wantSize, s.deviceSize(t))
}
