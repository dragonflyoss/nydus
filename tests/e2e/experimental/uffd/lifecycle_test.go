package uffd

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
	"unsafe"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestLifecycle(t *testing.T) {
	t.Parallel()
	if os.Getenv(childModeEnv) == childModeOutstandingFault {
		outstandingFaultChild(t)
		return
	}

	requireUserfaultfd(t)
	s := startService(t, standardImage(t))
	deviceSize := s.deviceSize(t)

	t.Run("ClientDisconnect", func(t *testing.T) {
		c := s.newFaultClient(t, handshakeCopy, blockSize)
		c.ack(t)
		c.close(t)
		s.expectAlive(t, deviceSize)
	})

	t.Run("DisconnectWithOutstandingFault", func(t *testing.T) {
		half := alignDown(deviceSize/2, blockSize)
		if !assert.Positive(t, half) {
			t.FailNow()
		}

		cmd := exec.Command(os.Args[0], "-test.run=^TestLifecycle$")

		cmd.Env = append(os.Environ(),
			childModeEnv+"="+childModeOutstandingFault,
			childSocketEnv+"="+s.socket,
			fmt.Sprintf("%s=%d", childDeviceSizeEnv, deviceSize),
			fmt.Sprintf("%s=%d", childRegionSizeEnv, half),
		)

		stdin, err := cmd.StdinPipe()
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		stdout, err := cmd.StdoutPipe()
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if !assert.NoError(t, cmd.Start()) {
			t.FailNow()
		}

		exited := make(chan error, 1)

		defer func() {
			_ = stdin.Close()
			_ = cmd.Process.Kill()
			<-exited

			if t.Failed() {
				t.Logf("child stderr:\n%s", stderr.String())
			}
		}()

		lines := make(chan string, 16)

		go func() {
			sc := bufio.NewScanner(stdout)
			for sc.Scan() {
				lines <- sc.Text()
			}

			close(lines)
			exited <- cmd.Wait()
		}()

		next := func(what string) string {
			select {
			case line, ok := <-lines:
				assert.True(t, ok)
				return line

			case <-time.After(caseTimeout):
				t.Fatalf("timed out waiting for child %s", what)
				return ""
			}
		}

		if !assert.Equal(t, "READY", next("READY")) {
			t.FailNow()
		}
		if !assert.Equal(t, "TOUCHING", next("TOUCHING")) {
			t.FailNow()
		}

		select {
		case line := <-lines:
			t.Fatalf("a fault outside the declared region was resolved: child printed %q", line)

		case <-time.After(time.Second):
		}

		_, err = io.WriteString(stdin, "close\n")
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.Equal(t, "RESOLVED 0", next("RESOLVED")) {
			t.FailNow()
		}

		assert.Equal(t, "DONE", next("DONE"))

		select {
		case err := <-exited:
			exited <- err
			assert.NoError(t, err)

		case <-time.After(caseTimeout):
			t.Fatalf("child still running %v after teardown", caseTimeout)
		}

		s.expectAlive(t, deviceSize)
	})

	t.Run("ServiceStopWithActiveSession", func(t *testing.T) {
		c := s.newFaultClient(t, handshakeCopy, blockSize)
		c.ack(t)

		if !assert.True(t, s.daemon.Stop()) {
			t.FailNow()
		}
		if !assert.Zero(t, s.daemon.ExitCode()) {
			t.FailNow()
		}

		assert.NoFileExists(t, s.socket)
		c.conn.expectClosed(t)
		c.close(t)
	})

	t.Run("RestartWithStaleSocket", func(t *testing.T) {
		if !assert.True(t, s.daemon.Stop()) {
			t.FailNow()
		}
		if !assert.NoError(t, os.WriteFile(s.socket, nil, 0o644)) {
			t.FailNow()
		}

		s.start(t)
		c := s.newFaultClient(t, handshakeCopy, blockSize)
		c.ack(t)
		b := waitTouch(t, c.touchAsync(t, 0), faultTimeout, "cold fault after restart")
		assert.Equal(t, deviceBytes(t, s.socket, 0, blockSize)[0], b)
	})
}

const (
	childModeEnv              = "NYDUS_E2E_UFFD_CHILD_MODE"
	childModeOutstandingFault = "outstanding-fault"
	childSocketEnv            = "NYDUS_E2E_UFFD_CHILD_SOCKET"
	childDeviceSizeEnv        = "NYDUS_E2E_UFFD_CHILD_DEVICE_SIZE"
	childRegionSizeEnv        = "NYDUS_E2E_UFFD_CHILD_REGION_SIZE"
)

func outstandingFaultChild(t *testing.T) {
	socket := os.Getenv(childSocketEnv)
	if socket == "" {
		t.Fatalf("%s not set", childSocketEnv)
	}

	deviceSize := uint64(env.Int(t, childDeviceSizeEnv, 0))
	regionSize := uint64(env.Int(t, childRegionSizeEnv, 0))
	if regionSize == 0 || regionSize >= deviceSize || deviceSize < blockSize {
		t.Fatalf("invalid geometry: device=%d region=%d block=%d", deviceSize, regionSize, blockSize)
	}

	mem, err := unix.Mmap(-1, 0, int(deviceSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		t.Fatalf("anonymous VMA mmap: %v", err)
	}

	uffd, err := newUserfaultfd()
	if err != nil {
		t.Fatal(err)
	}

	base := uint64(uintptr(unsafe.Pointer(&mem[0])))
	if err := registerMissing(uffd, base, deviceSize); err != nil {
		t.Fatal(err)
	}

	conn := dial(t, socket)

	region := vmaRegion{
		virtAddr:  base,
		size:      regionSize,
		faultSize: blockSize,
		prot:      int32(unix.PROT_READ | unix.PROT_WRITE),
		flags:     int32(unix.MAP_PRIVATE | unix.MAP_ANONYMOUS),
	}

	conn.handshake(t, handshakeCopy, []vmaRegion{region}, uffd)

	if size, _ := conn.stat(t); size != deviceSize {
		t.Fatalf("device size %d, want %d", size, deviceSize)
	}

	fmt.Println("READY")

	resolved := make(chan byte, 1)

	go func() {
		fmt.Println("TOUCHING")
		resolved <- mem[deviceSize-blockSize]
	}()

	_, _ = unix.Read(0, make([]byte, 1))

	_ = conn.Close()
	_ = unix.Close(uffd)
	b := <-resolved
	fmt.Printf("RESOLVED %d\n", b)

	if b != 0 {
		t.Fatalf("outstanding fault resolved with byte %#02x, want a zero page", b)
	}

	fmt.Println("DONE")
}
