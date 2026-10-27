package uffd

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/stretchr/testify/require"
)

// TestRealFaultCopy hands the service a real userfaultfd over an anonymous
// VMA and lets it resolve every fault with UFFDIO_COPY/ZEROPAGE: the cold
// and warm memory equal the device the service FETCHes, carry the EROFS
// superblock and a zero tail, and loop-mounted as EROFS reproduce the
// source tree.
func TestRealFaultCopy(t *testing.T) {
	t.Parallel()
	requireUserfaultfd(t)
	img := standardImage(t)
	s := startService(t, img)
	c := newFaultClient(t, s, handshakeCopy, 2<<20, 0)
	c.ack(t)

	want := deviceBytes(t, s.socket, 0, c.deviceSize)
	require.Equal(t, uint32(erofsSuperMagic), binary.LittleEndian.Uint32(want[erofsSuperOffset:]),
		"device reference lacks the EROFS superblock")

	first := waitTouch(t, c.touchAsync(t, 0), faultDeadline, "cold fault at device offset 0")
	require.Equal(t, want[0], first, "cold fault returned a wrong byte")
	for off := uint64(0); off < c.deviceSize; off += c.faultSize {
		waitTouch(t, c.touchAsync(t, off), faultDeadline, fmt.Sprintf("cold fault at device offset %#x", off))
	}
	cold := c.snapshot(t, "cold full-device read")
	requireSameBytes(t, want, cold, "cold fault-populated memory")
	require.Equal(t, make([]byte, c.blockSize), cold[c.deviceSize-uint64(c.blockSize):], "device tail not zero")

	// Resolved pages stay resolved: a second pass needs no service.
	requireSameBytes(t, want, c.snapshot(t, "warm full-device read"), "warm re-read")

	t.Run("LoopMount", func(t *testing.T) {
		env.RequireRoot(t)
		env.RequireKernel(t, 6, 4, "EROFS flatdev mounts of a flattened image")
		env.RequireFilesystem(t, "erofs")
		dir := env.WorkDir(t)
		image := filepath.Join(dir, "faulted-device.img")
		require.NoError(t, os.WriteFile(image, cold, 0o644))
		mnt := filepath.Join(dir, "mnt")
		require.NoError(t, os.MkdirAll(mnt, 0o755))
		out, err := exec.Command("mount", "-t", "erofs", "-o", "ro,loop", image, mnt).CombinedOutput()
		require.NoError(t, err, "loop-mount the fault-populated device: %s", out)
		t.Cleanup(func() { mount.Unmount(mnt) })
		oracle.VerifyMount(t, mnt, img.Want, img.Compare())
	})
}
