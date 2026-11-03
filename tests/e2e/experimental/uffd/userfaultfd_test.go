package uffd

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"golang.org/x/sys/unix"
)

const (
	uffdioAPI           = 0xc018aa3f
	uffdioRegister      = 0xc020aa00
	uffdioWake          = 0x8010aa02
	uffdAPIVersion      = 0xaa
	uffdRegisterMissing = 0x1

	uffdioBitWake     = 1 << 0x02
	uffdioBitCopy     = 1 << 0x03
	uffdioBitZeropage = 1 << 0x04
	uffdioRequired    = uffdioBitWake | uffdioBitCopy | uffdioBitZeropage
)

type uffdioAPIArg struct {
	api      uint64
	features uint64
	ioctls   uint64
}

type uffdioRangeArg struct {
	start uint64
	len   uint64
}

type uffdioRegisterArg struct {
	rng    uffdioRangeArg
	mode   uint64
	ioctls uint64
}

func uffdIoctl(fd int, req uintptr, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, uintptr(arg))
	if errno != 0 {
		return errno
	}

	return nil
}

func newUserfaultfd() (int, error) {
	rawFd, _, errno := unix.Syscall(unix.SYS_USERFAULTFD, unix.O_CLOEXEC, 0, 0)
	if errno != 0 {
		return -1, fmt.Errorf("userfaultfd syscall unavailable: %v (check vm.unprivileged_userfaultfd or run as root)", errno)
	}

	fd := int(rawFd)

	api := uffdioAPIArg{api: uffdAPIVersion}
	if err := uffdIoctl(fd, uffdioAPI, unsafe.Pointer(&api)); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("uffdioAPI handshake failed: %v", err)
	}

	return fd, nil
}

func registerMissing(fd int, base, size uint64) error {
	reg := uffdioRegisterArg{rng: uffdioRangeArg{start: base, len: size}, mode: uffdRegisterMissing}
	if err := uffdIoctl(fd, uffdioRegister, unsafe.Pointer(&reg)); err != nil {
		return fmt.Errorf("uffdioRegister (MISSING mode) failed: %v", err)
	}
	if reg.ioctls&uffdioRequired != uffdioRequired {
		return fmt.Errorf("required UFFD ioctls missing: have %#x, need WAKE|COPY|ZEROPAGE (%#x)", reg.ioctls, uint64(uffdioRequired))
	}

	return nil
}

func probeCapability() error {
	fd, err := newUserfaultfd()
	if err != nil {
		return err
	}

	defer func() { _ = unix.Close(fd) }()
	pageSize := unix.Getpagesize()
	mem, err := unix.Mmap(-1, 0, pageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return fmt.Errorf("anonymous mmap failed: %v", err)
	}

	defer func() { _ = unix.Munmap(mem) }()

	return registerMissing(fd, uint64(uintptr(unsafe.Pointer(&mem[0]))), uint64(pageSize))
}

func requireUserfaultfd(t testing.TB) {
	t.Helper()
	err := probeCapability()
	env.Require(t, err == nil, "runner lacks userfaultfd: %v", err)
}

func alignUp(v, a uint64) uint64 { return (v + a - 1) / a * a }

func alignDown(v, a uint64) uint64 { return v / a * a }
