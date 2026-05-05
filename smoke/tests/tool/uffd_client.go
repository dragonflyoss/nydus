// Copyright 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tool

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// UFFD protocol constants (matching service/src/uffd_proto.rs).
const (
	msgTypeHandshake = 0
	msgTypePageFault = 1
	msgTypeStat      = 2
	msgTypeStatResp  = 3

	PolicyZerocopy = 0
	PolicyCopy     = 1

	// userfaultfd syscall numbers.
	sysUserfaultfdAMD64 = 323
	sysUserfaultfdARM64 = 282

	// UFFDIO ioctl numbers.
	uffdioAPI      = 0xc018aa3f
	uffdioRegister = 0xc020aa00
	uffdioWake     = 0x8010aa02

	uffdioRegisterModeMissing = 1

	uffdAPI = 0xaa

	// EROFS superblock magic.
	erofsMagicOffset = 1024
	erofsMagic       = 0xE0F5E1E2
)

// Protocol message types.

type vmaRegion struct {
	BaseHostVirtAddr uint64 `json:"base_host_virt_addr"`
	Size             uint64 `json:"size"`
	Offset           uint64 `json:"offset"`
	PageSize         uint64 `json:"page_size"`
	PageSizeKib      uint64 `json:"page_size_kib,omitempty"`
	Prot             int32  `json:"prot,omitempty"`
	Flags            int32  `json:"flags,omitempty"`
}

type handshakeRequest struct {
	Type           int         `json:"type"`
	Regions        []vmaRegion `json:"regions"`
	Policy         int         `json:"policy"`
	EnablePrefault bool        `json:"enable_prefault"`
}

type blobRange struct {
	Len         uint64 `json:"len"`
	BlobOffset  uint64 `json:"blob_offset"`
	BlockOffset uint64 `json:"block_offset"`
}

type pageFaultResponse struct {
	Type   int         `json:"type"`
	Ranges []blobRange `json:"ranges"`
}

type statRequest struct {
	Type int `json:"type"`
}

type statResponse struct {
	Type      int    `json:"type"`
	Size      uint64 `json:"size"`
	BlockSize uint32 `json:"block_size"`
	Flags     uint32 `json:"flags"`
	Version   uint32 `json:"version"`
}

// UffdClient implements the UFFD block device protocol for testing.
type UffdClient struct {
	conn       *net.UnixConn
	uffdFd     int
	memPtr     uintptr // base address of mmap'd region
	memSize    uint64  // size of mmap'd region
	deviceSize uint64
	blockSize  uint32
	policy     int
	region     vmaRegion
	workerWg   sync.WaitGroup
	workerDone chan struct{}
	closed     bool
	mu         sync.Mutex
}

// sysUserfaultfd returns the syscall number for the current architecture.
func sysUserfaultfd() uintptr {
	switch runtime.GOARCH {
	case "amd64":
		return sysUserfaultfdAMD64
	case "arm64":
		return sysUserfaultfdARM64
	default:
		return sysUserfaultfdAMD64 // fallback
	}
}

// createUserfaultfd creates a userfaultfd file descriptor.
func createUserfaultfd() (int, error) {
	fd, _, errno := syscall.Syscall(sysUserfaultfd(), syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0, 0)
	if errno != 0 {
		return -1, fmt.Errorf("userfaultfd: %w", errno)
	}

	// UFFDIO_API handshake.
	var api struct {
		API      uint64
		Features uint64
		Ioctls   uint64
	}
	api.API = uffdAPI

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, uffdioAPI, uintptr(unsafe.Pointer(&api)))
	if errno != 0 {
		syscall.Close(int(fd))
		return -1, fmt.Errorf("UFFDIO_API: %w", errno)
	}

	return int(fd), nil
}

// uffdRegister registers a memory range with userfaultfd.
func uffdRegister(fd int, addr uintptr, len uint64) error {
	var reg struct {
		Start  uint64
		Len    uint64
		Mode   uint64
		Ioctls uint64
	}
	reg.Start = uint64(addr)
	reg.Len = len
	reg.Mode = uffdioRegisterModeMissing

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uffdioRegister, uintptr(unsafe.Pointer(&reg)))
	if errno != 0 {
		return fmt.Errorf("UFFDIO_REGISTER: %w", errno)
	}
	return nil
}

// uffdWake wakes threads blocked on page faults in the given range.
func uffdWake(fd int, addr uintptr, len uint64) error {
	var rng struct {
		Start uint64
		Len   uint64
	}
	rng.Start = uint64(addr)
	rng.Len = len

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uffdioWake, uintptr(unsafe.Pointer(&rng)))
	if errno != 0 {
		// EEXIST means page already mapped — not a fatal error.
		if errno == syscall.EEXIST {
			return nil
		}
		return fmt.Errorf("UFFDIO_WAKE: %w", errno)
	}
	return nil
}

// sendWithFd sends data with file descriptors via SCM_RIGHTS.
func sendWithFd(conn *net.UnixConn, data []byte, fds []int) error {
	oob := syscall.UnixRights(fds...)
	_, _, err := conn.WriteMsgUnix(data, oob, nil)
	return err
}

// recvWithFd receives data and file descriptors via SCM_RIGHTS.
func recvWithFd(conn *net.UnixConn, buf []byte) (int, []int, error) {
	oobBuf := make([]byte, 4096)
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oobBuf)
	if err != nil {
		return n, nil, err
	}

	var fds []int
	if oobn > 0 {
		msgs, err := syscall.ParseSocketControlMessage(oobBuf[:oobn])
		if err != nil {
			return n, nil, fmt.Errorf("parse socket control message: %w", err)
		}
		for _, msg := range msgs {
			parsedFds, err := syscall.ParseUnixRights(&msg)
			if err != nil {
				return n, nil, fmt.Errorf("parse unix rights: %w", err)
			}
			fds = append(fds, parsedFds...)
		}
	}

	return n, fds, nil
}

// NewUffdClient connects to the UFFD service and queries device size.
func NewUffdClient(sockPath string) (*UffdClient, error) {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", sockPath, err)
	}

	c := &UffdClient{
		conn:       conn,
		uffdFd:     -1,
		workerDone: make(chan struct{}),
	}

	// Send Stat request.
	req := statRequest{Type: msgTypeStat}
	data, err := json.Marshal(req)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("marshal stat request: %w", err)
	}
	if err := sendWithFd(conn, data, nil); err != nil {
		c.Close()
		return nil, fmt.Errorf("send stat request: %w", err)
	}

	// Receive Stat response.
	buf := make([]byte, 4096)
	n, _, err := recvWithFd(conn, buf)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("recv stat response: %w", err)
	}

	var resp statResponse
	if err := json.Unmarshal(buf[:n], &resp); err != nil {
		c.Close()
		return nil, fmt.Errorf("unmarshal stat response: %w", err)
	}
	if resp.Type != msgTypeStatResp {
		c.Close()
		return nil, fmt.Errorf("unexpected stat response type %d", resp.Type)
	}

	c.deviceSize = resp.Size
	c.blockSize = resp.BlockSize

	return c, nil
}

// DeviceSize returns the block device size reported by the server.
func (c *UffdClient) DeviceSize() uint64 {
	return c.deviceSize
}

// BlockSize returns the block size reported by the server.
func (c *UffdClient) BlockSize() uint32 {
	return c.blockSize
}

// Handshake creates a userfaultfd, mmaps a region, registers it,
// and sends the handshake request with the uffd fd via SCM_RIGHTS.
func (c *UffdClient) Handshake(policy int, enablePrefault bool) error {
	if c.memPtr != 0 {
		return fmt.Errorf("already handshaked")
	}

	// Create userfaultfd.
	uffdFd, err := createUserfaultfd()
	if err != nil {
		return fmt.Errorf("create userfaultfd: %w", err)
	}
	c.uffdFd = uffdFd

	// mmap anonymous region (2MB-aligned for huge page support).
	pageSize := uint64(4096)
	align := uint64(2 * 1024 * 1024) // 2MB
	mmapSize := (c.deviceSize + align - 1) / align * align
	if mmapSize == 0 {
		mmapSize = align
	}

	addr, _, errno := syscall.Syscall6(
		syscall.SYS_MMAP,
		0,                 // addr: let kernel choose
		uintptr(mmapSize), // length
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS,
		^uintptr(0), // fd: -1
		0,           // offset
	)
	if errno != 0 {
		syscall.Close(uffdFd)
		c.uffdFd = -1
		return fmt.Errorf("mmap: %w", errno)
	}
	c.memPtr = addr
	c.memSize = mmapSize

	// Register with userfaultfd.
	if err := uffdRegister(uffdFd, addr, mmapSize); err != nil {
		munmapAndClose(addr, mmapSize, uffdFd)
		c.memPtr = 0
		c.uffdFd = -1
		return fmt.Errorf("uffd register: %w", err)
	}

	// Send handshake request with uffd fd.
	c.policy = policy
	c.region = vmaRegion{
		BaseHostVirtAddr: uint64(addr),
		Size:             c.deviceSize,
		Offset:           0,
		PageSize:         pageSize,
		Prot:             syscall.PROT_READ,
		Flags:            syscall.MAP_PRIVATE | syscall.MAP_FIXED,
	}

	req := handshakeRequest{
		Type:           msgTypeHandshake,
		Regions:        []vmaRegion{c.region},
		Policy:         policy,
		EnablePrefault: enablePrefault,
	}
	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal handshake: %w", err)
	}

	if err := sendWithFd(c.conn, data, []int{uffdFd}); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

	// For zerocopy mode, start the worker goroutine.
	if policy == PolicyZerocopy {
		c.workerWg.Add(1)
		go c.zerocopyWorker()
	}

	return nil
}

// zerocopyWorker receives PageFaultResponse messages and mmaps blob fds.
func (c *UffdClient) zerocopyWorker() {
	defer c.workerWg.Done()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	buf := make([]byte, 4096)
	for {
		select {
		case <-c.workerDone:
			return
		default:
		}

		// No deadline — block until data arrives.
		c.conn.SetReadDeadline(time.Time{})
		n, fds, err := recvWithFd(c.conn, buf)
		if err != nil {
			if isTemporaryError(err) {
				continue
			}
			// Connection closed or error — stop worker.
			return
		}
		if n == 0 {
			return
		}

		// Parse the response.
		var resp pageFaultResponse
		if err := json.Unmarshal(buf[:n], &resp); err != nil {
			closeFds(fds)
			continue
		}

		if resp.Type != msgTypePageFault {
			closeFds(fds)
			continue
		}

		if len(fds) != len(resp.Ranges) {
			closeFds(fds)
			continue
		}

		// Process each range: mmap blob fd at the correct address.
		for i, r := range resp.Ranges {
			fd := fds[i]
			targetAddr := c.region.BaseHostVirtAddr + (r.BlockOffset - c.region.Offset)

			mapped, _, _ := syscall.Syscall6(
				syscall.SYS_MMAP,
				uintptr(targetAddr),
				uintptr(r.Len),
				uintptr(c.region.Prot),
				uintptr(c.region.Flags)|syscall.MAP_SHARED,
				uintptr(fd),
				uintptr(r.BlobOffset),
			)
			if mapped == ^uintptr(0) { // MAP_FAILED
				// mmap failed — close fd and continue.
				syscall.Close(fd)
				continue
			}

			// mmap succeeded — close the original fd (mmap duplicated it).
			syscall.Close(fd)

			// Wake any threads blocked on page faults in this range.
			uffdWake(c.uffdFd, uintptr(targetAddr), r.Len)
		}
	}
}

// ReadAt reads data from the UFFD-backed memory at the given offset.
// This triggers page faults which are resolved by the server.
func (c *UffdClient) ReadAt(offset, length int64) ([]byte, error) {
	if c.memPtr == 0 {
		return nil, fmt.Errorf("not handshaked")
	}
	if offset < 0 || offset+length > int64(c.deviceSize) {
		return nil, fmt.Errorf("read out of bounds: offset=%d length=%d deviceSize=%d", offset, length, c.deviceSize)
	}

	// Read from the mmap'd region. This triggers page faults resolved by the server.
	start := c.memPtr + uintptr(offset)
	data := make([]byte, length)
	copy(data, mustSliceFromPtr(start, length))
	return data, nil
}

// mustSliceFromPtr creates a byte slice from a uintptr address.
// The caller must ensure the address is valid and the memory is properly mapped.
// This is necessary because mmap returns uintptr, but we need a slice for I/O operations.
func mustSliceFromPtr(addr uintptr, length int64) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(addr)), length)
}

// munmapAndClose unmaps memory and closes the file descriptor during error cleanup.
func munmapAndClose(addr uintptr, size uint64, fd int) {
	if addr != 0 {
		_ = syscall.Munmap(mustSliceFromPtr(addr, int64(size)))
	}
	if fd >= 0 {
		_ = syscall.Close(fd)
	}
}

// Close cleans up all resources.
func (c *UffdClient) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}
	c.closed = true

	// Signal worker to stop.
	if c.workerDone != nil {
		select {
		case <-c.workerDone:
		default:
			close(c.workerDone)
		}
	}

	// Close the socket (will cause worker to exit if still running).
	if c.conn != nil {
		c.conn.Close()
	}

	// Wait for worker to finish.
	c.workerWg.Wait()

	// Unmap memory.
	if c.memPtr != 0 {
		syscall.Munmap(mustSliceFromPtr(c.memPtr, c.memSize))
		c.memPtr = 0
	}

	// Close userfaultfd.
	if c.uffdFd >= 0 {
		syscall.Close(c.uffdFd)
		c.uffdFd = -1
	}
}

// VerifyErofsMagic checks that the EROFS superblock magic is present at offset 1024.
func (c *UffdClient) VerifyErofsMagic() error {
	data, err := c.ReadAt(erofsMagicOffset, 4)
	if err != nil {
		return fmt.Errorf("read erofs magic: %w", err)
	}
	magic := binary.LittleEndian.Uint32(data)
	if magic != erofsMagic {
		return fmt.Errorf("erofs magic mismatch: got 0x%08x, want 0x%08x", magic, erofsMagic)
	}
	return nil
}

// VerifyNonZero reads data at the given offset and checks it's not all zeros.
func (c *UffdClient) VerifyNonZero(offset, length int64) error {
	data, err := c.ReadAt(offset, length)
	if err != nil {
		return fmt.Errorf("read at offset %d: %w", offset, err)
	}
	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("data at offset %d is all zeros (expected non-zero data)", offset)
	}
	return nil
}

// closeFds closes all file descriptors in the slice.
func closeFds(fds []int) {
	for _, fd := range fds {
		syscall.Close(fd)
	}
}

// isTemporaryError returns true if the error is a temporary network error.
func isTemporaryError(err error) bool {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	return false
}

// ExportDiskImage uses nydus-image to export the RAFS image to a raw disk file.
// Returns the path to the exported file.
func ExportDiskImage(builderPath, bootstrapPath, localfsDir, outputPath string) error {
	cmd := fmt.Sprintf("%s export --block --bootstrap %s --localfs-dir %s --output %s",
		builderPath, bootstrapPath, localfsDir, outputPath)
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nydus-image export failed: %w\n%s", err, string(out))
	}
	return nil
}
