package uffd

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

const (
	protocolMagic   = 0x5546_4644
	protocolVersion = 1

	msgHandshake     = 0x01
	msgStat          = 0x02
	msgFetch         = 0x03
	msgProbe         = 0x04
	msgRangeResponse = 0x81
	msgStatResponse  = 0x82

	headerSize       = 20
	rangeSize        = 24
	statResponseSize = 16
	rangeCountSize   = 4
	fetchRequestSize = 16
	regionSize       = 40
	maxRangesPerMsg  = 16

	flagNext          = 1 << 0
	handshakeCopy     = 0x01
	handshakePrefault = 0x02
)

type header struct {
	flags   uint16
	msgType uint16
	length  uint32
}

type deviceRange struct {
	deviceOffset uint64
	fileOffset   uint64
	length       uint64
}

type vmaRegion struct {
	virtAddr  uint64
	size      uint64
	offset    uint64
	faultSize uint64
	prot      int32
	flags     int32
}

type client struct {
	*net.UnixConn
}

func dial(t testing.TB, socket string) client {
	t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return client{c}
}

func encodeHeader(magic uint32, flags, msgType uint16, length uint32) []byte {
	h := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(h[0:4], magic)
	binary.LittleEndian.PutUint16(h[4:6], flags)
	binary.LittleEndian.PutUint16(h[6:8], msgType)
	binary.LittleEndian.PutUint32(h[16:20], length)

	return h
}

func (c client) send(t testing.TB, msgType uint16, payload []byte) {
	t.Helper()
	_, err := c.Write(append(encodeHeader(protocolMagic, 0, msgType, uint32(len(payload))), payload...))
	if !assert.NoError(t, err) {
		t.FailNow()
	}
}

func (c client) writeRawFrame(t testing.TB, magic uint32, flags, msgType uint16, declaredLen uint32, payload []byte, fds []int) {
	t.Helper()
	frame := append(encodeHeader(magic, flags, msgType, declaredLen), payload...)

	var rights []byte
	if len(fds) > 0 {
		rights = unix.UnixRights(fds...)
	}

	n, oobn, err := c.WriteMsgUnix(frame, rights, nil)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.Equal(t, len(frame), n) {
		t.FailNow()
	}

	assert.Equal(t, len(rights), oobn)
}

func encodeRange(offset, length uint64) []byte {
	payload := make([]byte, fetchRequestSize)
	binary.LittleEndian.PutUint64(payload[0:8], offset)
	binary.LittleEndian.PutUint64(payload[8:16], length)

	return payload
}

func encodeHandshakePayload(version uint16, flags, regionCount byte, regions []vmaRegion) []byte {
	payload := make([]byte, 4+len(regions)*regionSize)
	binary.LittleEndian.PutUint16(payload[0:2], version)
	payload[2] = flags
	payload[3] = regionCount
	off := 4

	for _, r := range regions {
		binary.LittleEndian.PutUint64(payload[off:off+8], r.virtAddr)
		binary.LittleEndian.PutUint64(payload[off+8:off+16], r.size)
		binary.LittleEndian.PutUint64(payload[off+16:off+24], r.offset)
		binary.LittleEndian.PutUint64(payload[off+24:off+32], r.faultSize)
		binary.LittleEndian.PutUint32(payload[off+32:off+36], uint32(r.prot))
		binary.LittleEndian.PutUint32(payload[off+36:off+40], uint32(r.flags))
		off += regionSize
	}

	return payload
}

func (c client) handshake(t testing.TB, flags byte, regions []vmaRegion, uffd int) {
	t.Helper()
	payload := encodeHandshakePayload(protocolVersion, flags, byte(len(regions)), regions)
	c.writeRawFrame(t, protocolMagic, 0, msgHandshake, uint32(len(payload)), payload, []int{uffd})
}

func (c client) readFrame(t testing.TB) (header, []byte, []int) {
	t.Helper()
	buf := make([]byte, headerSize)
	oob := make([]byte, 4096)
	var rights []int

	for n := 0; n < headerSize; {
		m, oobn, _, _, err := c.ReadMsgUnix(buf[n:], oob)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		rights = append(rights, parseUnixRights(t, oob[:oobn])...)
		n += m
	}

	if !assert.Equal(t, uint32(protocolMagic), binary.LittleEndian.Uint32(buf[0:4])) {
		t.FailNow()
	}

	h := header{
		flags:   binary.LittleEndian.Uint16(buf[4:6]),
		msgType: binary.LittleEndian.Uint16(buf[6:8]),
		length:  binary.LittleEndian.Uint32(buf[16:20]),
	}

	payload := make([]byte, h.length)
	if _, err := io.ReadFull(c, payload); !assert.NoError(t, err) {
		t.FailNow()
	}

	return h, payload, rights
}

func parseUnixRights(t testing.TB, oob []byte) []int {
	t.Helper()
	if len(oob) == 0 {
		return nil
	}

	messages, err := unix.ParseSocketControlMessage(oob)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	var fds []int

	for _, message := range messages {
		rights, err := unix.ParseUnixRights(&message)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		fds = append(fds, rights...)
	}

	return fds
}

func decodeRanges(t testing.TB, payload []byte) []deviceRange {
	t.Helper()
	if !assert.GreaterOrEqual(t, len(payload), rangeCountSize) {
		t.FailNow()
	}

	count := int(binary.LittleEndian.Uint32(payload[0:4]))
	if !assert.Len(t, payload, rangeCountSize+count*rangeSize) {
		t.FailNow()
	}

	ranges := make([]deviceRange, 0, count)

	for off := rangeCountSize; off < len(payload); off += rangeSize {
		ranges = append(ranges, deviceRange{
			deviceOffset: binary.LittleEndian.Uint64(payload[off : off+8]),
			fileOffset:   binary.LittleEndian.Uint64(payload[off+8 : off+16]),
			length:       binary.LittleEndian.Uint64(payload[off+16 : off+24]),
		})
	}

	return ranges
}

func (c client) readRangeResponse(t testing.TB) ([]deviceRange, []int, int) {
	t.Helper()
	var ranges []deviceRange
	var fds []int

	for frames := 1; ; frames++ {
		h, payload, frameFds := c.readFrame(t)
		if !assert.Equal(t, uint16(msgRangeResponse), h.msgType) {
			t.FailNow()
		}

		frameRanges := decodeRanges(t, payload)
		if !assert.Len(t, frameFds, len(frameRanges)) {
			t.FailNow()
		}

		ranges = append(ranges, frameRanges...)
		fds = append(fds, frameFds...)

		if h.flags&flagNext == 0 {
			return ranges, fds, frames
		}
	}
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		_ = unix.Close(fd)
	}
}

func (c client) withReadDeadline(t testing.TB, d time.Duration, fn func()) {
	t.Helper()
	if !assert.NoError(t, c.SetReadDeadline(time.Now().Add(d))) {
		t.FailNow()
	}

	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	fn()
}

func (c client) stat(t testing.TB) (uint64, uint32) {
	t.Helper()
	c.send(t, msgStat, nil)
	var h header
	var payload []byte
	var fds []int
	c.withReadDeadline(t, faultTimeout, func() { h, payload, fds = c.readFrame(t) })
	assert.Equal(t, uint16(msgStatResponse), h.msgType)
	assert.Empty(t, fds)

	if !assert.Len(t, payload, statResponseSize) {
		t.FailNow()
	}

	return binary.LittleEndian.Uint64(payload[0:8]), binary.LittleEndian.Uint32(payload[8:12])
}

func fetch(t testing.TB, socket string, off, length uint64) ([]deviceRange, []int) {
	t.Helper()
	c := dial(t, socket)
	defer func() { _ = c.Close() }()
	c.send(t, msgFetch, encodeRange(off, length))
	var ranges []deviceRange
	var fds []int
	c.withReadDeadline(t, caseTimeout, func() { ranges, fds, _ = c.readRangeResponse(t) })

	return ranges, fds
}

func deviceBytes(t testing.TB, socket string, off, length uint64) []byte {
	t.Helper()
	ranges, fds := fetch(t, socket, off, length)
	defer closeFDs(fds)
	buf := make([]byte, length)

	for i, r := range ranges {
		if !assert.GreaterOrEqual(t, r.deviceOffset, off) {
			t.FailNow()
		}
		if !assert.LessOrEqual(t, r.deviceOffset+r.length, off+length) {
			t.FailNow()
		}
		if isZeroDevice(t, fds[i]) {
			continue
		}

		dst := buf[r.deviceOffset-off : r.deviceOffset-off+r.length]
		for done := 0; done < len(dst); {
			n, err := unix.Pread(fds[i], dst[done:], int64(r.fileOffset)+int64(done))
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			if n == 0 {
				break
			}

			done += n
		}
	}

	return buf
}

func isZeroDevice(t testing.TB, fd int) bool {
	t.Helper()
	var st unix.Stat_t
	if !assert.NoError(t, unix.Fstat(fd, &st)) {
		t.FailNow()
	}

	return st.Mode&unix.S_IFMT == unix.S_IFCHR
}

func (c client) expectClosed(t testing.TB) {
	t.Helper()
	if !assert.NoError(t, c.SetReadDeadline(time.Now().Add(faultTimeout))) {
		t.FailNow()
	}

	_, err := c.Read(make([]byte, 1))
	if !assert.Error(t, err) {
		t.FailNow()
	}

	assert.NotErrorIs(t, err, os.ErrDeadlineExceeded)
}
