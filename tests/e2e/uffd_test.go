package e2e

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/corpus"
	"github.com/stretchr/testify/require"
)

const (
	uffdMagic = 0x5546_4644

	uffdMsgStatRequest   = 0x02
	uffdMsgFetchRequest  = 0x03
	uffdMsgProbeRequest  = 0x04
	uffdMsgRangeResponse = 0x81
	uffdMsgStatResponse  = 0x82

	uffdRangeResponseFlagNext = 1 << 0

	uffdHeaderSize        = 20
	uffdRangeSize         = 24
	uffdStatResponseSize  = 16
	uffdRangeCountSize    = 4
	uffdFetchRequestSize  = 16
	uffdSmokeRequestBlock = 4096
)

func TestUffdServiceSmoke(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("UFFD service smoke test requires Linux")
	}

	nydusBin := mustLookupExecutable(t, "nydus")
	if out, err := exec.Command(nydusBin, "uffd", "--help").CombinedOutput(); err != nil {
		t.Skipf("nydus binary does not include the uffd subcommand; build with FEATURES=cli,uffd: %s", out)
	}

	tmpDir := t.TempDir()
	corpusDir := filepath.Join(tmpDir, "corpus")
	bootstrapPath := filepath.Join(tmpDir, "image.boot")
	blobDir := filepath.Join(tmpDir, "blobs")
	cacheDir := filepath.Join(tmpDir, "cache")
	socketPath := filepath.Join(tmpDir, "uffd.sock")
	logDir := filepath.Join(tmpDir, "logs")
	configPath := filepath.Join(tmpDir, "config.yaml")

	corpus.MakeStandardCorpus(t, corpusDir)
	buildNydusFSImageToDir(t, nydusBin, bootstrapPath, blobDir, corpusDir, uffdSmokeRequestBlock)
	writeLocalStorageConfig(t, configPath, blobDir, cacheDir)

	svc := startUffdService(t, nydusBin, bootstrapPath, configPath, socketPath, logDir)
	defer stopUffdService(t, svc)

	conn := dialUffdSocket(t, socketPath)
	defer func() {
		require.NoError(t, conn.Close())
	}()

	sendUffdRequest(t, conn, uffdMsgStatRequest, nil)
	statHeader, statPayload, statFds := readUffdFrame(t, conn)
	require.Equal(t, uint16(uffdMsgStatResponse), statHeader.msgType)
	require.Empty(t, statFds)
	require.Len(t, statPayload, uffdStatResponseSize)
	deviceSize := binary.LittleEndian.Uint64(statPayload[0:8])
	blockSize := binary.LittleEndian.Uint32(statPayload[8:12])
	require.Greater(t, deviceSize, uint64(0))
	require.Equal(t, uint32(uffdSmokeRequestBlock), blockSize)

	sendUffdRequest(t, conn, uffdMsgFetchRequest, encodeUffdDeviceRange(0, uint64(blockSize)))
	fetchRanges, fetchFds, _ := readUffdRangeResponses(t, conn)
	defer closeRawFds(fetchFds)
	require.NotEmpty(t, fetchRanges)
	require.Len(t, fetchFds, len(fetchRanges))
	require.Equal(t, uint64(0), fetchRanges[0].deviceOffset)
	require.Equal(t, uint64(0), fetchRanges[0].fileOffset)
	require.Equal(t, uint64(blockSize), fetchRanges[0].length)

	// The first returned FD backs the device head, which is the bootstrap
	// blob: it must carry the EROFS superblock magic at byte offset 1024.
	head := make([]byte, 4)
	_, err := syscall.Pread(fetchFds[0], head, int64(fetchRanges[0].fileOffset)+erofsSuperOffset)
	require.NoError(t, err)
	require.Equal(t, uint32(erofsSuperMagic), binary.LittleEndian.Uint32(head),
		"FETCH-returned FD must expose the EROFS superblock content")

	sendUffdRequest(t, conn, uffdMsgProbeRequest, nil)
	probeRanges, probeFds, _ := readUffdRangeResponses(t, conn)
	defer closeRawFds(probeFds)
	require.NotEmpty(t, probeRanges)
	require.Len(t, probeFds, len(probeRanges))
}

type uffdHeader struct {
	flags   uint16
	msgType uint16
	length  uint32
}

type uffdRange struct {
	deviceOffset uint64
	fileOffset   uint64
	length       uint64
}

// uffdServiceProc tracks one `nydus uffd` service child process together
// with its captured output for diagnostics.
type uffdServiceProc struct {
	cmd        *exec.Cmd
	output     *bytes.Buffer
	socketPath string
	logDir     string
}

func startUffdService(t *testing.T, nydusBin, bootstrapPath, configPath, socketPath, logDir string) *uffdServiceProc {
	t.Helper()
	require.NoError(t, os.MkdirAll(logDir, 0755))

	cmd := exec.Command(
		nydusBin,
		"uffd",
		"--bootstrap", bootstrapPath,
		"--config", configPath,
		"--socket", socketPath,
		"--log-dir", logDir,
		"--threads", "1",
	)
	output := &bytes.Buffer{}
	cmd.Stdout = output
	cmd.Stderr = output
	require.NoError(t, cmd.Start())

	require.Eventually(t, func() bool {
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			return false
		}
		conn, err := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 10*time.Second, 100*time.Millisecond, "nydus uffd did not start:\n%s", output.String())

	return &uffdServiceProc{cmd: cmd, output: output, socketPath: socketPath, logDir: logDir}
}

func stopUffdService(t *testing.T, svc *uffdServiceProc) {
	t.Helper()
	if svc == nil || svc.cmd.Process == nil || svc.cmd.ProcessState != nil {
		return
	}
	_ = svc.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- svc.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = svc.cmd.Process.Kill()
		<-done
	}
}

func dialUffdSocket(t *testing.T, socketPath string) *net.UnixConn {
	t.Helper()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	require.NoError(t, err)
	return conn
}

func sendUffdRequest(t *testing.T, conn *net.UnixConn, msgType uint16, payload []byte) {
	t.Helper()
	var frame bytes.Buffer
	var header [uffdHeaderSize]byte
	binary.LittleEndian.PutUint32(header[0:4], uffdMagic)
	binary.LittleEndian.PutUint16(header[6:8], msgType)
	binary.LittleEndian.PutUint32(header[16:20], uint32(len(payload)))
	frame.Write(header[:])
	frame.Write(payload)

	_, err := conn.Write(frame.Bytes())
	require.NoError(t, err)
}

func encodeUffdDeviceRange(offset, length uint64) []byte {
	payload := make([]byte, uffdFetchRequestSize)
	binary.LittleEndian.PutUint64(payload[0:8], offset)
	binary.LittleEndian.PutUint64(payload[8:16], length)
	return payload
}

// readUffdRangeResponses collects one logical RANGE_RESPONSE (possibly split
// over several NEXT-linked frames) and returns the ranges, the received FDs
// and the number of frames (batches) the response spanned.
func readUffdRangeResponses(t *testing.T, conn *net.UnixConn) ([]uffdRange, []int, int) {
	t.Helper()
	var ranges []uffdRange
	var fds []int
	batches := 0
	for {
		header, payload, frameFds := readUffdFrame(t, conn)
		require.Equal(t, uint16(uffdMsgRangeResponse), header.msgType)
		frameRanges := decodeUffdRanges(t, payload)
		require.Len(t, frameFds, len(frameRanges))
		ranges = append(ranges, frameRanges...)
		fds = append(fds, frameFds...)
		batches++
		if header.flags&uffdRangeResponseFlagNext == 0 {
			return ranges, fds, batches
		}
	}
}

func readUffdFrame(t *testing.T, conn *net.UnixConn) (uffdHeader, []byte, []int) {
	t.Helper()
	buf := make([]byte, 64*1024)
	oob := make([]byte, 4096)
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, uffdHeaderSize)

	header := decodeUffdHeader(t, buf[:uffdHeaderSize])
	payloadLen := int(header.length)
	payloadEnd := uffdHeaderSize + payloadLen
	availableEnd := n
	if availableEnd > payloadEnd {
		availableEnd = payloadEnd
	}
	payload := append([]byte(nil), buf[uffdHeaderSize:availableEnd]...)
	if len(payload) < int(header.length) {
		remaining := payloadLen - len(payload)
		extra := make([]byte, remaining)
		_, err := io.ReadFull(conn, extra)
		require.NoError(t, err)
		payload = append(payload, extra...)
	}

	return header, payload, parseUnixRights(t, oob[:oobn])
}

func decodeUffdHeader(t *testing.T, data []byte) uffdHeader {
	t.Helper()
	require.Len(t, data, uffdHeaderSize)
	require.Equal(t, uint32(uffdMagic), binary.LittleEndian.Uint32(data[0:4]))
	return uffdHeader{
		flags:   binary.LittleEndian.Uint16(data[4:6]),
		msgType: binary.LittleEndian.Uint16(data[6:8]),
		length:  binary.LittleEndian.Uint32(data[16:20]),
	}
}

func decodeUffdRanges(t *testing.T, payload []byte) []uffdRange {
	t.Helper()
	require.GreaterOrEqual(t, len(payload), uffdRangeCountSize)
	count := int(binary.LittleEndian.Uint32(payload[0:4]))
	require.Len(t, payload, uffdRangeCountSize+count*uffdRangeSize)

	ranges := make([]uffdRange, 0, count)
	offset := uffdRangeCountSize
	for i := 0; i < count; i++ {
		ranges = append(ranges, uffdRange{
			deviceOffset: binary.LittleEndian.Uint64(payload[offset : offset+8]),
			fileOffset:   binary.LittleEndian.Uint64(payload[offset+8 : offset+16]),
			length:       binary.LittleEndian.Uint64(payload[offset+16 : offset+24]),
		})
		offset += uffdRangeSize
	}
	return ranges
}

func parseUnixRights(t *testing.T, oob []byte) []int {
	t.Helper()
	if len(oob) == 0 {
		return nil
	}
	messages, err := syscall.ParseSocketControlMessage(oob)
	require.NoError(t, err)
	var fds []int
	for _, message := range messages {
		rights, err := syscall.ParseUnixRights(&message)
		require.NoError(t, err)
		fds = append(fds, rights...)
	}
	return fds
}

func closeRawFds(fds []int) {
	for _, fd := range fds {
		_ = syscall.Close(fd)
	}
}
