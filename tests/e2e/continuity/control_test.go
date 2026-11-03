package continuity

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

const controlUpgradeProtocol = "nydus-fuse-control/1"

type control struct {
	*net.UnixConn
}

func (c control) setDeadline(t testing.TB) {
	t.Helper()
	assert.NoError(t, c.SetDeadline(time.Now().Add(controlProtocolTimeout)))
}

func (c control) readHTTPHeader() ([]byte, error) {
	header := make([]byte, 0, 512)
	var next [1]byte

	for len(header) < 16*1024 {
		if _, err := io.ReadFull(c, next[:]); err != nil {
			return nil, err
		}

		header = append(header, next[0])
		if bytes.HasSuffix(header, []byte("\r\n\r\n")) {
			return header, nil
		}
	}

	return nil, errors.New("control HTTP header exceeds 16 KiB")
}

func hasHTTPToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}

	return false
}

func dialControl(path string, timeout time.Duration) (control, error) {
	deadline := time.Now().Add(timeout)
	dialer := net.Dialer{Deadline: deadline}
	raw, err := dialer.Dial("unix", path)
	if err != nil {
		return control{}, err
	}

	conn := control{raw.(*net.UnixConn)}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return control{}, err
	}

	if err := conn.upgrade(); err != nil {
		_ = conn.Close()
		return control{}, err
	}

	return conn, nil
}

func (c control) upgrade() error {
	if _, err := io.WriteString(c, "GET /fuse/handoff HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: "+controlUpgradeProtocol+"\r\n\r\n"); err != nil {
		return err
	}

	header, err := c.readHTTPHeader()
	if err != nil {
		return err
	}

	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(header)), nil)
	if err != nil {
		return err
	}

	defer func() { _ = response.Body.Close() }()

	if response.Proto != "HTTP/1.1" || response.StatusCode != http.StatusSwitchingProtocols ||
		!hasHTTPToken(response.Header.Get("Connection"), "Upgrade") ||
		response.Header.Get("Upgrade") != controlUpgradeProtocol {
		return fmt.Errorf("invalid control HTTP upgrade response: %s", header)
	}

	return nil
}

func requestControlInfo(path string) (controlResponse, error) {
	conn, err := dialControl(path, time.Second)
	if err != nil {
		return controlResponse{}, err
	}

	defer func() { _ = conn.Close() }()

	if err := conn.write(map[string]any{"type": "info"}); err != nil {
		return controlResponse{}, err
	}

	responseFrame, err := conn.read()
	if err != nil {
		return controlResponse{}, err
	}
	if responseFrame.Type != "info" || responseFrame.Info == nil {
		return controlResponse{}, fmt.Errorf("unexpected control response %q", responseFrame.Type)
	}

	return responseFrame, nil
}

type controlInstanceInfo struct {
	PID         uint32 `json:"pid"`
	Version     string `json:"version"`
	Mountpoint  string `json:"mountpoint"`
	ImageDigest string `json:"image_digest"`
}

type controlResponse struct {
	Type      string               `json:"type"`
	Info      *controlInstanceInfo `json:"info,omitempty"`
	SessionID *string              `json:"session_id,omitempty"`
}

type controlSessionState struct {
	ProtoMajor uint32 `json:"proto_major"`
	ProtoMinor uint32 `json:"proto_minor"`
}

type controlTransferState struct {
	Version          uint32              `json:"version"`
	Mountpoint       string              `json:"mountpoint"`
	ImageDigest      string              `json:"image_digest"`
	FuseSessionState controlSessionState `json:"fuse_session_state"`
}

func (c control) writeRaw(payload []byte) error {
	if len(payload) == 0 || len(payload) > 4<<20 {
		return fmt.Errorf("invalid control frame length %d", len(payload))
	}

	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(payload)))
	frameBytes := append(hdr[:], payload...)
	_, err := c.Write(frameBytes)

	return err
}

func (c control) readRaw() ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, err
	}

	n := binary.LittleEndian.Uint32(hdr[:])
	if n == 0 || n > 4<<20 {
		return nil, fmt.Errorf("invalid control frame length %d", n)
	}

	payload := make([]byte, n)
	if _, err := io.ReadFull(c, payload); err != nil {
		return nil, err
	}

	return payload, nil
}

func (c control) write(v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}

	return c.writeRaw(payload)
}

func (c control) read() (controlResponse, error) {
	payload, err := c.readRaw()
	if err != nil {
		return controlResponse{}, err
	}

	var response controlResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		return controlResponse{}, fmt.Errorf("decode control frame: %w", err)
	}

	return response, nil
}

func (c control) recvFDs(expected int) (fds []int, err error) {
	if expected <= 0 {
		return nil, fmt.Errorf("invalid expected fd count %d", expected)
	}

	defer func() {
		if err != nil {
			for _, fd := range fds {
				err = errors.Join(err, unix.Close(fd))
			}

			fds = nil
		}
	}()

	if err = c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}

	raw, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}

	payload := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace((expected+1)*4))
	var n, oobn, flags int

	var recvErr error
	if err = raw.Read(func(fd uintptr) bool {
		for {
			n, oobn, flags, _, recvErr = unix.Recvmsg(
				int(fd),
				payload,
				oob,
				unix.MSG_CMSG_CLOEXEC,
			)

			if recvErr == unix.EINTR {
				continue
			}

			return recvErr != unix.EAGAIN
		}
	}); err != nil {
		return nil, err
	}

	if recvErr != nil {
		return nil, recvErr
	}

	messages, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, err
	}

	invalidControl := false

	for _, message := range messages {
		if message.Header.Level != unix.SOL_SOCKET || message.Header.Type != unix.SCM_RIGHTS {
			invalidControl = true
			continue
		}

		rights, parseErr := unix.ParseUnixRights(&message)
		if parseErr != nil {
			return fds, parseErr
		}

		fds = append(fds, rights...)
	}

	if n != 1 || payload[0] != 'F' || flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 {
		return fds, errors.New("invalid descriptor transfer payload")
	}
	if invalidControl || len(messages) != 1 {
		return fds, errors.New("descriptor transfer requires one SCM_RIGHTS message")
	}
	if len(fds) != expected {
		return fds, fmt.Errorf("received %d descriptors, expected %d", len(fds), expected)
	}

	for _, fd := range fds {
		fdFlags, fcntlErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if fcntlErr != nil {
			return fds, fcntlErr
		}
		if fdFlags&unix.FD_CLOEXEC == 0 {
			return fds, fmt.Errorf("received descriptor %d without FD_CLOEXEC", fd)
		}
	}

	return fds, nil
}

func (c control) mustWrite(t testing.TB, v any) {
	t.Helper()
	if !assert.NoError(t, c.write(v)) {
		t.FailNow()
	}
}

func (c control) mustRead(t testing.TB) controlResponse {
	t.Helper()
	response, err := c.read()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	return response
}
