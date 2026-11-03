package fstest

import (
	"bytes"
	"encoding/binary"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// Dirent is one raw getdents64 record.
type Dirent struct {
	Name string
	Ino  uint64
	Type uint8
	Off  int64
}

// SortedDirents lists dir through a buffer small enough to take several
// getdents64 calls, so readdir resumption is exercised, without "." and
// "..", sorted by name.
func SortedDirents(t testing.TB, dir string) []Dirent {
	t.Helper()
	entries := slices.DeleteFunc(ReadDirents(t, dir, 512), func(e Dirent) bool {
		return e.Name == "." || e.Name == ".."
	})

	slices.SortFunc(entries, func(a, b Dirent) int { return strings.Compare(a.Name, b.Name) })

	return entries
}

// ReadDirents opens dir and drains it with a bufSize getdents64 buffer.
func ReadDirents(t testing.TB, dir string, bufSize int) []Dirent {
	t.Helper()
	// O_CLOEXEC: a daemon another parallel test starts must not inherit the
	// descriptor and keep this mount busy.
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { _ = unix.Close(fd) }()

	return DrainDirents(t, fd, bufSize)
}

// DrainDirents decodes the raw getdents64 stream of fd. unix.ParseDirent
// would be simpler but discards d_type, d_ino and d_off, which is precisely
// what needs checking.
func DrainDirents(t testing.TB, fd int, bufSize int) []Dirent {
	t.Helper()
	buf := make([]byte, bufSize)
	var out []Dirent

	for {
		n, err := unix.Getdents(fd, buf)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if n == 0 {
			return out
		}

		for offset := 0; offset < n; {
			var raw unix.Dirent
			nameOffset := int(unsafe.Offsetof(raw.Name))
			if !assert.GreaterOrEqual(t, n-offset, nameOffset) {
				t.FailNow()
			}

			record := buf[offset:n]
			reclen := int(binary.NativeEndian.Uint16(record[unsafe.Offsetof(raw.Reclen):]))
			if !assert.Greater(t, reclen, nameOffset) {
				t.FailNow()
			}
			if !assert.LessOrEqual(t, reclen, len(record)) {
				t.FailNow()
			}

			nameBytes := record[nameOffset:reclen]
			if i := bytes.IndexByte(nameBytes, 0); i >= 0 {
				nameBytes = nameBytes[:i]
			}

			out = append(out, Dirent{
				Name: string(nameBytes),
				Ino:  binary.NativeEndian.Uint64(record[unsafe.Offsetof(raw.Ino):]),
				Type: record[unsafe.Offsetof(raw.Type)],
				Off:  int64(binary.NativeEndian.Uint64(record[unsafe.Offsetof(raw.Off):])),
			})

			offset += reclen
		}
	}
}
