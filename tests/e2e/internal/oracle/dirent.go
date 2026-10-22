package oracle

import (
	"bytes"
	"slices"
	"sort"
	"unsafe"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/stretchr/testify/require"
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
func SortedDirents(t env.TB, dir string) []Dirent {
	t.Helper()
	entries := slices.DeleteFunc(ReadDirents(t, dir, 512), func(e Dirent) bool {
		return e.Name == "." || e.Name == ".."
	})
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries
}

// ReadDirents opens dir and drains it with a bufSize getdents64 buffer.
func ReadDirents(t env.TB, dir string, bufSize int) []Dirent {
	t.Helper()
	// O_CLOEXEC: a daemon another parallel test starts must not inherit the
	// descriptor and keep this mount busy.
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	require.NoError(t, err, "open %s", dir)
	defer func() { _ = unix.Close(fd) }()
	return DrainDirents(t, fd, bufSize)
}

// DrainDirents decodes the raw getdents64 stream of fd. unix.ParseDirent
// would be simpler but discards d_type, d_ino and d_off, which is precisely
// what needs checking.
func DrainDirents(t env.TB, fd int, bufSize int) []Dirent {
	t.Helper()
	buf := make([]byte, bufSize)
	var out []Dirent
	for {
		n, err := unix.Getdents(fd, buf)
		require.NoError(t, err)
		if n == 0 {
			return out
		}
		for offset := 0; offset < n; {
			// SAFETY: the kernel wrote whole linux_dirent64 records into
			// buf[:n], and offset always lands on a record boundary.
			raw := (*unix.Dirent)(unsafe.Pointer(&buf[offset]))
			reclen := int(raw.Reclen)
			require.Greater(t, reclen, 0, "malformed dirent record length")

			nameBytes := unsafe.Slice((*byte)(unsafe.Pointer(&raw.Name[0])), reclen-int(unsafe.Offsetof(raw.Name)))
			if i := bytes.IndexByte(nameBytes, 0); i >= 0 {
				nameBytes = nameBytes[:i]
			}
			out = append(out, Dirent{Name: string(nameBytes), Ino: raw.Ino, Type: raw.Type, Off: raw.Off})
			offset += reclen
		}
	}
}
