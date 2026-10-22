package oracle

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TarSafe reports whether s can be carried in a PAX record through
// `nydus build --source-type tar`: the tar crate splits PAX records at
// newlines, so it rejects a record containing one.
func TarSafe(s string) bool {
	return !strings.Contains(s, "\n")
}

// TarXattr reports whether WriteTar carries the xattr name=value.
// trusted.* is left out: the builder drops it from a layer tar as
// containerd's Apply does, while older releases keep it.
func TarXattr(name string, value Bytes) bool {
	return !strings.HasPrefix(name, "trusted.") && TarSafe(name) && TarSafe(string(value))
}

// WriteTar writes the tree under root as an OCI layer tarball: PAX
// headers carrying xattrs and nanosecond mtimes, and hardlinks as link entries
// to the first path of the inode. It leaves out sockets, which tar cannot
// carry, what TarSafe rejects and the xattrs TarXattr rejects.
func WriteTar(w io.Writer, root string) error {
	tw := tar.NewWriter(w)
	first := map[uint64]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == root {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if !TarSafe(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			return err
		}
		kind := st.Mode & unix.S_IFMT
		if kind == unix.S_IFSOCK {
			return nil
		}
		var target string
		if kind == unix.S_IFLNK {
			if target, err = os.Readlink(path); err != nil {
				return err
			}
			if !TarSafe(target) {
				return nil
			}
		}

		hdr := &tar.Header{
			Name:    rel,
			Mode:    int64(st.Mode & 07777),
			Uid:     int(st.Uid),
			Gid:     int(st.Gid),
			ModTime: time.Unix(st.Mtim.Sec, st.Mtim.Nsec),
			Format:  tar.FormatPAX,
		}
		xattrs, err := listXattrs(path)
		if err != nil {
			return err
		}
		for name, value := range xattrs {
			if !TarXattr(name, value) {
				continue
			}
			if hdr.PAXRecords == nil {
				hdr.PAXRecords = map[string]string{}
			}
			hdr.PAXRecords["SCHILY.xattr."+name] = string(value)
		}

		if kind != unix.S_IFDIR && st.Nlink > 1 {
			if target, ok := first[st.Ino]; ok {
				hdr.Typeflag = tar.TypeLink
				hdr.Linkname = target
				return tw.WriteHeader(hdr)
			}
			first[st.Ino] = rel
		}

		switch kind {
		case unix.S_IFDIR:
			hdr.Typeflag = tar.TypeDir
			hdr.Name += "/"
		case unix.S_IFREG:
			hdr.Typeflag = tar.TypeReg
			hdr.Size = st.Size
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			_, err = io.Copy(tw, f)
			return err
		case unix.S_IFLNK:
			hdr.Typeflag = tar.TypeSymlink
			hdr.Linkname = target
		case unix.S_IFCHR, unix.S_IFBLK:
			hdr.Typeflag = tar.TypeChar
			if kind == unix.S_IFBLK {
				hdr.Typeflag = tar.TypeBlock
			}
			hdr.Devmajor = int64(unix.Major(st.Rdev))
			hdr.Devminor = int64(unix.Minor(st.Rdev))
		case unix.S_IFIFO:
			hdr.Typeflag = tar.TypeFifo
		default:
			return fmt.Errorf("%s: unsupported file type %o", rel, kind)
		}
		return tw.WriteHeader(hdr)
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

// VerifyExport streams `nydus export` of blob and compares the OCI
// layer with want. A tar has no sockets, no link counts and hardlinks of
// regular files only.
func VerifyExport(t env.TB, reader, blob string, want []Entry) {
	t.Helper()
	cmd := exec.Command(reader, "export", blob)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	got, scanErr := ScanTar(stdout, want)
	_, _ = io.Copy(io.Discard, stdout)
	require.NoError(t, cmd.Wait(), "nydus export %s: %s", blob, stderr.String())
	require.NoError(t, scanErr, "reading the exported tar")
	CompareTree(t, WithoutSockets(want), got, CompareOptions{Tar: true})
}

// ScanTar records the entries of a layer tarball. Large files are
// checked against their extents in want as they stream past.
func ScanTar(r io.Reader, want []Entry) ([]Entry, error) {
	wantByPath := map[Bytes]Entry{}
	for _, entry := range want {
		wantByPath[entry.Path] = entry
	}

	var entries []Entry
	index := map[string]int{}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		rel := strings.TrimSuffix(strings.TrimPrefix(hdr.Name, "./"), "/")
		if rel == "" || rel == "." {
			continue
		}

		if hdr.Typeflag == tar.TypeLink {
			target := strings.TrimPrefix(hdr.Linkname, "./")
			i, ok := index[target]
			if !ok {
				return nil, fmt.Errorf("%q: hardlink to %q, which is not in the tar before it", rel, target)
			}
			entry := entries[i]
			entry.Path = Bytes(rel)
			index[rel] = len(entries)
			entries = append(entries, entry)
			continue
		}

		entry := Entry{
			Path:      Bytes(rel),
			Mode:      uint32(hdr.Mode & 07777),
			UID:       uint32(hdr.Uid),
			GID:       uint32(hdr.Gid),
			MtimeSec:  hdr.ModTime.Unix(),
			MtimeNsec: int64(hdr.ModTime.Nanosecond()),
			inode:     rel,
		}
		for key, value := range hdr.PAXRecords {
			if name, ok := strings.CutPrefix(key, "SCHILY.xattr."); ok && !strings.HasPrefix(name, "trusted.nydus.") {
				if entry.Xattrs == nil {
					entry.Xattrs = map[string]Bytes{}
				}
				entry.Xattrs[name] = Bytes(value)
			}
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			entry.Type = "dir"
			entry.inode = ""
		case tar.TypeReg:
			entry.Type = "reg"
			entry.Size = hdr.Size
			if hdr.Size <= FullReadLimit {
				h := sha256.New()
				if _, err := io.Copy(h, tr); err != nil {
					return nil, err
				}
				entry.SHA256 = hex.EncodeToString(h.Sum(nil))
			} else if err := verifySparseStream(tr, wantByPath[entry.Path]); err != nil {
				return nil, fmt.Errorf("%q: %w", rel, err)
			}
		case tar.TypeSymlink:
			entry.Type = "symlink"
			entry.Target = Bytes(hdr.Linkname)
			entry.Size = int64(len(hdr.Linkname))
		case tar.TypeChar, tar.TypeBlock:
			entry.Type = "chr"
			if hdr.Typeflag == tar.TypeBlock {
				entry.Type = "blk"
			}
			entry.Major = uint32(hdr.Devmajor)
			entry.Minor = uint32(hdr.Devminor)
		case tar.TypeFifo:
			entry.Type = "fifo"
		default:
			return nil, fmt.Errorf("%q: unexpected tar entry type %q", rel, hdr.Typeflag)
		}
		index[rel] = len(entries)
		entries = append(entries, entry)
	}
	assignLinks(entries)
	return entries, nil
}

// verifySparseStream checks a large file's content as it streams: the
// extents of want hash as recorded and everything else is zeros.
func verifySparseStream(r io.Reader, want Entry) error {
	if want.Size == 0 || len(want.Extents) == 0 {
		return errors.New("no extents recorded for a large file")
	}
	buf := make([]byte, 1<<20)
	zero := make([]byte, len(buf))
	extents := want.Extents
	h := sha256.New()
	for pos := int64(0); pos < want.Size; {
		n, err := io.ReadFull(r, buf[:min(int64(len(buf)), want.Size-pos)])
		if err != nil {
			return fmt.Errorf("at %d: %w", pos, err)
		}
		for data := buf[:n]; len(data) > 0; {
			if len(extents) > 0 && pos >= extents[0].Offset {
				end := extents[0].Offset + extents[0].Length
				m := min(int64(len(data)), end-pos)
				h.Write(data[:m])
				pos += m
				data = data[m:]
				if pos == end {
					if sum := hex.EncodeToString(h.Sum(nil)); sum != extents[0].SHA256 {
						return fmt.Errorf("data at %d differs", extents[0].Offset)
					}
					h.Reset()
					extents = extents[1:]
				}
				continue
			}
			next := want.Size
			if len(extents) > 0 {
				next = extents[0].Offset
			}
			m := min(int64(len(data)), next-pos)
			if !bytes.Equal(data[:m], zero[:m]) {
				return fmt.Errorf("hole at %d is not zeros", pos)
			}
			pos += m
			data = data[m:]
		}
	}
	return nil
}
