package tar

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/v2/pkg/archive"
	"github.com/containerd/continuity/fs"
	"golang.org/x/sys/unix"
)

// errNoReference marks an archive whose reference depends on the host
// filesystem's xattr capacity, so it cannot serve as an oracle.
var errNoReference = errors.New("reference depends on the host filesystem")

// typeGNUDumpDir is GNU's incremental directory entry, which Go reads but
// does not name.
const typeGNUDumpDir = 'D'

// extractReference applies data to dir with containerd's archive.Apply, the
// tree a converted layer must reproduce. It departs from Apply only where a
// single layer differs from a rootfs: GNU sparse and contiguous entries are
// the regular files Go reads them as, dumpdir entries are directories, OCI
// whiteouts stay plain files for a merge to interpret, and implicit parents
// get the zero mtime the builder gives them. It returns Apply's error for an
// archive containerd rejects.
func extractReference(data []byte, dir string) error {
	// Normalize the member types and record the directories the archive
	// names, so the parents Apply creates implicitly can be told apart.
	explicitDirs := map[string]bool{}
	normalize := func(hdr *tar.Header) (bool, error) {
		switch hdr.Typeflag {
		case tar.TypeGNUSparse, tar.TypeCont:
			hdr.Typeflag = tar.TypeReg
		case typeGNUDumpDir:
			hdr.Typeflag = tar.TypeDir
		}

		// Apply resolves symlinks in the parent only, never the member.
		if hdr.Typeflag == tar.TypeDir {
			parent, base := filepath.Split(hdr.Name)
			if resolved, err := fs.RootPath(dir, parent); err == nil {
				explicitDirs[filepath.Join(resolved, base)] = true
			}
		}

		return true, nil
	}
	keepWhiteouts := func(*tar.Header, string) (bool, error) { return true, nil }

	// Apply the archive. Only the xattr capacity of the host filesystem is
	// host dependent.
	_, err := archive.Apply(context.Background(), dir, bytes.NewReader(data),
		archive.WithFilter(normalize), archive.WithConvertWhiteout(keepWhiteouts))
	if err != nil {
		if errors.Is(err, unix.ENOSPC) && strings.Contains(err.Error(), "failed to setxattr") {
			return fmt.Errorf("%w: %v", errNoReference, err)
		}

		return err
	}

	// Give the implicit parents the zero mtime the builder gives them.
	zero := []unix.Timespec{{}, {}}
	return filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || !entry.IsDir() || path == dir || explicitDirs[path] {
			return err
		}

		return unix.UtimesNanoAt(unix.AT_FDCWD, path, zero, unix.AT_SYMLINK_NOFOLLOW)
	})
}
