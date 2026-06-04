/*
 * Copyright (c) 2026. Lepton Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package converter

import (
	"archive/tar"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

const paxSchilyXattr = "SCHILY.xattr."

// entryMode returns the permission bits of a tar entry including the
// setuid/setgid/sticky special bits, translated into os.FileMode flags so that
// os.Mkdir/os.OpenFile/os.Chmod preserve them. os.ModePerm alone only covers
// the low 0o777 bits and would silently drop the special bits.
func entryMode(hdr *tar.Header) os.FileMode {
	mode := os.FileMode(hdr.Mode).Perm()
	if hdr.Mode&unix.S_ISUID != 0 {
		mode |= os.ModeSetuid
	}
	if hdr.Mode&unix.S_ISGID != 0 {
		mode |= os.ModeSetgid
	}
	if hdr.Mode&unix.S_ISVTX != 0 {
		mode |= os.ModeSticky
	}
	return mode
}

// extractTar extracts a raw OCI layer tar stream into dir.
//
// Unlike a layered overlay apply, this performs a verbatim extraction: OCI
// whiteout entries (".wh.*") are written out as ordinary files so that a
// subsequent `lepton merge` can interpret the whiteouts itself.
//
// Faithfully reproducing the layer requires root: ownership (uid/gid), device
// nodes and privileged xattrs cannot otherwise be restored. Rather than
// silently producing an image with the wrong ownership, extractTar refuses to
// run unprivileged.
func extractTar(r io.Reader, dir string) error {
	if os.Geteuid() != 0 {
		return errors.New("converting an image requires root privileges to preserve file ownership and device nodes; re-run with sudo")
	}

	tr := tar.NewReader(r)
	// Track directories so their mtimes can be restored after their children
	// have been written.
	type dirTime struct {
		path  string
		atime time.Time
		mtime time.Time
	}
	var dirs []dirTime

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "read tar entry")
		}

		target, err := sanitizeEntryPath(dir, hdr.Name)
		if err != nil {
			return err
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, entryMode(hdr)); err != nil {
				return errors.Wrapf(err, "mkdir %s", target)
			}
			dirs = append(dirs, dirTime{path: target, atime: hdr.AccessTime, mtime: hdr.ModTime})
		case tar.TypeReg:
			if err := writeRegularFile(target, hdr, tr); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return errors.Wrapf(err, "mkdir parent of %s", target)
			}
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return errors.Wrapf(err, "symlink %s", target)
			}
		case tar.TypeLink:
			linkTarget, err := sanitizeEntryPath(dir, hdr.Linkname)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return errors.Wrapf(err, "mkdir parent of %s", target)
			}
			_ = os.Remove(target)
			if err := os.Link(linkTarget, target); err != nil {
				return errors.Wrapf(err, "hardlink %s", target)
			}
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			if err := makeDevice(target, hdr); err != nil {
				return errors.Wrapf(err, "create device/fifo %s", target)
			}
		default:
			// Skip unsupported entry types (e.g. GNU sparse, global headers).
			continue
		}

		if err := applyMetadata(target, hdr); err != nil {
			return err
		}
	}

	// Restore directory timestamps after all children are in place.
	for i := len(dirs) - 1; i >= 0; i-- {
		d := dirs[i]
		_ = chtimes(d.path, d.atime, d.mtime)
	}
	return nil
}

// sanitizeEntryPath joins name onto dir while preventing path traversal outside
// of dir.
func sanitizeEntryPath(dir, name string) (string, error) {
	clean := filepath.Clean("/" + name)
	target := filepath.Join(dir, clean)
	if target != dir && !strings.HasPrefix(target, dir+string(os.PathSeparator)) {
		return "", errors.Errorf("tar entry %q escapes extraction root", name)
	}
	return target, nil
}

func writeRegularFile(target string, hdr *tar.Header, tr io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return errors.Wrapf(err, "mkdir parent of %s", target)
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, entryMode(hdr))
	if err != nil {
		return errors.Wrapf(err, "create %s", target)
	}
	if _, err := io.Copy(f, tr); err != nil {
		_ = f.Close()
		return errors.Wrapf(err, "write %s", target)
	}
	if err := f.Close(); err != nil {
		return errors.Wrapf(err, "close %s", target)
	}
	return nil
}

func makeDevice(target string, hdr *tar.Header) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	_ = os.Remove(target)
	mode := uint32(hdr.Mode) & 0o7777
	switch hdr.Typeflag {
	case tar.TypeChar:
		mode |= unix.S_IFCHR
	case tar.TypeBlock:
		mode |= unix.S_IFBLK
	case tar.TypeFifo:
		mode |= unix.S_IFIFO
	}
	dev := int(unix.Mkdev(uint32(hdr.Devmajor), uint32(hdr.Devminor)))
	return unix.Mknod(target, mode, dev)
}

// applyMetadata restores ownership, permissions, xattrs and timestamps for an
// extracted entry. Ownership and permission failures are fatal because they
// would otherwise silently corrupt the converted image; timestamps remain
// best-effort.
func applyMetadata(target string, hdr *tar.Header) error {
	// xattrs carried via PAX records.
	for key, value := range hdr.PAXRecords {
		if !strings.HasPrefix(key, paxSchilyXattr) {
			continue
		}
		attr := strings.TrimPrefix(key, paxSchilyXattr)
		if err := unix.Lsetxattr(target, attr, []byte(value), 0); err != nil {
			return errors.Wrapf(err, "set xattr %q on %s", attr, target)
		}
	}

	// Ownership must be preserved for a faithful image. Apply it before chmod so
	// that chown cannot clear the setuid/setgid bits afterwards.
	if err := os.Lchown(target, hdr.Uid, hdr.Gid); err != nil {
		return errors.Wrapf(err, "chown %s to %d:%d", target, hdr.Uid, hdr.Gid)
	}

	// Permissions for non-symlink entries.
	if hdr.Typeflag != tar.TypeSymlink {
		if err := os.Chmod(target, entryMode(hdr)); err != nil {
			return errors.Wrapf(err, "chmod %s", target)
		}
	}

	if hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeSymlink {
		_ = chtimes(target, hdr.AccessTime, hdr.ModTime)
	}
	return nil
}

// chtimes sets the access and modification times of path without following
// symlinks.
func chtimes(path string, atime, mtime time.Time) error {
	if atime.IsZero() {
		atime = mtime
	}
	if mtime.IsZero() {
		return nil
	}
	ts := []unix.Timespec{
		unix.NsecToTimespec(atime.UnixNano()),
		unix.NsecToTimespec(mtime.UnixNano()),
	}
	return unix.UtimesNanoAt(unix.AT_FDCWD, path, ts, unix.AT_SYMLINK_NOFOLLOW)
}
