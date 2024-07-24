//go:build !windows

/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package archive

import (
	"archive/tar"
	"errors"

	"os"
	"runtime"

	"syscall"

	"github.com/containerd/continuity/sysx"
	"golang.org/x/sys/unix"
)

func chmodTarEntry(perm os.FileMode) os.FileMode {
	return perm
}

func setHeaderForSpecialDevice(hdr *tar.Header, _ string, fi os.FileInfo) error {
	// Devmajor and Devminor are only needed for special devices.

	// In FreeBSD, RDev for regular files is -1 (unless overridden by FS):
	// https://cgit.freebsd.org/src/tree/sys/kern/vfs_default.c?h=stable/13#n1531
	// (NODEV is -1: https://cgit.freebsd.org/src/tree/sys/sys/param.h?h=stable/13#n241).

	// ZFS in particular does not override the default:
	// https://cgit.freebsd.org/src/tree/sys/contrib/openzfs/module/os/freebsd/zfs/zfs_vnops_os.c?h=stable/13#n2027

	// Since `Stat_t.Rdev` is uint64, the cast turns -1 into (2^64 - 1).
	// Such large values cannot be encoded in a tar header.
	if runtime.GOOS == "freebsd" && hdr.Typeflag != tar.TypeBlock && hdr.Typeflag != tar.TypeChar {
		return nil
	}
	s, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("unsupported stat type")
	}

	rdev := uint64(s.Rdev) //nolint:nolintlint,unconvert // rdev is int32 on darwin/bsd, int64 on linux/solaris

	// Currently go does not fill in the major/minors
	if s.Mode&syscall.S_IFBLK != 0 ||
		s.Mode&syscall.S_IFCHR != 0 {
		hdr.Devmajor = int64(unix.Major(rdev))
		hdr.Devminor = int64(unix.Minor(rdev))
	}

	return nil
}

func open(p string) (*os.File, error) {
	return os.Open(p)
}

func getxattr(path, attr string) ([]byte, error) {
	b, err := sysx.LGetxattr(path, attr)
	if err == unix.ENOTSUP || err == sysx.ENODATA {
		return nil, nil
	}
	return b, err
}
