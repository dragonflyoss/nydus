/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// fsNode captures the metadata of a single filesystem entry used for comparing
// two mounted root filesystems.
type fsNode struct {
	mode    os.FileMode
	size    int64
	uid     uint32
	gid     uint32
	rdev    uint64 // device id for character/block device nodes
	symlink string
	hash    string            // sha256 of file contents, regular files only
	xattrs  map[string]string // extended attributes (excluding system.* noise)
}

// walkRootfs walks root and returns a map of relative path -> node metadata.
// filepath.Walk uses Lstat, so symlinks are reported as symlinks and never
// followed. Every entry (directories, regular files, symlinks, device nodes,
// fifos and sockets) is recorded.
func walkRootfs(root string) (map[string]fsNode, error) {
	nodes := make(map[string]fsNode)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return errors.Wrap(err, "compute relative path")
		}

		node := fsNode{
			mode: info.Mode(),
			size: info.Size(),
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			node.uid = st.Uid
			node.gid = st.Gid
			node.rdev = uint64(st.Rdev) //nolint:unconvert // Rdev is uint64 on some platforms and uint32 on others
		}

		xattrs, err := readXattrs(path)
		if err != nil {
			return errors.Wrapf(err, "read xattrs %s", rel)
		}
		node.xattrs = xattrs

		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return errors.Wrapf(err, "read symlink %s", rel)
			}
			node.symlink = target
			// Symlink size is target-dependent across filesystems; ignore it.
			node.size = 0
		case info.Mode().IsRegular():
			hash, err := hashFile(path)
			if err != nil {
				return errors.Wrapf(err, "hash %s", rel)
			}
			node.hash = hash
		}
		nodes[rel] = node
		return nil
	})
	if err != nil {
		return nil, err
	}
	return nodes, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// readXattrs lists and reads the extended attributes of path without following
// symlinks. The volatile system.* namespace (e.g. system.nfs4_acl, POSIX ACL
// shadows already reflected in the mode bits) is skipped to avoid spurious
// mismatches between an extracted OCI rootfs and a FUSE-mounted nydus image.
func readXattrs(path string) (map[string]string, error) {
	size, err := unix.Llistxattr(path, nil)
	if err != nil {
		if errIsXattrUnsupported(err) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "list xattr size")
	}
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	read, err := unix.Llistxattr(path, buf)
	if err != nil {
		if errIsXattrUnsupported(err) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "list xattr")
	}

	result := make(map[string]string)
	for _, name := range splitNullTerminated(buf[:read]) {
		if shouldSkipXattr(name) {
			continue
		}
		value, err := getXattr(path, name)
		if err != nil {
			return nil, errors.Wrapf(err, "get xattr %q", name)
		}
		result[name] = value
	}
	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}

func getXattr(path, name string) (string, error) {
	size, err := unix.Lgetxattr(path, name, nil)
	if err != nil {
		return "", err
	}
	buf := make([]byte, size)
	read, err := unix.Lgetxattr(path, name, buf)
	if err != nil {
		return "", err
	}
	return string(buf[:read]), nil
}

func shouldSkipXattr(name string) bool {
	// system.* attributes are filesystem-internal (ACL/selinux shadows) and are
	// not part of the image content; skip them for a stable comparison.
	return len(name) >= 7 && name[:7] == "system."
}

func errIsXattrUnsupported(err error) bool {
	return errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP)
}

func splitNullTerminated(buf []byte) []string {
	var names []string
	start := 0
	for i, b := range buf {
		if b == 0 {
			if i > start {
				names = append(names, string(buf[start:i]))
			}
			start = i + 1
		}
	}
	return names
}

// verifyRootfs compares two filesystem node maps and returns an error
// describing the first inconsistency found (missing/extra entries or metadata
// mismatches).
func verifyRootfs(source, target map[string]fsNode) error {
	paths := make([]string, 0, len(source))
	for p := range source {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, p := range paths {
		src := source[p]
		tgt, ok := target[p]
		if !ok {
			return errors.Errorf("path %q exists in source but not in target", p)
		}
		if err := compareNode(p, src, tgt); err != nil {
			return err
		}
	}

	for p := range target {
		if _, ok := source[p]; !ok {
			return errors.Errorf("path %q exists in target but not in source", p)
		}
	}
	return nil
}

func compareNode(path string, src, tgt fsNode) error {
	if src.mode.Type() != tgt.mode.Type() {
		return errors.Errorf("path %q: file type mismatch (source %s, target %s)", path, src.mode.Type(), tgt.mode.Type())
	}
	if specialBits(src.mode) != specialBits(tgt.mode) {
		return errors.Errorf("path %q: special bits mismatch (source %s, target %s)", path, src.mode, tgt.mode)
	}
	if src.mode.Perm() != tgt.mode.Perm() {
		return errors.Errorf("path %q: permission mismatch (source %o, target %o)", path, src.mode.Perm(), tgt.mode.Perm())
	}
	if src.uid != tgt.uid {
		return errors.Errorf("path %q: uid mismatch (source %d, target %d)", path, src.uid, tgt.uid)
	}
	if src.gid != tgt.gid {
		return errors.Errorf("path %q: gid mismatch (source %d, target %d)", path, src.gid, tgt.gid)
	}
	if src.symlink != tgt.symlink {
		return errors.Errorf("path %q: symlink target mismatch (source %q, target %q)", path, src.symlink, tgt.symlink)
	}
	// Device nodes: compare the device id (major/minor).
	if src.mode&(os.ModeDevice|os.ModeCharDevice) != 0 && src.rdev != tgt.rdev {
		return errors.Errorf("path %q: device id mismatch (source %d, target %d)", path, src.rdev, tgt.rdev)
	}
	if err := compareXattrs(path, src.xattrs, tgt.xattrs); err != nil {
		return err
	}
	if src.mode.IsRegular() {
		if src.size != tgt.size {
			return errors.Errorf("path %q: size mismatch (source %d, target %d)", path, src.size, tgt.size)
		}
		if src.hash != tgt.hash {
			return errors.Errorf("path %q: content mismatch (source %s, target %s)", path, src.hash, tgt.hash)
		}
	}
	return nil
}

func specialBits(mode os.FileMode) os.FileMode {
	return mode & (os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
}

func compareXattrs(path string, src, tgt map[string]string) error {
	names := make([]string, 0, len(src))
	for name := range src {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		sv := src[name]
		tv, ok := tgt[name]
		if !ok {
			return errors.Errorf("path %q: xattr %q present in source but missing in target", path, name)
		}
		if sv != tv {
			return errors.Errorf("path %q: xattr %q value mismatch", path, name)
		}
	}
	for name := range tgt {
		if _, ok := src[name]; !ok {
			return errors.Errorf("path %q: xattr %q present in target but missing in source", path, name)
		}
	}
	return nil
}
