/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	continuityfs "github.com/containerd/continuity/fs"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/go-digest"
)

const (
	// bootstrapFile is the bootstrap in the bootstrap layer's image dir.
	bootstrapFile = "image.boot"

	// blobMetaSuffix names a blob's chunk table in the image dir and cache.
	blobMetaSuffix = ".blob.meta"

	// maxBlobs is the most blobs a bootstrap references: EROFS counts extra
	// devices in a u16, refer to nydus-format/src/erofs/superblock.rs.
	maxBlobs = 65535
)

// BootstrapLayer is an unpacked nydus bootstrap layer: image/image.boot and
// image/<blob>.blob.meta for every blob the image references. Its content is
// untrusted layer content: paths resolve within the layer and only regular
// files are used, as containerd resolves image paths, refer to
// https://github.com/containerd/containerd/blob/main/internal/cri/opts/container.go.
type BootstrapLayer struct {
	// fsDir is the snapshot's fs dir the layer is unpacked into.
	fsDir string
}

// NewBootstrapLayer returns the bootstrap layer unpacked into a snapshot's fs
// dir.
func NewBootstrapLayer(fsDir string) *BootstrapLayer {
	return &BootstrapLayer{fsDir: fsDir}
}

// Blobs returns the IDs of the blobs the bootstrap references, named by the
// blob metas the layer ships.
func (b *BootstrapLayer) Blobs() ([]string, error) {
	dir, err := b.imageDir()
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read image dir %s: %w", dir, err)
	}

	// Blob IDs name cache files, so only sha256 hex names count, as
	// containerd's content store validates a digest before building a path.
	var blobs []string
	for _, entry := range entries {
		blob, ok := strings.CutSuffix(entry.Name(), blobMetaSuffix)
		if !ok || !entry.Type().IsRegular() || digest.NewDigestFromEncoded(digest.SHA256, blob).Validate() != nil {
			continue
		}

		if len(blobs) == maxBlobs {
			return nil, fmt.Errorf("image dir %s holds over %d blob metas: %w", dir, maxBlobs, errdefs.ErrInvalidArgument)
		}

		blobs = append(blobs, blob)
	}

	return blobs, nil
}

// linkBootstrap links the bootstrap to dst, replacing an existing one, so a
// daemon keeps its bootstrap when the snapshot holding it is removed.
func (b *BootstrapLayer) linkBootstrap(dst string) error {
	if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", dst, err)
	}

	return b.link(bootstrapFile, dst)
}

// seedCache links the blob metas into the cache, as nydusify mount does, so a
// daemon need not fetch them. An existing meta is kept.
func (b *BootstrapLayer) seedCache(cacheDir string, blobs []string) error {
	for _, blob := range blobs {
		name := blob + blobMetaSuffix
		if err := b.link(name, filepath.Join(cacheDir, name)); err != nil {
			return err
		}
	}

	return nil
}

// imageDir returns the layer's image dir, resolved within the fs dir.
func (b *BootstrapLayer) imageDir() (string, error) {
	dir, err := continuityfs.RootPath(b.fsDir, "image")
	if err != nil {
		return "", fmt.Errorf("resolve image dir in %s: %w", b.fsDir, err)
	}

	return dir, nil
}

// link hard links a regular layer file to dst, keeping an existing dst, and
// copies across mounts (EXDEV), refer to nydusify/internal/nydusfs/extract.go.
func (b *BootstrapLayer) link(name, dst string) error {
	dir, err := b.imageDir()
	if err != nil {
		return err
	}

	// A link would hand the daemon whatever a symlink in the layer names.
	src := filepath.Join(dir, name)
	info, err := os.Lstat(src)
	if err != nil {
		return fmt.Errorf("stat %s: %w", src, err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file: %w", src, errdefs.ErrInvalidArgument)
	}

	err = os.Link(src, dst)
	if err == nil || errors.Is(err, os.ErrExist) {
		return nil
	}

	if !errors.Is(err, syscall.EXDEV) {
		return fmt.Errorf("link %s to %s: %w", src, dst, err)
	}

	return b.copyFile(src, dst)
}

// copyFile copies src to dst through a temporary file renamed into place,
// streaming a bootstrap that may be hundreds of MB.
func (b *BootstrapLayer) copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()

	tmp, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", dst, err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	if _, err := io.Copy(tmp, in); err != nil {
		return fmt.Errorf("copy %s to %s: %w", src, dst, err)
	}

	if err := tmp.Chmod(0o644); err != nil {
		return fmt.Errorf("chmod %s: %w", tmp.Name(), err)
	}

	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", tmp.Name(), err)
	}

	if err := os.Rename(tmp.Name(), dst); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmp.Name(), dst, err)
	}

	return nil
}
