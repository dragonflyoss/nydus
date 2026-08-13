/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydusfs

import (
	"archive/tar"
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/v2/core/content"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/dragonflyoss/nydus/nydusify/internal/oci"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

// blobMetaLinkConcurrency bounds how many blob meta files are hardlinked/copied
// into the cache directory in parallel.
const blobMetaLinkConcurrency = 10

// ExtractBootstrapLayer extracts a nydus bootstrap layer (gzip(tar(image/...)))
// from the content store into destDir. It writes the embedded bootstrap file to
// destDir/image.boot and every `*.blob.meta` artifact to destDir, returning the
// bootstrap path and the list of extracted blob meta paths.
func ExtractBootstrapLayer(ctx context.Context, cs content.Store, desc ocispec.Descriptor, destDir string) (string, []string, error) {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", nil, errors.Wrap(err, "create bootstrap dir")
	}

	decompressed, err := oci.OpenDecompressedBlob(ctx, cs, desc)
	if err != nil {
		return "", nil, errors.Wrap(err, "open bootstrap layer")
	}
	defer func() { _ = decompressed.Close() }()

	bootstrapPath := ""
	var blobMetaPaths []string
	tr := tar.NewReader(decompressed)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", nil, errors.Wrap(err, "read bootstrap tar")
		}
		switch {
		case hdr.Name == nydus.BootstrapFileNameInLayer:
			bootstrapPath = filepath.Join(destDir, "image.boot")
			if err := WriteTarEntry(tr, bootstrapPath); err != nil {
				return "", nil, errors.Wrap(err, "write bootstrap file")
			}
		case strings.HasSuffix(hdr.Name, ".blob.meta"):
			metaPath := filepath.Join(destDir, path.Base(hdr.Name))
			if err := WriteTarEntry(tr, metaPath); err != nil {
				return "", nil, errors.Wrapf(err, "write blob meta %s", hdr.Name)
			}
			blobMetaPaths = append(blobMetaPaths, metaPath)
		}
	}
	if bootstrapPath == "" {
		return "", nil, errors.Errorf("bootstrap entry %q not found in layer", nydus.BootstrapFileNameInLayer)
	}
	return bootstrapPath, blobMetaPaths, nil
}

// WriteTarEntry copies the current tar entry body into destPath.
func WriteTarEntry(tr *tar.Reader, destPath string) error {
	out, err := os.Create(destPath)
	if err != nil {
		return errors.Wrap(err, "create file")
	}
	if _, err := io.Copy(out, tr); err != nil {
		_ = out.Close()
		return errors.Wrap(err, "copy file")
	}
	return out.Close()
}

// LinkBlobMetaFiles populates cacheDir with the blob meta artifacts so the
// registry backend can load metadata from disk instead of fetching the blob
// footer. Each file is hardlinked when possible (same filesystem) and copied
// otherwise (e.g. across filesystems). Work is bounded by
// blobMetaLinkConcurrency.
func LinkBlobMetaFiles(ctx context.Context, blobMetaPaths []string, cacheDir string) error {
	if len(blobMetaPaths) == 0 {
		return nil
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return errors.Wrap(err, "create cache dir")
	}

	g, _ := errgroup.WithContext(ctx)
	g.SetLimit(blobMetaLinkConcurrency)
	for _, src := range blobMetaPaths {
		src := src
		g.Go(func() error {
			dst := filepath.Join(cacheDir, filepath.Base(src))
			return linkOrCopyFile(src, dst)
		})
	}
	return g.Wait()
}

// linkOrCopyFile hardlinks src to dst, falling back to a copy when the link
// fails (e.g. cross-device). An existing dst is treated as success because blob
// meta files are content-addressed by their full-blob digest.
func linkOrCopyFile(src, dst string) error {
	if _, err := os.Stat(dst); err == nil {
		return nil
	}
	if err := os.Link(src, dst); err == nil {
		return nil
	} else if errors.Is(err, fs.ErrExist) {
		return nil
	}
	return copyFile(src, dst)
}

// copyFile copies src to dst atomically via a temporary file in the same dir.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return errors.Wrap(err, "open source")
	}
	defer func() { _ = in.Close() }()

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".blob-meta-*")
	if err != nil {
		return errors.Wrap(err, "create temp file")
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := io.Copy(tmp, in); err != nil {
		return errors.Wrap(err, "copy data")
	}
	if err := tmp.Close(); err != nil {
		return errors.Wrap(err, "close temp file")
	}
	if err := os.Rename(tmpPath, dst); err != nil && !errors.Is(err, fs.ErrExist) {
		return errors.Wrap(err, "rename temp file")
	}
	committed = true
	return nil
}
