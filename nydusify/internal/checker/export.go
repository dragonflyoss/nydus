/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import (
	"archive/tar"
	"context"
	"io"
	"os"
	"path/filepath"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/pkg/archive/compression"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// exportImage writes the metadata of a single-image check into destDir for
// inspection:
//   - index.json   the raw image index (only when the root descriptor is an
//     index; a single-platform reference has no index);
//   - manifest.json the selected platform manifest;
//   - config.json   the image config;
//   - bootstrap/    the extracted bootstrap layer, preserving its directory
//     structure (nydus images only).
func exportImage(ctx context.Context, cs content.Store, img *Image, destDir string) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return errors.Wrapf(err, "create export dir %q", destDir)
	}

	if images.IsIndexType(img.Root.MediaType) {
		if err := writeBlobFile(ctx, cs, img.Root, filepath.Join(destDir, "index.json")); err != nil {
			return errors.Wrap(err, "write index.json")
		}
	}
	if err := writeBlobFile(ctx, cs, img.Desc, filepath.Join(destDir, "manifest.json")); err != nil {
		return errors.Wrap(err, "write manifest.json")
	}
	if err := writeBlobFile(ctx, cs, img.Manifest.Config, filepath.Join(destDir, "config.json")); err != nil {
		return errors.Wrap(err, "write config.json")
	}

	if img.Kind == KindNydus {
		if img.Bootstrap == nil {
			return errors.New("nydus image is missing its bootstrap layer")
		}
		if err := extractBootstrapTree(ctx, cs, *img.Bootstrap, filepath.Join(destDir, "bootstrap")); err != nil {
			return errors.Wrap(err, "extract bootstrap layer")
		}
	}
	return nil
}

// writeBlobFile reads desc from cs and writes its raw bytes to destPath.
func writeBlobFile(ctx context.Context, cs content.Store, desc ocispec.Descriptor, destPath string) error {
	b, err := content.ReadBlob(ctx, cs, desc)
	if err != nil {
		return errors.Wrapf(err, "read blob %s", desc.Digest)
	}
	if err := os.WriteFile(destPath, b, 0o644); err != nil {
		return errors.Wrapf(err, "write %q", destPath)
	}
	return nil
}

// extractBootstrapTree decompresses the bootstrap layer (gzip(tar(...))) from
// the content store and extracts every entry into destDir, preserving the
// layer's directory structure (e.g. image/image.boot and image/*.blob.meta).
func extractBootstrapTree(ctx context.Context, cs content.Store, desc ocispec.Descriptor, destDir string) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return errors.Wrap(err, "create bootstrap dir")
	}

	ra, err := cs.ReaderAt(ctx, desc)
	if err != nil {
		return errors.Wrap(err, "open bootstrap reader")
	}
	defer func() { _ = ra.Close() }()

	sr := io.NewSectionReader(ra, 0, ra.Size())
	decompressed, err := compression.DecompressStream(sr)
	if err != nil {
		return errors.Wrap(err, "decompress bootstrap layer")
	}
	defer func() { _ = decompressed.Close() }()

	tr := tar.NewReader(decompressed)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "read bootstrap tar")
		}

		target, err := safeJoin(destDir, hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return errors.Wrapf(err, "create dir %q", target)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return errors.Wrapf(err, "create parent dir for %q", target)
			}
			if err := writeTarEntry(tr, target); err != nil {
				return errors.Wrapf(err, "write %q", target)
			}
		default:
			// Bootstrap layers only carry regular files under a directory;
			// other entry types are not expected and are skipped.
		}
	}
	return nil
}

// safeJoin joins name onto base, rejecting paths that would escape base (e.g.
// via "../") to avoid path traversal when extracting a tar archive.
func safeJoin(base, name string) (string, error) {
	target := filepath.Join(base, name)
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return "", errors.Wrapf(err, "resolve %q", name)
	}
	if rel == ".." || filepath.IsAbs(rel) || len(rel) >= 3 && rel[:3] == ".."+string(os.PathSeparator) {
		return "", errors.Errorf("invalid tar entry path %q", name)
	}
	return target, nil
}
