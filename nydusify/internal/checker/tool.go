/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/pkg/archive"
	"github.com/containerd/containerd/v2/pkg/archive/compression"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/dragonflyoss/nydus/nydusify/internal/converter"
)

func builderBinary(path string) string {
	if path == "" {
		return "nydus"
	}
	return path
}

// nydusLogLevel returns level, or "info" when level is empty, so a nydus
// subprocess always receives a valid `--log-level` value.
func nydusLogLevel(level string) string {
	if level == "" {
		return "info"
	}
	return level
}

// blobMetaLinkConcurrency bounds how many blob meta files are hardlinked/copied
// into the cache directory in parallel.
const blobMetaLinkConcurrency = 10

// extractBootstrapLayer extracts a nydus bootstrap layer (gzip(tar(image/...)))
// from the content store into destDir. It writes the embedded bootstrap file to
// destDir/image.boot and every `*.blob.meta` artifact to destDir, returning the
// bootstrap path and the list of extracted blob meta paths.
func extractBootstrapLayer(ctx context.Context, cs content.Store, desc ocispec.Descriptor, destDir string) (string, []string, error) {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", nil, errors.Wrap(err, "create bootstrap dir")
	}

	ra, err := cs.ReaderAt(ctx, desc)
	if err != nil {
		return "", nil, errors.Wrap(err, "open bootstrap reader")
	}
	defer func() { _ = ra.Close() }()

	sr := io.NewSectionReader(ra, 0, ra.Size())
	decompressed, err := compression.DecompressStream(sr)
	if err != nil {
		return "", nil, errors.Wrap(err, "decompress bootstrap layer")
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
		case hdr.Name == converter.BootstrapFileNameInLayer:
			bootstrapPath = filepath.Join(destDir, "image.boot")
			if err := writeTarEntry(tr, bootstrapPath); err != nil {
				return "", nil, errors.Wrap(err, "write bootstrap file")
			}
		case strings.HasSuffix(hdr.Name, ".blob.meta"):
			metaPath := filepath.Join(destDir, path.Base(hdr.Name))
			if err := writeTarEntry(tr, metaPath); err != nil {
				return "", nil, errors.Wrapf(err, "write blob meta %s", hdr.Name)
			}
			blobMetaPaths = append(blobMetaPaths, metaPath)
		}
	}
	if bootstrapPath == "" {
		return "", nil, errors.Errorf("bootstrap entry %q not found in layer", converter.BootstrapFileNameInLayer)
	}
	return bootstrapPath, blobMetaPaths, nil
}

// writeTarEntry copies the current tar entry body into destPath.
func writeTarEntry(tr *tar.Reader, destPath string) error {
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

// linkBlobMetaFiles populates cacheDir with the blob meta artifacts so the
// registry backend can load metadata from disk instead of fetching the blob
// footer. Each file is hardlinked when possible (same filesystem) and copied
// otherwise (e.g. across filesystems). Work is bounded by
// blobMetaLinkConcurrency.
func linkBlobMetaFiles(ctx context.Context, blobMetaPaths []string, cacheDir string) error {
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
	} else if os.IsExist(err) {
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
	if err := os.Rename(tmpPath, dst); err != nil && !os.IsExist(err) {
		return errors.Wrap(err, "rename temp file")
	}
	committed = true
	return nil
}

// extractBootstrap reads a nydus bootstrap layer (gzip(tar(image/image.boot)))
// from the content store and writes the embedded bootstrap file to destPath.
func extractBootstrap(ctx context.Context, cs content.Store, desc ocispec.Descriptor, destPath string) error {
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
		if hdr.Name != converter.BootstrapFileNameInLayer {
			continue
		}
		out, err := os.Create(destPath)
		if err != nil {
			return errors.Wrap(err, "create bootstrap file")
		}
		if _, err := io.Copy(out, tr); err != nil {
			_ = out.Close()
			return errors.Wrap(err, "write bootstrap file")
		}
		if err := out.Close(); err != nil {
			return errors.Wrap(err, "close bootstrap file")
		}
		return nil
	}
	return errors.Errorf("bootstrap entry %q not found in layer", converter.BootstrapFileNameInLayer)
}

// applyOCIImage applies all OCI layers of img sequentially into rootfs,
// resolving whiteouts so the result is the fully merged root filesystem.
func applyOCIImage(ctx context.Context, cs content.Store, img *Image, rootfs string) error {
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		return errors.Wrap(err, "create rootfs dir")
	}
	for _, layer := range img.Manifest.Layers {
		if err := applyOCILayer(ctx, cs, layer, rootfs); err != nil {
			return errors.Wrapf(err, "apply layer %s", layer.Digest)
		}
	}
	return nil
}

func applyOCILayer(ctx context.Context, cs content.Store, layer ocispec.Descriptor, rootfs string) error {
	ra, err := cs.ReaderAt(ctx, layer)
	if err != nil {
		return errors.Wrap(err, "open layer reader")
	}
	defer func() { _ = ra.Close() }()

	sr := io.NewSectionReader(ra, 0, ra.Size())
	decompressed, err := compression.DecompressStream(sr)
	if err != nil {
		return errors.Wrap(err, "decompress layer")
	}
	defer func() { _ = decompressed.Close() }()

	// Preserve the original uid/gid recorded in the layer so the comparison
	// reflects the real image ownership (requires root, enforced by the
	// filesystem rule's privilege precheck).
	if _, err := archive.Apply(ctx, rootfs, decompressed); err != nil {
		return errors.Wrap(err, "apply layer archive")
	}
	return nil
}

// runNydusCheck invokes `nydus check` to statically validate a bootstrap.
// Data blobs are not verified, so no blob directory is required.
func runNydusCheck(ctx context.Context, builder, bootstrapPath string) error {
	args := []string{
		"check",
		"--bootstrap", bootstrapPath,
	}
	cmd := exec.CommandContext(ctx, builderBinary(builder), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return errors.Wrapf(err, "nydus check failed: %s", stderr.String())
	}
	return nil
}
